package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// courtesy of https://blog.golang.org/pipelines
func merge(cs ...<-chan gopacket.Packet) <-chan gopacket.Packet {
	var wg sync.WaitGroup
	out := make(chan gopacket.Packet)

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan gopacket.Packet) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func capturePacketsToChan(device string, snapLen int, filter string) <-chan gopacket.Packet {
	output := make(chan gopacket.Packet)
	if handle, err := pcap.OpenLive(device, int32(snapLen), true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	} else {
		go func() {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				output <- packet
			}
		}()
	}
	return output
}

func capturePackets(devices []pcap.Interface, snapLen int, filter string) <-chan gopacket.Packet {
	listeners := make([]<-chan gopacket.Packet, len(devices))
	for idx, device := range devices {
		listeners[idx] = capturePacketsToChan(device.Name, snapLen, filter)
	}
	return merge(listeners...)
}

type PegasusPacket struct {
	Type    uint32
	Size    uint32
	Payload []byte
}

type PegasusPacketStreamFactory struct {
	Out chan PegasusPacket
}

func (streamFactory *PegasusPacketStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go handlePegasusPackets(&r, streamFactory.Out)
	return &r
}

func handlePegasusPackets(r io.Reader, out chan<- PegasusPacket) {
	ticker := time.Tick(time.Millisecond)
	for {
		select {
		case <-ticker:
			// First 4 bytes are the payload type
			var payloadType uint32
			if err := binary.Read(r, binary.LittleEndian, &payloadType); err != nil {
				tcpreader.DiscardBytesToEOF(r)
				continue
			}
			// Ignore ping (115), pong (116), and messages outside of the PegasusPacket type range
			if payloadType > 500 || payloadType == 115 || payloadType == 116 {
				tcpreader.DiscardBytesToEOF(r)
				continue
			}
			// Next 4 bytes are the payload size
			var payloadSize uint32
			if err := binary.Read(r, binary.LittleEndian, &payloadSize); err != nil {
				tcpreader.DiscardBytesToEOF(r)
				continue
			}
			// Read the payload
			payload := make([]byte, payloadSize)
			if err := binary.Read(r, binary.LittleEndian, &payload); err != nil {
				tcpreader.DiscardBytesToEOF(r)
				continue
			}
			out <- PegasusPacket{
				Type:    payloadType,
				Size:    payloadSize,
				Payload: payload,
			}
		}
	}
}

const PegasusPacketFilter string = "(tcp port 3724 or tcp port 1119) and not host (12.130.244.193 or 12.129.242.24 or 12.129.206.133)"

var snaplen = flag.Int("snaplen", 1600, "Snaplen for pcap packet capture")
var filter = flag.String("filter", PegasusPacketFilter, "BPF filter for pcap")
var dbPath = flag.String("db", "./hearthstone.db", "Path to the database")

func main() {
	flag.Parse()
	// Open the database
	db, openDbErr := sql.Open("sqlite3", *dbPath)
	if openDbErr != nil {
		log.Fatal(openDbErr)
	}
	defer db.Close()
	// Create the single hearthstone table
	createTableStatement := `
	create table if not exists hearthstone(
		id integer not null primary key,
		time datetime default current_timestamp,
		type integer not null,
		size integer not null,
		payload blob);
	`
	_, createTableErr := db.Exec(createTableStatement)
	if createTableErr != nil {
		log.Printf("%q: %s\n", createTableErr, createTableStatement)
		return
	}

	// Create an index on the type column
	createTypeIndexStatement := `
	create index if not exists typeindex on hearthstone (type)
	`
	_, createIndexErr := db.Exec(createTypeIndexStatement)
	if createIndexErr != nil {
		log.Printf("%q: %s\n", createIndexErr, createTypeIndexStatement)
		return
	}

	// Log any pegasus packets into the database
	pegasusPackets := make(chan PegasusPacket)
	go func() {
		for packet := range pegasusPackets {
			tx, err := db.Begin()
			if err != nil {
				log.Fatal(err)
			}
			insertStatement, err := tx.Prepare("insert into hearthstone(type, size, payload) values(?, ?, ?)")
			if err != nil {
				log.Fatal(err)
			}
			defer insertStatement.Close()
			_, err = insertStatement.Exec(packet.Type, packet.Size, packet.Payload)
			if err != nil {
				log.Fatal(err)
			}
			tx.Commit()
		}
	}()

	// Capture packets
	streamFactory := &PegasusPacketStreamFactory{Out: pegasusPackets}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	devices, _ := pcap.FindAllDevs()
	capturedPackets := capturePackets(devices, *snaplen, *filter)
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-capturedPackets:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(-time.Minute))
		}
	}
}
