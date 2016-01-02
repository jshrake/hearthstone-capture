package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
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

type PegasusPacketStreamFactory struct {
}

func (streamFactory *PegasusPacketStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go func(reader io.Reader) {
		// NOTE(jshrake): rate limit the amount of packets streamed to stdout so we don't spin several
		// cores on the users machine. 60 packets per second is sufficient
		ticker := time.Tick(16 * time.Millisecond)
		packedBuffer := new(bytes.Buffer)
		for {
			select {
			case <-ticker:
				// First 4 bytes are the payload type
				var packetType uint32
				if err := binary.Read(reader, binary.LittleEndian, &packetType); err != nil {
					tcpreader.DiscardBytesToEOF(reader)
					continue
				}
				// Discard packets with unknown types
				if packetType > 500 {
					tcpreader.DiscardBytesToEOF(reader)
					continue
				}
				// Next 4 bytes are the payload size
				var packetSize uint32
				if err := binary.Read(reader, binary.LittleEndian, &packetSize); err != nil {
					tcpreader.DiscardBytesToEOF(reader)
					continue
				}
				// Discard ridiculously sized packets
				if packetSize > 9000 {
					tcpreader.DiscardBytesToEOF(reader)
					continue
				}
				// Read the payload
				payload := make([]byte, packetSize)
				if err := binary.Read(reader, binary.LittleEndian, &payload); err != nil {
					tcpreader.DiscardBytesToEOF(reader)
					continue
				}
				// Pack the data back into the packedBuffer and write to stdout
				binary.Write(packedBuffer, binary.LittleEndian, packetType)
				binary.Write(packedBuffer, binary.LittleEndian, packetSize)
				binary.Write(packedBuffer, binary.LittleEndian, payload)
				fmt.Println(packedBuffer)
				packedBuffer.Reset()
			}
		}
	}(&r)
	return &r
}

var snaplen = flag.Int("snaplen", 1600, "Snaplen for pcap")
var filter = flag.String("filter", "tcp port 3724 or tcp port 1119", "BPF filter for pcap")

func main() {
	flag.Parse()

	// Listen on all devices so the user doesn't have to figure out which device to select
	devices, _ := pcap.FindAllDevs()
	capturedPackets := capturePackets(devices, *snaplen, *filter)

	// Feed captured packets into the tcp stream assembler
	streamFactory := &PegasusPacketStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	streamFlushTicker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-capturedPackets:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			}
		case <-streamFlushTicker:
			assembler.FlushOlderThan(time.Now().Add(-time.Minute))
		}
	}
}
