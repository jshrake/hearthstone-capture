# hearthstone-capture

Stream Hearthstone PegasusPackets to stdout

## Install

Requires [golang](https://golang.org/)
```bash
git clone https://github.com/jshrake/hearthstone-db
cd hearthstone-db
make install
```

## Usage

Requires privledge escalation for packet capturing:

`[sudo] hearthstone-capture [-snaplen=1600 -filter="tcp port 3724 or tcp port 1119"]`

- `snaplen`: [Snapshot Length](https://wiki.wireshark.org/SnapLen). Defaults to `1600`
- `filter`: [Berkley Packet Filter](http://biot.com/capstats/bpf.html). Defaults to `tcp port 3724 or tcp port 1119`

## PegasusPacket format

```c
struct PegasusPacket {
	uint32_t type;
	uint32_t size;
	uint8_t *message;
};
```

- The first 4 bytes are the message type
- The next 4 bytes are the message size
- The remaining size bytes are the [protocol buffer encoded message](https://developers.google.com/protocol-buffers/)

The decompiled protocol buffer message definitions can be found at [HearthSim/hs-proto](https://github.com/HearthSim/hs-proto). Of particular interest are the messages defined in [PegasusGame](https://github.com/HearthSim/hs-proto/blob/e7a26141e2e8d27404e6da9c224934bd3c407b43/pegasus/game.proto).

The PegausPacket type corresponds to the message `PacketID`. For instance, a PegasusPacket type of 19 corresponds to a [PowerHistory message](https://github.com/HearthSim/hs-proto/blob/e7a26141e2e8d27404e6da9c224934bd3c407b43/pegasus/game.proto#L264-L266).

Here's a handcrafted map from type to message name to get you started:

```json
{
	"1": "GetGameState",
	"2": "ChooseOption",
	"3": "ChooseEntities",
	"11": "Concede",
	"13": "EntitiesChosen",
	"14": "AllOptions",
	"15": "UserUI",
	"16": "GameSetup",
	"17": "EntityChoices",
	"19": "PowerHistory",
	"24": "SpectatorNotify",
	"115": "Ping",
	"116": "Pong",
	"168": "Handshake"
}
