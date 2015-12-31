# hearthstone-db

Captures Hearthstone TCP game packets and stores them in a SQLite database

## Install

Requires [golang](https://golang.org/)
```bash
git clone https://github.com/jshrake/hearthstone-db
cd hearthstone-db
make install
```

## Usage

Requires privledge escalation for packet capturing:

`[sudo] hearthstone-db [-db="./hearthstone.db" -snaplen=1600 -filter="tcp port 3724 or tcp port 1119"]`

- `db`: Path to the database file. Defaults to `./hearthstone.db`
- `snaplen`: [Snapshot Length](https://wiki.wireshark.org/SnapLen). Defaults to `1600`
- `filter`: [Berkley Packet Filter](http://biot.com/capstats/bpf.html). Defaults to a filter for capturing hearthstone packets

## Database table format

The packets are logged to a table named `hearthstone` with the following schema:
```
	create table if not exists hearthstone(
		id integer not null primary key,
		time datetime default current_timestamp,
		type integer not null,
		size integer not null,
		payload blob);
```

## Resources

- [http://www.theforce.dk/hearthstone/](http://www.theforce.dk/hearthstone/)
