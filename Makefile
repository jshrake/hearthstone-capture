all: build

get:
	go get

build: get
	go build

run: build
	# Needs sudo for packet capture
	sudo ./hearthstone-db

install:
	go install

.PHONY: build dist