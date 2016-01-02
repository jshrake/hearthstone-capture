all: build

get:
	go get

build: get
	go build

run: build
	# Needs sudo for packet capture
	sudo ./hearthstone-capture

install:
	go install

dist:
	GOOS=darwin GOARCH=386 CGO_ENABLED=1 go build -o dist/hearthstone-capture-i386-macosx
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o dist/hearthstone-capture-x86_64-macosx
	GOOS=windows GOARCH=386 CGO_ENABLED=1 go build -o dist/hearthstone-capture-i386-win32.exe
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -o dist/hearthstone-capture-x86_64-win32.exe

.PHONY: build dist