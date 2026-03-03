.PHONY: build clean run test

build:
	go build -o bin/sip-ban ./cmd/sip-ban

clean:
	rm -rf bin/

run: build
	sudo ./bin/sip-ban

test:
	go test ./...

install: build
	sudo cp bin/sip-ban /usr/local/bin/

.DEFAULT_GOAL := build
