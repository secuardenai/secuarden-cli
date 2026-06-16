VERSION ?= dev
LDFLAGS = -ldflags "-X github.com/secuarden/secuarden-cli/cmd.Version=$(VERSION)"

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/secuarden ./cmd/secuarden

test:
	go test ./internal/... -v

lint:
	golangci-lint run

install: build
	cp bin/secuarden /usr/local/bin/secuarden

clean:
	rm -rf bin/

.PHONY: build test lint install clean
