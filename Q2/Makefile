# Build:   make
# Run:     sudo ./bin/geotrace www.harvard.edu
#    or:   make run HOST=www.harvard.edu
# Raw sockets need root, or: sudo setcap cap_net_raw+ep ./bin/geotrace

BIN  := bin/geotrace
HOST ?= www.harvard.edu

.PHONY: build test run clean

build:
	go build -o $(BIN) ./cmd/geotrace

test:
	go test ./...

run: build
	sudo ./$(BIN) $(HOST)

clean:
	rm -rf bin
