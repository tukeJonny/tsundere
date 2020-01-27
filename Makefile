
LINUX_ENV=GOOS=linux GOARCH=amd64

MAKE_BPF=make -C./bpf
BUILD=go build
BUILD_ENV=CGO_ENABLED=1
PROTOC=protoc
PROTOC_OPTS=-I. --go_out=plugins=grpc:.

default: build

build: protoc
	$(MAKE_BPF)
	$(LINUX_ENV) $(BUILD_ENV) $(BUILD) -o ./bin/tsundered ./cmd/tsundered
	$(LINUX_ENV) $(BUILD) -o ./bin/tsunderectl ./cmd/tsunderectl
.PHONY: build

protoc:
	cd pb && \
	$(PROTOC) $(PROTOC_OPTS) fw.proto
.PHONY: protoc

test:
	$(MAKE_BPF)
	$(MAKE_BPF) test
.PHONY: test

