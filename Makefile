GO      ?= go
BIN     := .harness/bin
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
# The three region platforms: tuchanka-1 (laptop, darwin/arm64), palaven-1 (Oracle ARM), thessia-1 (Codespace).
TARGETS := darwin/arm64 linux/arm64 linux/amd64

.PHONY: check vet test cross build serve conformance ratchet loop report clean

## check: everything an agent must pass before committing (vet, tests, all three platforms build)
check: vet test cross

vet:
	@unformatted=$$(gofmt -l cmd internal 2>/dev/null); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	@$(GO) vet ./...

test:
	@$(GO) test -count=1 ./...

cross:
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -ldflags "$(LDFLAGS)" -o /dev/null ./cmd/citadel \
			|| { echo "cross-build failed for $$t (is something using cgo?)"; exit 1; }; \
	done
	@echo "cross-build ok: $(TARGETS)"

build:
	@mkdir -p $(BIN)
	@CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/citadel ./cmd/citadel

## serve: run a dev region on :8420 (point the aws CLI at it with AWS_CONFIG_FILE=harness/aws.config)
serve: build
	$(BIN)/citadel serve --region tuchanka-1 --listen 127.0.0.1:8420 --data .harness/data/dev \
		--bootstrap harness/bootstrap.json --log text

## conformance: run one conformance suite, e.g. make conformance SUITE=s3 ARGS="-k test_bucket_list_empty"
conformance:
	@harness/conformance.sh $(SUITE) $(ARGS)

ratchet:
	@harness/ratchet.sh

loop:
	@harness/loop.sh $(ARGS)

report:
	@harness/report.sh

clean:
	rm -rf .harness/bin .harness/results .harness/data
