# docker-security — build & test. No git is used in this project by design.
BIN := bin
GOFLAGS ?=

.PHONY: all build build-runtime test test-race vet fmt fmt-check cover run demo serve install clean tidy

all: fmt-check vet test build ## fmt-check, vet, test, then build

build: ## build the dsecrat CLI + dsecrat-runtime daemon into ./bin
	@mkdir -p $(BIN)
	go build $(GOFLAGS) -o $(BIN)/dsecrat ./cmd/dsecrat
	go build $(GOFLAGS) -o $(BIN)/dsecrat-runtime ./cmd/dsecrat-runtime
	@echo "built $(BIN)/dsecrat and $(BIN)/dsecrat-runtime"

test: ## run all tests
	go test ./...

test-race: ## run all tests with the race detector
	go test -race ./...

cover: ## run tests with a coverage summary
	go test -cover ./...

vet: ## go vet the whole tree
	go vet ./...

fmt: ## gofmt-write the tree
	gofmt -w internal cmd web

fmt-check: ## fail if anything is not gofmt-clean
	@out=$$(gofmt -l internal cmd web); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

run: build ## scan the sample bad Dockerfile
	$(BIN)/dsecrat scan examples/Dockerfile.bad

serve: build ## start the API + web dashboard with a persistent inventory store
	$(BIN)/dsecrat serve --addr 127.0.0.1:8080 --store ./.dsecrat-store

demo: build ## end-to-end demo: exercise every capability against a fixture image
	./scripts/demo.sh

install: ## install dsecrat + dsecrat-runtime into $GOBIN / $GOPATH/bin
	go install ./cmd/dsecrat ./cmd/dsecrat-runtime

# Cross-platform release matrix. Pure Go + CGO_ENABLED=0 → static binaries that
# run on Windows, macOS (Intel + Apple Silicon), and Linux (x86-64 + arm64) with
# no runtime dependency. eBPF live-capture is Linux-only and behind build tags;
# every other capability is identical across platforms.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
release: ## build dsecrat + dsecrat-runtime for every supported OS/arch into ./dist
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = "windows" ] && ext=.exe; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -o dist/dsecrat_$${os}_$${arch}$$ext ./cmd/dsecrat; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -o dist/dsecrat-runtime_$${os}_$${arch}$$ext ./cmd/dsecrat-runtime; \
	done
	@echo "release binaries in ./dist:"; ls -1 dist

tidy: ## verify the module stays dependency-free
	go mod tidy
	@test ! -f go.sum && echo "go.sum absent (zero-dependency, as intended)" || echo "note: go.sum present — a dependency was added"

clean: ## remove build output
	rm -rf $(BIN) dist .dsecrat-store

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'
