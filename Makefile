# The test gate. One command, run identically by a human and by CI.
#
# Not a bare `go test ./...`: that reuses cached PASS results, so a stale build
# can report green for code you just changed, and it runs without the race
# detector, which is where this repo's store and session defects actually show
# up. -count=1 defeats the cache; -race is the point.

.PHONY: test build fmt vet generate

# Prose reaches the document ONLY through this step. Go drops comments at compile
# time, so an operation's description cannot be read off the running binary: the
# doc comment on each typed handler is lifted here into the package's
# zipdoc_gen.go, which registers it with zip.Describe at init. That file is
# COMMITTED, because a consumer building this module does not run go generate.
#
# Skipping it does not fail loudly — it publishes an operationId and silence, in
# the OpenAPI document, the MCP tool list and every generated client and CLI. So
# `test` runs zipdoc -check first: a doc comment edited without regenerating is a
# red build, not a quietly stale artifact.
generate: ## Lift every typed handler's doc comment into its zipdoc_gen.go.
	go generate -run zipdoc ./...

test: ## Run the full suite — the gate. Everything must be green to ship.
	# zipdoc takes package patterns, so ask it once. The loop that stood here ran it
	# per directory — the generator relinked twenty-four times — and stopped at the
	# first stale file, so N stale files cost N red runs to discover one at a time.
	# One invocation is faster and names all of them.
	@go run github.com/zap-proto/zip/cmd/zipdoc -check ./... || { echo "run: make generate"; exit 1; }
	go test ./... -race -count=1

build: ## Build every package.
	go build ./...

fmt: ## Format.
	go fmt ./...

vet: ## Vet.
	go vet ./...
