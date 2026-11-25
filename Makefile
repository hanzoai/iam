# The test gate. One command, run identically by a human and by CI.
#
# Not a bare `go test ./...`: that reuses cached PASS results, so a stale build
# can report green for code you just changed, and it runs without the race
# detector, which is where this repo's store and session defects actually show
# up. -count=1 defeats the cache; -race is the point.

.DEFAULT_GOAL := generate

.PHONY: test build fmt vet generate debug debug-tools debug-attach debug-dap debug-test

GO ?= go
DLV ?= $(CURDIR)/.dev/bin/dlv
DLV_VERSION ?= latest
DEBUG_HTTP_PORT ?= 8000
DEBUG_ZAP_PORT ?= 19653
DEBUG_DAP_PORT ?= 38697

# Standalone debug uses only local fixtures; never use deployed keys or stores.
debug-tools: ## Install or verify the local Delve executable.
	@mkdir -p .dev/bin
	@if ! command -v "$(DLV)" >/dev/null 2>&1; then \
	  test "$(DLV)" = "$(CURDIR)/.dev/bin/dlv" || { echo "Configured DLV executable not found: $(DLV)" >&2; exit 1; }; \
	  GOBIN="$(CURDIR)/.dev/bin" $(GO) install github.com/go-delve/delve/cmd/dlv@$(DLV_VERSION); \
	fi
	@"$(DLV)" version

debug: debug-tools ## Launch standalone IAM under Delve with an isolated local database.
	@umask 077; mkdir -p .dev/keys; \
	  if [ ! -s .dev/keys/cert-dev ]; then openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .dev/keys/cert-dev || exit 1; fi; \
	  if [ ! -f .dev/init_data.json ]; then printf '%s\n' '{"organizations":[{"owner":"admin","name":"hanzo"}],"certs":[{"owner":"admin","name":"cert-dev","cryptoAlgorithm":"RS256"}],"applications":[{"owner":"admin","name":"hanzo-dev","clientId":"hanzo-dev","organization":"hanzo","enablePassword":true}]}' > .dev/init_data.json; fi
	@IAM_ISSUER= IAM_ISSUER_MAP= IAM_DEV_HOST_RELATIVE=1 IAM_SIGNING_KEYS="$(CURDIR)/.dev/keys" "$(DLV)" debug . -- serve --store sqlite --db "$(CURDIR)/.dev/iam-debug.db" --http http://127.0.0.1:$(DEBUG_HTTP_PORT) --zap 127.0.0.1:$(DEBUG_ZAP_PORT) --ops '' --init-data "$(CURDIR)/.dev/init_data.json"

debug-attach: debug-tools ## Attach to a local IAM process (PID required).
	@case "$(PID)" in ''|*[!0-9]*|0) echo 'Set PID to the local debug process ID' >&2; exit 1;; esac
	@"$(DLV)" attach "$(PID)"

debug-dap: debug-tools ## Serve local IDE DAP on loopback only.
	@"$(DLV)" dap --listen=127.0.0.1:$(DEBUG_DAP_PORT)

debug-test: debug-tools ## Debug tests in PKG (default current package).
	@"$(DLV)" test "$(if $(PKG),$(PKG),.)"


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
	go test ./... -race -count=1 -timeout 20m

build: ## Build every package.
	go build ./...

fmt: ## Format.
	go fmt ./...

vet: ## Vet.
	go vet ./...
