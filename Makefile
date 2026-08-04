# The test entry point. One command, run identically by a human and by CI.
#
# Not a bare `go test ./...`: that reuses cached PASS results, so a stale build
# can report green for code you just changed, and it runs without the race
# detector, which is where this repo's store and session defects actually show
# up. -count=1 defeats the cache; -race is the point.

.PHONY: help generate test build lint fmt vet clean

help: ## Show this help.
	@awk 'BEGIN{FS=":.*##";printf "\nUsage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*##/{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

test: ## Run the full suite. Everything must be green to ship.
	@set -e; for d in $$(grep -rl '^//go:generate go run github.com/zap-proto/zip/cmd/zipdoc' --include='*.go' . | xargs -n1 dirname | sort -u); do 	  (cd $$d && go run github.com/zap-proto/zip/cmd/zipdoc -check) || { echo "$$d/zipdoc_gen.go is stale — run: make generate"; exit 1; }; 	done
	go test ./... -race -count=1

build: ## Compile every package; write the server binary to ./iam.
	go build ./...
	go build -o iam .

fmt: ## Format.
	go fmt ./...

vet: ## Vet.
	go vet ./...

lint: vet ## Lint — go vet, the one static check this repo runs.

# The ONE artifact this repo writes to disk: the server binary from the root
# package, which `build` emits and .gitignore anchors as `/iam`. `go build ./...`
# alone cannot leave it — naming more than one package makes Go compile and
# DISCARD every object — so `build` runs both steps: the module-wide compile
# check, then the binary the Dockerfile ships (`go build -o /out/iam .`). Five
# packages (server, feature, internal/{e2e,featurestore,testhttp}) are unreachable
# from main, so dropping the first step would stop compiling them.
#
# NOT the zipdoc_gen.go files. Those are generated, but they are COMMITTED —
# a consumer building this module does not run go generate — so removing them
# deletes tracked source. `make generate` rewrites them; clean never touches them.
clean: ## Remove the built binary.
	rm -f iam
