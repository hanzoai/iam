# The test gate. One command, run identically by a human and by CI.
#
# Not a bare `go test ./...`: that reuses cached PASS results, so a stale build
# can report green for code you just changed, and it runs without the race
# detector, which is where this repo's store and session defects actually show
# up. -count=1 defeats the cache; -race is the point.

.PHONY: test build fmt vet

test: ## Run the full suite — the gate. Everything must be green to ship.
	go test ./... -race -count=1

build: ## Build every package.
	go build ./...

fmt: ## Format.
	go fmt ./...

vet: ## Vet.
	go vet ./...
