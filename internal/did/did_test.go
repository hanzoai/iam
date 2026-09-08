// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package did

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/crypto/common"
	"github.com/luxfi/crypto/rlp"
)

// The anchor is exercised against a stub node rather than a chain: what has to
// be right is the call data, the signature, and the ORDER — and none of those
// need a block to be checked.

const (
	// signerKey is a fixed secp256k1 key, so a signature over fixed inputs is a
	// fixed value. It is the go-ethereum test vector, published for exactly this.
	signerKey  = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	signerAddr = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	// registryAt is the contract every test in this file writes to. It is a
	// value, not the estate's: there is deliberately no default address in the
	// package, and the one lux/standard records holds no code on any live chain.
	registryAt = "0x00000000000000000000000000000000000000dd"
	chainID    = 96369
	walletAddr = "0x9011E888251AB053B7bD1cdB598Db4f9DEd94714"
	subject    = "hanzo/z"
	fullDID    = "did:lux:hanzo:z"
)

// node is a stub JSON-RPC endpoint: it answers the reads a test configures and
// records every call it received, in order.
type node struct {
	t *testing.T

	mu    sync.Mutex
	calls []call
	// exists is what didExists answers; method is what method() answers.
	exists bool
	method string
	// fail names a method that answers with a JSON-RPC error.
	fail string
}

type call struct {
	method string
	params []json.RawMessage
}

func newNode(t *testing.T) (*node, *httptest.Server) {
	t.Helper()
	n := &node{t: t, method: "lux"}
	srv := httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(srv.Close)
	return n, srv
}

func (n *node) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		n.t.Fatalf("stub node: decode request: %v", err)
	}
	n.mu.Lock()
	n.calls = append(n.calls, call{method: req.Method, params: req.Params})
	fail := n.fail
	n.mu.Unlock()

	if fail == req.Method {
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": 1,
			"error": map[string]any{"code": -32000, "message": "execution reverted"}})
		return
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": 1, "result": n.answer(req)})
}

// answer produces the result for one request. eth_call is dispatched on the
// selector in the call data, which is how one stub serves both view methods.
func (n *node) answer(req struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}) string {
	switch req.Method {
	case "eth_call":
		var arg struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(req.Params[0], &arg); err != nil {
			n.t.Fatalf("stub node: eth_call params: %v", err)
		}
		switch {
		case strings.HasPrefix(arg.Data, "0x"+hex.EncodeToString(selector(sigMethod))):
			return "0x" + hex.EncodeToString(append(word(big.NewInt(wordLen)), bytesTail([]byte(n.method))...))
		case strings.HasPrefix(arg.Data, "0x"+hex.EncodeToString(selector(sigDIDExists))):
			v := big.NewInt(0)
			if n.exists {
				v = big.NewInt(1)
			}
			return "0x" + hex.EncodeToString(word(v))
		}
		n.t.Fatalf("stub node: unexpected eth_call %s", arg.Data)
	case "eth_getTransactionCount":
		return "0x7"
	case "eth_estimateGas":
		return "0x30d40"
	case "eth_gasPrice":
		return "0x3b9aca00"
	case "eth_sendRawTransaction":
		return "0x" + strings.Repeat("11", 32)
	}
	n.t.Fatalf("stub node: unexpected method %s", req.Method)
	return ""
}

// sent returns the raw transactions the node was given, in order.
func (n *node) sent() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out [][]byte
	for _, c := range n.calls {
		if c.method != "eth_sendRawTransaction" {
			continue
		}
		var raw string
		if err := json.Unmarshal(c.params[0], &raw); err != nil {
			n.t.Fatalf("raw transaction param: %v", err)
		}
		b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
		if err != nil {
			n.t.Fatalf("raw transaction hex: %v", err)
		}
		out = append(out, b)
	}
	return out
}

// methods returns the JSON-RPC method names in the order they were called.
func (n *node) methods() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.calls))
	for _, c := range n.calls {
		out = append(out, c.method)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// configure points the four settings at the stub node and a key file, and
// returns the Registry FromEnv builds from them — so the tests exercise the
// same construction a deployment does.
func configure(t *testing.T, rpcURL string) *Registry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller")
	// A trailing newline, because mounted secret material routinely carries one.
	if err := os.WriteFile(path, []byte(signerKey+"\n"), 0o600); err != nil {
		t.Fatalf("write key material: %v", err)
	}
	t.Setenv(EnvRPC, rpcURL)
	t.Setenv(EnvRegistry, registryAt)
	t.Setenv(EnvChain, "96369")
	t.Setenv(EnvKeyFile, path)
	r, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if r == nil {
		t.Fatal("FromEnv returned no registry with all four settings named")
	}
	return r
}

// A deployment that names nothing gets no registry and no error — the off
// state, which is the default and is not a misconfiguration.
func TestUnconfiguredIsOff(t *testing.T) {
	for _, name := range []string{EnvRPC, EnvRegistry, EnvChain, EnvKeyFile} {
		t.Setenv(name, "")
	}
	r, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv with nothing set: %v", err)
	}
	if r != nil {
		t.Fatal("FromEnv built a registry from no settings")
	}
	// The nil Registry is the whole reason the link path has no branch: every
	// method has to tolerate it.
	if err := r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr); err != nil {
		t.Fatalf("Anchor on an unconfigured registry: %v", err)
	}
	if got := r.Controller(); got != "" {
		t.Fatalf("Controller() on an unconfigured registry = %q, want empty", got)
	}
}

// A half-named registry is a mistake, not a choice. It is refused rather than
// silently behaving as the off state.
func TestPartialConfigurationIsRefused(t *testing.T) {
	for _, name := range []string{EnvRPC, EnvRegistry, EnvChain, EnvKeyFile} {
		t.Setenv(name, "")
	}
	t.Setenv(EnvRegistry, registryAt)
	if _, err := FromEnv(); !errors.Is(err, ErrPartial) {
		t.Fatalf("FromEnv with one setting = %v, want ErrPartial", err)
	}
}

// Each setting is checked at construction, so a deployment learns at the first
// link rather than mid-transaction.
func TestBadSettingsAreRefused(t *testing.T) {
	good := filepath.Join(t.TempDir(), "controller")
	if err := os.WriteFile(good, []byte(signerKey), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, registry, chain, key string }{
		{"registry is not an address", "0xnope", "96369", good},
		{"chain id is not a number", registryAt, "mainnet", good},
		{"chain id is zero", registryAt, "0", good},
		{"key file is absent", registryAt, "96369", filepath.Join(t.TempDir(), "missing")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvRPC, "http://127.0.0.1:1")
			t.Setenv(EnvRegistry, tc.registry)
			t.Setenv(EnvChain, tc.chain)
			t.Setenv(EnvKeyFile, tc.key)
			if r, err := FromEnv(); err == nil {
				t.Fatalf("FromEnv accepted %s, returning %v", tc.name, r)
			}
		})
	}
}

// The controller is derived from the key material, not configured beside it —
// a configured address could disagree with the key that actually signs, and
// the registry would then create documents nobody can write to.
func TestControllerComesFromTheKey(t *testing.T) {
	_, srv := newNode(t)
	r := configure(t, srv.URL)
	if !strings.EqualFold(r.Controller(), signerAddr) {
		t.Fatalf("Controller() = %s, want %s", r.Controller(), signerAddr)
	}
}

// The first wallet on an account writes three transactions in one order:
// create the document, point a service at the issuer, add the wallet. The
// service is written with the document because it does not change.
func TestAnchorCreatesTheDocumentThenTheWallet(t *testing.T) {
	n, srv := newNode(t)
	r := configure(t, srv.URL)

	if err := r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr); err != nil {
		t.Fatalf("Anchor: %v", err)
	}

	raws := n.sent()
	if len(raws) != 3 {
		t.Fatalf("sent %d transactions, want 3 (create, service, verification method)", len(raws))
	}
	want := [][]byte{
		createDIDFor("hanzo:z", common.HexToAddress(signerAddr)),
		addService(fullDID, service{
			id:          hash32(fullDID + "#iam"),
			serviceType: serviceIssuer,
			endpoint:    "https://hanzo.id",
			data:        []byte(subject),
		}),
		addVerificationMethod(fullDID, verification{
			id:          hash32(fullDID + "#evm:" + walletAddr),
			methodType:  methodEcdsaRecovery,
			controller:  common.HexToAddress(walletAddr),
			accountHash: accountWord(walletAddr),
		}),
	}
	for i, raw := range raws {
		tx := decodeTx(t, raw)
		if tx.to != strings.ToLower(registryAt) {
			t.Fatalf("transaction %d addressed %s, want the registry %s", i, tx.to, registryAt)
		}
		if hex.EncodeToString(tx.data) != hex.EncodeToString(want[i]) {
			t.Fatalf("transaction %d call data\n got %x\nwant %x", i, tx.data, want[i])
		}
		// Nonces run forward from the node's pending count. Three transactions
		// sharing one would replace each other in the mempool and only one
		// would land.
		if tx.nonce != uint64(7+i) {
			t.Fatalf("transaction %d nonce = %d, want %d", i, tx.nonce, 7+i)
		}
		if got := tx.signer(t); !strings.EqualFold(got, signerAddr) {
			t.Fatalf("transaction %d recovers to %s, want the controller %s", i, got, signerAddr)
		}
	}
}

// A document the registry already holds is not recreated — createDIDFor would
// revert — and the issuer service is not restated. Only the new wallet is
// written.
func TestAnchorAddsToAnExistingDocument(t *testing.T) {
	n, srv := newNode(t)
	n.exists = true
	r := configure(t, srv.URL)

	if err := r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	raws := n.sent()
	if len(raws) != 1 {
		t.Fatalf("sent %d transactions for an existing document, want 1", len(raws))
	}
	got := decodeTx(t, raws[0]).data
	want := addVerificationMethod(fullDID, verification{
		id:          hash32(fullDID + "#evm:" + walletAddr),
		methodType:  methodEcdsaRecovery,
		controller:  common.HexToAddress(walletAddr),
		accountHash: accountWord(walletAddr),
	})
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("the one transaction is not the verification method\n got %x\nwant %x", got, want)
	}
}

// A non-EVM wallet still anchors the ACCOUNT — the document and its issuer
// service — and is simply not written as a verification method, because the
// registry's struct types an account as an EVM address and nothing else.
func TestAnchorSkipsTheVerificationMethodOffEVM(t *testing.T) {
	n, srv := newNode(t)
	r := configure(t, srv.URL)

	if err := r.Anchor(context.Background(), subject, "https://hanzo.id", "solana", "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK"); err != nil {
		t.Fatalf("Anchor: %v", err)
	}
	if got := len(n.sent()); got != 2 {
		t.Fatalf("sent %d transactions for a solana wallet, want 2 (create, service)", got)
	}
}

// A registry serving a different DID method would register documents under
// strings no token's `did` claim matches. That is worse than not anchoring, so
// it fails closed — before any transaction is signed.
func TestAnchorRefusesAForeignMethod(t *testing.T) {
	n, srv := newNode(t)
	n.method = "ethr"
	r := configure(t, srv.URL)

	err := r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr)
	if err == nil || !strings.Contains(err.Error(), "ethr") {
		t.Fatalf("Anchor against a did:ethr registry = %v, want a refusal naming the method", err)
	}
	if got := len(n.sent()); got != 0 {
		t.Fatalf("sent %d transactions after refusing, want 0", got)
	}
	// The answer is kept, so a second link does not re-ask.
	before := len(n.methods())
	_ = r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr)
	if after := len(n.methods()); after != before {
		t.Fatalf("the method check was re-asked: %d calls became %d", before, after)
	}
}

// A subject the derivation refuses has no identifier to anchor, so nothing is
// sent rather than a document being registered under an empty name.
func TestAnchorRefusesASubjectWithNoIdentifier(t *testing.T) {
	n, srv := newNode(t)
	r := configure(t, srv.URL)

	if err := r.Anchor(context.Background(), "hanzo/z#k", "https://hanzo.id", "evm", walletAddr); err == nil {
		t.Fatal("Anchor accepted a subject that renders no identifier")
	}
	if got := len(n.sent()); got != 0 {
		t.Fatalf("sent %d transactions for an unrenderable subject, want 0", got)
	}
}

// A gas estimate is asked for BEFORE anything is signed, which is what turns a
// missing registrar role into a refusal here instead of a failed transaction
// that costs gas and reports nothing.
func TestAnchorStopsWhenTheCallWouldRevert(t *testing.T) {
	n, srv := newNode(t)
	n.fail = "eth_estimateGas"
	r := configure(t, srv.URL)

	err := r.Anchor(context.Background(), subject, "https://hanzo.id", "evm", walletAddr)
	if err == nil || !strings.Contains(err.Error(), "execution reverted") {
		t.Fatalf("Anchor = %v, want the node's own revert reason", err)
	}
	if got := len(n.sent()); got != 0 {
		t.Fatalf("sent %d transactions despite a failing estimate, want 0", got)
	}
}

// Report must not hold a request open, and must not use the request's context —
// which is cancelled the moment the response is written.
func TestReportDoesNotBlock(t *testing.T) {
	n, srv := newNode(t)
	r := configure(t, srv.URL)

	done := make(chan struct{})
	go func() { r.Report(subject, "https://hanzo.id", "evm", walletAddr); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Report blocked its caller")
	}
	// The write itself still happens; give the goroutine a moment to land.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(n.sent()) < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(n.sent()); got != 3 {
		t.Fatalf("Report sent %d transactions, want 3", got)
	}
}

// A chain id is required: without it the signature is not replay-protected, so
// a transaction authorizing a DID write on one network could be rebroadcast on
// another sharing the registry's address.
func TestSignRequiresAChainID(t *testing.T) {
	k, err := newKey(signerKey)
	if err != nil {
		t.Fatalf("newKey: %v", err)
	}
	for _, id := range []*big.Int{nil, big.NewInt(0)} {
		if _, err := k.sign(id, 0, big.NewInt(1), 21000, common.HexToAddress(registryAt), nil); err == nil {
			t.Fatalf("sign accepted chain id %v", id)
		}
	}
}

// --- reading a raw transaction back ---

// tx is a decoded legacy transaction, enough of one to check what a node would
// have received.
type tx struct {
	nonce    uint64
	gasPrice *big.Int
	gas      uint64
	to       string
	value    *big.Int
	data     []byte
	v, r, s  *big.Int
}

// signer recovers the address that signed the transaction, by rebuilding the
// EIP-155 signing payload from the decoded fields. It is the check that matters
// most here: the node's answer to "who authorized this" is the only thing the
// registry's access control sees.
func (x tx) signer(t *testing.T) string {
	t.Helper()
	chain := new(big.Int).Div(new(big.Int).Sub(x.v, big.NewInt(35)), big.NewInt(2))
	recovery := new(big.Int).Sub(x.v, new(big.Int).Add(new(big.Int).Mul(chain, big.NewInt(2)), big.NewInt(35)))
	payload, err := rlp.EncodeToBytes([]any{
		x.nonce, x.gasPrice, x.gas, common.HexToAddress(x.to), uint64(0), x.data,
		chain, uint64(0), uint64(0),
	})
	if err != nil {
		t.Fatalf("re-encode signing payload: %v", err)
	}
	sig := make([]byte, 65)
	x.r.FillBytes(sig[:32])
	x.s.FillBytes(sig[32:64])
	sig[64] = byte(recovery.Uint64())
	pub, err := luxcrypto.SigToPub(luxcrypto.Keccak256(payload), sig)
	if err != nil {
		t.Fatalf("recover signer: %v", err)
	}
	if chain.Int64() != chainID {
		t.Fatalf("transaction carries chain id %s, want %d", chain, chainID)
	}
	return luxcrypto.PubkeyToAddress(*pub).Hex()
}

// decodeTx reads a legacy transaction back out of its RLP. The package encodes
// but does not decode, so this is written here rather than reused — and that is
// the point: the assertion is over the bytes a NODE would parse, not over the
// values the encoder was handed.
func decodeTx(t *testing.T, raw []byte) tx {
	t.Helper()
	items := rlpList(t, raw)
	if len(items) != 9 {
		t.Fatalf("transaction has %d fields, want 9 (legacy, EIP-155)", len(items))
	}
	num := func(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
	return tx{
		nonce:    num(items[0]).Uint64(),
		gasPrice: num(items[1]),
		gas:      num(items[2]).Uint64(),
		to:       "0x" + hex.EncodeToString(items[3]),
		value:    num(items[4]),
		data:     items[5],
		v:        num(items[6]),
		r:        num(items[7]),
		s:        num(items[8]),
	}
}

// rlpList splits one RLP list into its items' payloads. It handles the string
// and list headers a transaction actually contains and nothing else.
func rlpList(t *testing.T, b []byte) [][]byte {
	t.Helper()
	payload, rest := rlpItem(t, b)
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after the transaction: %x", rest)
	}
	var out [][]byte
	for len(payload) > 0 {
		var item []byte
		item, payload = rlpItem(t, payload)
		out = append(out, item)
	}
	return out
}

// rlpItem reads one RLP item, returning its payload and the remaining bytes.
func rlpItem(t *testing.T, b []byte) (payload, rest []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("rlp: empty input")
	}
	k := b[0]
	switch {
	case k <= 0x7f:
		return b[:1], b[1:]
	case k <= 0xb7:
		n := int(k - 0x80)
		return b[1 : 1+n], b[1+n:]
	case k <= 0xbf:
		w := int(k - 0xb7)
		n := int(new(big.Int).SetBytes(b[1 : 1+w]).Int64())
		return b[1+w : 1+w+n], b[1+w+n:]
	case k <= 0xf7:
		n := int(k - 0xc0)
		return b[1 : 1+n], b[1+n:]
	default:
		w := int(k - 0xf7)
		n := int(new(big.Int).SetBytes(b[1 : 1+w]).Int64())
		return b[1+w : 1+w+n], b[1+w+n:]
	}
}

// accountWord renders an EVM address into the bytes32 the verification method
// carries it in.
func accountWord(addr string) [32]byte {
	var out [32]byte
	a := common.HexToAddress(addr)
	copy(out[wordLen-common.AddressLength:], a[:])
	return out
}
