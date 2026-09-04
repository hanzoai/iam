// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package did

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/crypto/common"
	"github.com/luxfi/crypto/rlp"
)

// The chain leg: a JSON-RPC client and a legacy EIP-155 transaction signer, and
// deliberately nothing else. No block subscription, no receipt polling, no
// nonce cache, no gas oracle. IAM writes at most three transactions when a
// person links a wallet and never reads the chain otherwise; a client with a
// lifecycle would be a second piece of infrastructure to operate inside an
// identity provider.
//
// Legacy (type 0) rather than EIP-1559 because it is the shape every EVM in the
// estate accepts, including the ones that never activated London. A fee market
// would buy nothing here: these transactions are not competing for inclusion.

// rpc is a minimal JSON-RPC 2.0 caller over one endpoint.
type rpc struct {
	url    string
	client *http.Client
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

// call sends one JSON-RPC request and decodes the result into a hex-string.
// Every method this package uses answers with one, so the caller never handles
// a second shape.
func (r rpc) call(ctx context.Context, method string, params ...any) (string, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var out struct {
		Result string    `json:"result"`
		Error  *rpcError `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("%s: %w", method, out.Error)
	}
	return out.Result, nil
}

// number decodes a hex-quantity answer ("0x1f") into a big.Int.
func (r rpc) number(ctx context.Context, method string, params ...any) (*big.Int, error) {
	s, err := r.call(ctx, method, params...)
	if err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("%s: %q is not a quantity", method, s)
	}
	return n, nil
}

// view performs an eth_call against the registry and returns the raw return
// data. It reads; it never spends and never needs the key.
func (r rpc) view(ctx context.Context, to common.Address, data []byte) ([]byte, error) {
	s, err := r.call(ctx, "eth_call", map[string]string{
		"to": to.Hex(), "data": hexData(data),
	}, "latest")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// send signs and broadcasts one transaction, returning its hash.
//
// The gas limit is ESTIMATED rather than guessed, which does double duty: a
// call that would revert — the commonest cause being a signer that was never
// granted REGISTRAR_ROLE — fails here, cheaply and with the node's own revert
// reason, instead of being mined into a failed transaction that costs gas and
// says nothing.
func (r rpc) send(ctx context.Context, k *key, chainID *big.Int, to common.Address, nonce uint64, data []byte) (string, error) {
	from := k.address.Hex()
	gas, err := r.number(ctx, "eth_estimateGas", map[string]string{
		"from": from, "to": to.Hex(), "data": hexData(data),
	})
	if err != nil {
		return "", err
	}
	price, err := r.number(ctx, "eth_gasPrice")
	if err != nil {
		return "", err
	}
	raw, err := k.sign(chainID, nonce, price, gas.Uint64(), to, data)
	if err != nil {
		return "", err
	}
	return r.call(ctx, "eth_sendRawTransaction", hexData(raw))
}

// nonceOf reads the next transaction index for the signer. "pending" is asked
// for rather than "latest" so a second link that lands while the first is still
// in the mempool does not reuse an index and get itself dropped as a
// replacement.
func (r rpc) nonceOf(ctx context.Context, from common.Address) (uint64, error) {
	n, err := r.number(ctx, "eth_getTransactionCount", from.Hex(), "pending")
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}

// key is the controller credential: a secp256k1 private key and the address it
// derives. The key material is loaded once, at construction, and never leaves
// this struct.
type key struct {
	priv    *ecdsa.PrivateKey
	address common.Address
}

// newKey parses hex private-key material — the bytes a KMS-synced secret volume
// presents — and derives its address. A `0x` prefix and surrounding whitespace
// are tolerated because mounted material routinely carries both.
func newKey(material string) (*key, error) {
	h := strings.TrimPrefix(strings.TrimSpace(material), "0x")
	priv, err := luxcrypto.HexToECDSA(h)
	if err != nil {
		return nil, fmt.Errorf("controller key: %w", err)
	}
	return &key{priv: priv, address: luxcrypto.PubkeyToAddress(priv.PublicKey)}, nil
}

// sign produces the raw RLP of a signed legacy EIP-155 transaction.
//
// EIP-155 is the replay guard and it is not optional: the chain id goes into the
// hash that is signed and into the recovery value, so a transaction authorizing
// a DID write on one network cannot be rebroadcast on another that shares the
// registry's address. Every value carried here is zero (these calls transfer
// nothing) except the call data.
func (k *key) sign(chainID *big.Int, nonce uint64, gasPrice *big.Int, gas uint64, to common.Address, data []byte) ([]byte, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, errors.New("chain id is required for a replay-protected transaction")
	}
	payload, err := rlp.EncodeToBytes([]any{
		nonce, gasPrice, gas, to, uint64(0), data, chainID, uint64(0), uint64(0),
	})
	if err != nil {
		return nil, err
	}
	sig, err := luxcrypto.Sign(luxcrypto.Keccak256(payload), k.priv)
	if err != nil {
		return nil, err
	}
	// crypto.Sign answers [R || S || V] with V in {0,1}; EIP-155 carries it as
	// v = V + chainID*2 + 35.
	v := new(big.Int).Add(
		new(big.Int).Mul(chainID, big.NewInt(2)),
		big.NewInt(int64(sig[64])+35),
	)
	return rlp.EncodeToBytes([]any{
		nonce, gasPrice, gas, to, uint64(0), data,
		v, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64]),
	})
}

// hexData renders call data / raw transaction bytes as the 0x-prefixed string
// JSON-RPC takes.
func hexData(b []byte) string { return "0x" + hex.EncodeToString(b) }

// abiString decodes a single `string` return value from eth_call data: an
// offset word, a length word, then the bytes.
func abiString(data []byte) (string, error) {
	if len(data) < 2*wordLen {
		return "", errors.New("return data is too short for a string")
	}
	off := new(big.Int).SetBytes(data[:wordLen]).Uint64()
	if off+wordLen > uint64(len(data)) {
		return "", errors.New("string offset is out of range")
	}
	n := new(big.Int).SetBytes(data[off : off+wordLen]).Uint64()
	if off+wordLen+n > uint64(len(data)) {
		return "", errors.New("string length is out of range")
	}
	return string(data[off+wordLen : off+wordLen+n]), nil
}

// abiBool decodes a single `bool` return value: one word, zero or one.
func abiBool(data []byte) (bool, error) {
	if len(data) < wordLen {
		return false, errors.New("return data is too short for a bool")
	}
	return new(big.Int).SetBytes(data[:wordLen]).Sign() != 0, nil
}
