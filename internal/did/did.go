// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package did anchors an IAM account's derived identifier in the Lux
// DIDRegistry (contracts/identity/DIDRegistry.sol), so that the identity a token
// asserts and the identity a chain resolves are the same one.
//
// It is OPTIONAL and OFF unless a deployment names all four of its settings. An
// unconfigured IAM links wallets, mints the `wallets` and `did` claims, and
// never touches a chain — the claim is derived from the subject (schema.DID) and
// owes the registry nothing. Anchoring adds a public, third-party-checkable
// record of the same fact; it does not create the fact.
//
// THE STORE IS THE SOURCE OF TRUTH, the registry is a projection. Every write
// here happens after the link is committed and outside its transaction, so a
// chain that is slow, forked, or gone cannot fail a sign-in or leave a wallet
// half-linked. The cost of that ordering is that a failed anchor is not retried:
// the DID document catches up the next time that person links a wallet. A
// deployment wanting convergence should reconcile from the store, which holds
// every binding, rather than making a login wait on a block.
package did

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/luxfi/crypto/common"

	"github.com/hanzoai/iam/pkg/schema"
)

// The settings. All four or none: a half-named registry is a mistake, not a
// choice, so it is refused loudly instead of degrading into the off state and
// leaving an operator to wonder why nothing is being written.
const (
	// EnvRPC is the JSON-RPC endpoint of the chain the registry lives on.
	EnvRPC = "IAM_DID_RPC"
	// EnvRegistry is the DIDRegistry contract address (0x-prefixed).
	//
	// There is no default, deliberately. An address that ships in source is an
	// address nobody re-checks, and the one recorded for this contract in
	// lux/standard's registry.json holds no code on any live Lux chain while
	// naming an AMM router on another — a default would have pointed every
	// deployment at it.
	EnvRegistry = "IAM_DID_REGISTRY"
	// EnvChain is the EIP-155 chain id, decimal. It is signed into every
	// transaction, so it is stated rather than discovered: a node that answers
	// eth_chainId with the wrong value would otherwise get IAM to sign
	// transactions replayable on the network it actually meant.
	EnvChain = "IAM_DID_CHAIN"
	// EnvKeyFile is the path to the controller key material — hex, one line.
	//
	// A FILE, never an inline value, because the estate has exactly one secret
	// path: Hanzo KMS → KMSSecret → K8s Secret → mounted material (the same one
	// internal/registry/signkey.go and provision's DirCredentials read). A key
	// in the environment is a plaintext secret in a pod spec, readable by
	// anything that can describe the workload, and it is not what KMS delivers.
	EnvKeyFile = "IAM_DID_KEY_FILE"
)

// Verification method and service types, by their ordinal in
// interfaces/IDID.sol. Named here so a reader sees which member of the enum is
// meant without counting positions in another repo.
const (
	methodEcdsaRecovery = 5 // EcdsaSecp256k1RecoveryMethod2020
	serviceIssuer       = 9 // CredentialIssuer
)

// evmChain is the wallet chain family whose addresses the registry can type.
// See Registry.Anchor for why the others are linked but not anchored.
const evmChain = "evm"

// ErrPartial reports a deployment that named some settings and not others.
var ErrPartial = errors.New("did: the registry needs " + EnvRPC + ", " + EnvRegistry + ", " + EnvChain + " and " + EnvKeyFile + " together, or none of them")

// Registry writes an account's identifier and its wallets into a DIDRegistry.
// The zero value is not usable; FromEnv is the one constructor, and a nil
// *Registry is the configured-off state that every method tolerates.
type Registry struct {
	rpc      rpc
	contract common.Address
	chainID  *big.Int
	key      *key

	// The registry builds its DID strings as "did:" + method + ":" + identifier
	// with its OWN method, set at deployment. Ours are rendered with
	// schema.DIDMethod. If the two disagree, every document IAM creates is
	// addressed by a string IAM cannot name, so the check runs once and the
	// answer is kept.
	once   sync.Once
	method error
}

// FromEnv builds the Registry a deployment configured, or (nil, nil) when it
// configured none — the off state, which is not an error.
func FromEnv() (*Registry, error) {
	rpcURL := env(EnvRPC)
	contract := env(EnvRegistry)
	chain := env(EnvChain)
	keyFile := env(EnvKeyFile)

	named := 0
	for _, v := range []string{rpcURL, contract, chain, keyFile} {
		if v != "" {
			named++
		}
	}
	switch named {
	case 0:
		return nil, nil
	case 4:
	default:
		return nil, ErrPartial
	}

	if !common.IsHexAddress(contract) {
		return nil, fmt.Errorf("did: %s=%q is not a contract address", EnvRegistry, contract)
	}
	id, ok := new(big.Int).SetString(chain, 10)
	if !ok || id.Sign() <= 0 {
		return nil, fmt.Errorf("did: %s=%q is not a chain id", EnvChain, chain)
	}
	material, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("did: read %s=%s: %w", EnvKeyFile, keyFile, err)
	}
	k, err := newKey(string(material))
	if err != nil {
		return nil, fmt.Errorf("did: %w", err)
	}
	return &Registry{
		rpc:      rpc{url: rpcURL, client: &http.Client{Timeout: 20 * time.Second}},
		contract: common.HexToAddress(contract),
		chainID:  id,
		key:      k,
	}, nil
}

// Controller is the address IAM signs with — the account that must hold
// REGISTRAR_ROLE on the registry, and the controller every document it creates
// is registered to. Empty when unconfigured.
func (r *Registry) Controller() string {
	if r == nil {
		return ""
	}
	return r.key.address.Hex()
}

// Anchor records a newly linked wallet against the account's DID: it creates
// the document if the registry does not already hold one, points a service
// entry at the issuer that asserts the identity, and adds the wallet as a
// verification method.
//
// A nil Registry — the unconfigured deployment — returns nil immediately. The
// caller does not branch on whether anchoring is switched on, so the linking
// path reads the same either way.
//
// WHO MAY WRITE WHAT. The contract splits its authority: createDIDFor is
// onlyRole(REGISTRAR_ROLE), while addVerificationMethod and addService are
// controller-only (_isController). One key can therefore do all three only by
// creating documents controlled BY ITSELF, which is what happens here — IAM is
// the controller, which is what lets it keep a document in step as a person
// links a second wallet. The consequence is worth saying plainly: these
// documents are not self-sovereign. Handing control to the person (the
// contract's changeController) ends IAM's ability to write, and there is no
// registrar override to get it back.
//
// EVM WALLETS ARE ANCHORED; THE OTHERS ARE NOT. The registry's
// VerificationMethod types an account as an `address` plus a bytes32
// blockchainAccountId, which fits a secp256k1 EVM account and nothing else. A
// Solana or Bitcoin address does not go in an `address` field, and packing one
// there would be inventing an encoding no resolver reads. Those wallets link
// normally, appear in the `wallets` claim, and count as a credential; they are
// simply absent from the on-chain document. The DID and its issuer service are
// still written, so the account is anchored even when the wallet that triggered
// it is not.
func (r *Registry) Anchor(ctx context.Context, subject, issuer, chain, address string) error {
	if r == nil {
		return nil
	}
	id := schema.DID(subject)
	if id == "" {
		return fmt.Errorf("did: subject %q has no identifier", subject)
	}
	if err := r.check(ctx); err != nil {
		return err
	}

	exists, err := r.exists(ctx, id)
	if err != nil {
		return err
	}
	nonce, err := r.rpc.nonceOf(ctx, r.key.address)
	if err != nil {
		return err
	}

	if !exists {
		identifier := strings.TrimPrefix(id, "did:"+schema.DIDMethod+":")
		if err := r.write(ctx, &nonce, createDIDFor(identifier, r.key.address)); err != nil {
			return fmt.Errorf("did: create %s: %w", id, err)
		}
		// The issuer service says WHERE this identity is asserted and WHO it is
		// there — the OIDC issuer and the subject at it — which is the whole of
		// what makes the on-chain document and the token the same identity. It
		// is written once, with the document, because it does not change: a
		// second wallet on the same account is asserted by the same issuer.
		if err := r.write(ctx, &nonce, addService(id, service{
			id:          hash32(id + "#iam"),
			serviceType: serviceIssuer,
			endpoint:    issuer,
			data:        []byte(subject),
		})); err != nil {
			return fmt.Errorf("did: service %s: %w", id, err)
		}
	}

	if chain != evmChain {
		return nil
	}
	if !common.IsHexAddress(address) {
		return fmt.Errorf("did: %q is not an evm address", address)
	}
	wallet := common.HexToAddress(address)
	var account [32]byte
	copy(account[wordLen-common.AddressLength:], wallet[:])
	if err := r.write(ctx, &nonce, addVerificationMethod(id, verification{
		id: hash32(id + "#" + chain + ":" + address),
		// Recovery-method rather than a key type: IAM verified a personal_sign
		// and recovered an ADDRESS. It never held the public key, and naming a
		// key type would claim material this service does not have.
		methodType: methodEcdsaRecovery,
		controller: wallet,
		// No publicKeyMultibase, for the same reason.
		accountHash: account,
	})); err != nil {
		return fmt.Errorf("did: verification method %s: %w", id, err)
	}
	return nil
}

// Report runs Anchor in the background and writes a line when it fails.
//
// It is separate from Anchor so the anchoring itself stays synchronous and
// directly testable, and so the ONE place that decides "a chain write must
// never delay a sign-in" is visible rather than spread across callers. The
// context is this function's own: the request's is cancelled the moment the
// response is written, which would abort every one of these.
func (r *Registry) Report(subject, issuer, chain, address string) {
	if r == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := r.Anchor(ctx, subject, issuer, chain, address); err != nil {
			log.Printf("did: anchor %s (%s): %v", subject, chain, err)
		}
	}()
}

// check verifies once that the registry names the method our identifiers are
// rendered with. It fails closed: a registry answering a different method would
// register documents under strings no token's `did` claim matches, which is a
// worse outcome than not anchoring at all.
func (r *Registry) check(ctx context.Context) error {
	r.once.Do(func() {
		data, err := r.rpc.view(ctx, r.contract, registryMethod())
		if err != nil {
			r.method = fmt.Errorf("did: read registry method: %w", err)
			return
		}
		got, err := abiString(data)
		if err != nil {
			r.method = fmt.Errorf("did: read registry method: %w", err)
			return
		}
		if got != schema.DIDMethod {
			r.method = fmt.Errorf("did: registry serves method %q, identifiers are rendered as %q", got, schema.DIDMethod)
		}
	})
	return r.method
}

// exists reports whether the registry already holds a document for this DID.
func (r *Registry) exists(ctx context.Context, id string) (bool, error) {
	data, err := r.rpc.view(ctx, r.contract, didExists(id))
	if err != nil {
		return false, fmt.Errorf("did: resolve %s: %w", id, err)
	}
	return abiBool(data)
}

// write sends one transaction and advances the local nonce. The index is held
// by the caller across the run so three writes in one anchor do not all claim
// the same one — the node reports a pending count, and three transactions sent
// before any is mined would otherwise replace each other.
func (r *Registry) write(ctx context.Context, nonce *uint64, data []byte) error {
	if _, err := r.rpc.send(ctx, r.key, r.chainID, r.contract, *nonce, data); err != nil {
		return err
	}
	*nonce++
	return nil
}

// env reads a setting, trimmed.
func env(name string) string { return strings.TrimSpace(os.Getenv(name)) }
