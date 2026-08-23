// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	wan "github.com/go-webauthn/webauthn/webauthn"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// A virtual authenticator, and the ceremonies driven end to end through it.
//
// Every assertion here is a REAL ECDSA signature over real authenticator data,
// encoded with the library's own CBOR and COSE writers, so a test that passes has
// exercised the verifier rather than a stub of it. Each negative test changes ONE
// thing about what the authenticator signs — the verification bit, the relying
// party it signed for, whose key signed — and demands a refusal.

// The authenticator-data flags a real platform authenticator sets. UP is the
// person's presence, UV that the device verified WHO they are (Face ID, a PIN);
// BE and BS say the credential can be and is backed up, which is what makes a
// passkey follow somebody to a new phone. AT marks the attested credential data
// that rides along on a registration only.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40

	// signPresent is what an ordinary assertion sets: present, verified, backed up.
	signPresent = flagUP | flagUV | flagBE | flagBS
	// signUnverified is the same assertion from a device that let the key go
	// WITHOUT verifying the person — a passkey reduced to possession.
	signUnverified = flagUP | flagBE | flagBS
	// attested is a registration: an assertion's flags plus the attested key.
	attested = signPresent | flagAT
)

// testOrigin is the one origin these ceremonies run at, and testRPID the relying
// party derived from it. pin makes the server agree.
const (
	testOrigin = "https://hanzo.id"
	testRPID   = "hanzo.id"
)

// pin fixes the issuer the relying party is read from, so the RP ID a test signs
// for is the RP ID the server verifies against no matter what else has run.
func pin(t *testing.T) {
	t.Helper()
	r, err := newIssuerResolver(testOrigin, "", false)
	if err != nil {
		t.Fatalf("pin issuer: %v", err)
	}
	prev := activeResolver.Load()
	activeResolver.Store(r)
	t.Cleanup(func() { activeResolver.Store(prev) })
}

// authenticator is a virtual FIDO2 authenticator: one P-256 key and the credential
// id it is filed under.
type authenticator struct {
	priv *ecdsa.PrivateKey
	id   []byte
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("credential id: %v", err)
	}
	return &authenticator{priv: priv, id: id}
}

// cose is the public key in the COSE form an authenticator hands over at
// registration, written with the library's own encoder.
func (a *authenticator) cose(t *testing.T) []byte {
	t.Helper()
	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        a.priv.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord:        a.priv.PublicKey.Y.FillBytes(make([]byte, 32)),
	}
	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("encode COSE key: %v", err)
	}
	return b
}

// data builds authenticator data: the hash of the relying party id the key was
// released for, the flags, the signature counter, and — on a registration — the
// attested credential.
func (a *authenticator) data(t *testing.T, rpID string, flags byte, counter uint32) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, sum[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	if flags&flagAT == 0 {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID: none
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
	out = append(out, a.id...)
	return append(out, a.cose(t)...)
}

// clientData is what the BROWSER attests to: the ceremony, the challenge it was
// answering, and the origin the page was actually on.
func clientData(t *testing.T, ceremony, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": ceremony, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("encode client data: %v", err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// attest answers a registration challenge — the body the browser POSTs after
// navigator.credentials.create().
func (a *authenticator) attest(t *testing.T, challenge string, flags byte) []byte {
	t.Helper()
	client := clientData(t, "webauthn.create", challenge, testOrigin)
	object, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.data(t, testRPID, flags, 0),
	})
	if err != nil {
		t.Fatalf("encode attestation: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{
			"attestationObject": b64(object), "clientDataJSON": b64(client),
		},
	})
	return body
}

// sign answers an assertion challenge — the body the browser POSTs after
// navigator.credentials.get(). rpID and flags are arguments rather than constants
// so a test can produce an assertion signed for the WRONG relying party, or one the
// device released without verifying the person.
func (a *authenticator) sign(t *testing.T, challenge string, handle []byte, rpID string, flags byte, counter uint32) []byte {
	t.Helper()
	client := clientData(t, "webauthn.get", challenge, testOrigin)
	auth := a.data(t, rpID, flags, counter)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": b64(auth), "clientDataJSON": b64(client),
			"signature": b64(sig), "userHandle": b64(handle),
		},
	})
	return body
}

// --- driving the ceremonies ---

// begin runs a begin leg and returns the challenge the authenticator must answer
// and the cookie that names the outstanding ceremony.
func begin(t *testing.T, app *zip.App, path, cookie string) (challenge, held string) {
	t.Helper()
	req := formReqNoBody("GET", path)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.PublicKey.Challenge == "" {
		t.Fatalf("GET %s returned no challenge (status %d): %s", path, resp.StatusCode, body)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == challengeCookie {
			held = ck.Name + "=" + ck.Value
		}
	}
	if held == "" {
		t.Fatalf("GET %s set no %s cookie, so nothing binds the ceremony", path, challengeCookie)
	}
	return out.PublicKey.Challenge, held
}

// finish posts an answer and returns the decoded envelope.
func finish(t *testing.T, app *zip.App, path, held string, body []byte) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", held)
	_, raw := do(t, app, req)
	return decode(t, raw)
}

// enroll registers a passkey for the signed-in caller and returns the envelope.
func enroll(t *testing.T, app *zip.App, cookie string, a *authenticator, flags byte) map[string]any {
	t.Helper()
	challenge, held := begin(t, app, PathWebauthnRegisterBegin, cookie)
	return finish(t, app, PathWebauthnRegisterFinish, held, a.attest(t, challenge, flags))
}

// passkeyServer seeds the application and hanzo/alice, signs her in, and pins the
// relying party. It returns the app, the store and her session cookie.
func passkeyServer(t *testing.T) (*zip.App, orm.DB, string) {
	t.Helper()
	pin(t)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	return app, db, sessionCookieFor(t, app)
}

// handleFor is the user handle an authenticator stores beside a passkey and returns
// on every assertion.
func handleFor(t *testing.T, db orm.DB, owner, name string) []byte {
	t.Helper()
	u, err := orm.Get[schema.User](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	return []byte(subjectOf(u))
}

// --- the ceremonies ---

// The whole point, end to end: a person enrolls a passkey and then signs in with it.
// Everything else in this file is a way for this to go wrong.
func TestPasskeyEnrollsAndSignsIn(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)

	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	// The passkey is a row the credential surface can list and revoke — one table,
	// written by the ceremony and administered there.
	row, err := orm.Get[schema.WebauthnCredential](db, "hanzo/"+schema.CredentialName(a.id))
	if err != nil {
		t.Fatalf("the attested passkey is not addressable as a credential row: %v", err)
	}
	if row.User != "hanzo/alice" {
		t.Errorf("passkey row User = %q, want hanzo/alice", row.User)
	}
	if !row.UserVerified {
		t.Error("passkey row records UserVerified = false after a verified enrollment")
	}

	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	env := finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signPresent, 1))
	if env["status"] != "ok" {
		t.Fatalf("passkey sign-in refused: %v", env["msg"])
	}
	if env["data"] != "hanzo/alice" {
		t.Errorf("sign-in returned data = %v, want the identity hanzo/alice", env["data"])
	}
}

// A captured assertion is worth one use. The challenge is burned when it is
// answered, so replaying the very same bytes — the exact thing an attacker who
// recorded a sign-in holds — loses.
func TestPasskeyReplayedChallengeIsRefused(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	answer := a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signPresent, 1)

	if env := finish(t, app, PathWebauthnLoginFinish, held, answer); env["status"] != "ok" {
		t.Fatalf("the first use of the challenge was refused: %v", env["msg"])
	}
	if env := finish(t, app, PathWebauthnLoginFinish, held, answer); env["status"] == "ok" {
		t.Fatal("a replayed assertion signed in a second time: the challenge was not burned")
	}
}

// A challenge is bound to the person it was minted for. Bob's passkey cannot answer
// Alice's challenge — the ceremony reads WHOSE it is from the burned row, never from
// the request, so there is nothing in the answer that can redirect it.
func TestPasskeyChallengeForAnotherPersonIsRefused(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	alice := newAuthenticator(t)
	if env := enroll(t, app, cookie, alice, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	// Bob is a real account with a real passkey of his own.
	bob := newAuthenticator(t)
	seedUserNamed(t, db, "bob")
	bobCookie := sessionCookieForNamed(t, app, "bob")
	if env := enroll(t, app, bobCookie, bob, attested); env["status"] != "ok" {
		t.Fatalf("bob's enrollment refused: %v", env["msg"])
	}

	// A challenge minted for Alice, answered by Bob's authenticator with Bob's own
	// key, credential id and handle. Every part of it is individually valid.
	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	env := finish(t, app, PathWebauthnLoginFinish, held,
		bob.sign(t, challenge, handleFor(t, db, "hanzo", "bob"), testRPID, signPresent, 1))
	if env["status"] == "ok" {
		t.Fatalf("bob's passkey answered alice's challenge and signed somebody in as %v", env["data"])
	}

	// Sharper: Bob claims ALICE's handle. The handle is the `sub` — an identifier
	// that travels in tokens, so an attacker can be assumed to know it. That removes
	// the handle comparison from the argument and leaves only the rule that the
	// answering credential must be one of ALICE's.
	challenge, held = begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	env = finish(t, app, PathWebauthnLoginFinish, held,
		bob.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signPresent, 1))
	if env["status"] == "ok" {
		t.Fatalf("bob's passkey wearing alice's handle signed somebody in as %v", env["data"])
	}
}

// The enrollment check, isolated the same way its sign-in twin is: with the
// requirement missing from the stored ceremony, an unverified passkey must still be
// refused rather than stored. The two checks share one failure mode — the session
// round-trip — so they would be lost together, and a stored unverified credential is
// what a lost pair would leave behind for a later sign-in to accept.
func TestPasskeyEnrollmentVerificationSurvivesALostRequirement(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)

	challenge, held := begin(t, app, PathWebauthnRegisterBegin, cookie)
	forgetVerification(t, db, held)
	env := finish(t, app, PathWebauthnRegisterFinish, held, a.attest(t, challenge, attested&^flagUV))
	if env["status"] == "ok" {
		t.Fatal("with the requirement lost from the stored ceremony, an unverified " +
			"passkey was enrolled")
	}
	if _, err := orm.Get[schema.WebauthnCredential](db, "hanzo/"+schema.CredentialName(a.id)); err == nil {
		t.Fatal("the refused passkey was stored anyway")
	}
}

// Without user verification a passkey proves possession of a phone and nothing
// about who is holding it. An assertion whose UV bit is clear — a stolen unlocked
// device, an authenticator configured not to ask — is not a sign-in.
func TestPasskeyUnverifiedAssertionIsRefused(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	// The ONLY difference from the passing sign-in above is the verification bit.
	env := finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signUnverified, 1))
	if env["status"] == "ok" {
		t.Fatal("an assertion the device released WITHOUT verifying the person signed them in")
	}
}

// Both ceremonies ASK the browser for verification, and for a credential the device
// keeps.
//
// This is the half the refusals cannot show. A server that only refuses unverified
// assertions after the fact would let a person complete a passkey prompt that never
// asked for their face, and then be told no — so what the options say is its own
// property, read off the wire the browser reads.
func TestPasskeyCeremoniesAskForVerification(t *testing.T) {
	app, _, cookie := passkeyServer(t)

	req := formReqNoBody("GET", PathWebauthnRegisterBegin)
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	var reg struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				UserVerification string `json:"userVerification"`
				ResidentKey      string `json:"residentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode enrollment options: %v (%s)", err, body)
	}
	if got := reg.PublicKey.AuthenticatorSelection.UserVerification; got != "required" {
		t.Errorf("enrollment userVerification = %q, want required: the browser is not "+
			"being told to demand a fingerprint, face or PIN", got)
	}
	if got := reg.PublicKey.AuthenticatorSelection.ResidentKey; got != "required" {
		t.Errorf("enrollment residentKey = %q, want required: the credential would not "+
			"be a passkey the device holds", got)
	}

	_, body = do(t, app, formReqNoBody("GET", PathWebauthnLoginBegin+"?owner=hanzo&name=alice"))
	// A person with no passkey is refused, which is the wrong shape to read options
	// from — so enroll one first and ask again.
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}
	_, body = do(t, app, formReqNoBody("GET", PathWebauthnLoginBegin+"?owner=hanzo&name=alice"))
	var login struct {
		PublicKey struct {
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatalf("decode sign-in options: %v (%s)", err, body)
	}
	if got := login.PublicKey.UserVerification; got != "required" {
		t.Errorf("sign-in userVerification = %q, want required", got)
	}
}

// The options are shaped for the browser code that already calls these addresses.
//
// The hosted login page and account page were written against this ceremony long
// before it answered: they read publicKey.challenge, publicKey.user.id and the
// credential ids out of the two begin legs, base64url-decode each into an
// ArrayBuffer, and hand the result to navigator.credentials. They also distinguish a
// refusal from options by testing for a "status" key. That is a wire contract with a
// client we do not compile, so it is asserted here rather than assumed.
func TestPasskeyOptionsMatchTheBrowserContract(t *testing.T) {
	app, _, cookie := passkeyServer(t)

	// Enrollment options: challenge + user handle, and the relying party the
	// browser will check its own origin against.
	req := formReqNoBody("GET", PathWebauthnRegisterBegin)
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if _, ok := decodeAny(t, body)["status"]; ok {
		t.Fatalf("enrollment options carry a status key, which the browser reads as a refusal: %s", body)
	}
	var reg struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode enrollment options: %v (%s)", err, body)
	}
	mustDecode(t, "enrollment challenge", reg.PublicKey.Challenge)
	mustDecode(t, "user handle", reg.PublicKey.User.ID)
	if reg.PublicKey.RP.ID != testRPID {
		t.Errorf("enrollment rp.id = %q, want %q", reg.PublicKey.RP.ID, testRPID)
	}

	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	// Sign-in options: the page iterates allowCredentials unconditionally, so an
	// absent or empty list is a crash in the browser rather than a refusal.
	_, body = do(t, app, formReqNoBody("GET", PathWebauthnLoginBegin+"?owner=hanzo&name=alice"))
	var login struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
			Allowed   []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatalf("decode sign-in options: %v (%s)", err, body)
	}
	mustDecode(t, "sign-in challenge", login.PublicKey.Challenge)
	if login.PublicKey.RPID != testRPID {
		t.Errorf("sign-in rpId = %q, want %q", login.PublicKey.RPID, testRPID)
	}
	if len(login.PublicKey.Allowed) != 1 {
		t.Fatalf("allowCredentials has %d entries, want 1 — the page iterates this list "+
			"unconditionally", len(login.PublicKey.Allowed))
	}
	if got := mustDecode(t, "allowed credential id", login.PublicKey.Allowed[0].ID); !bytes.Equal(got, a.id) {
		t.Errorf("allowCredentials[0].id is not the enrolled credential")
	}
	if login.PublicKey.Allowed[0].Type != "public-key" {
		t.Errorf("allowCredentials[0].type = %q, want public-key", login.PublicKey.Allowed[0].Type)
	}

	// A refusal, by contrast, MUST carry status — it is the only thing separating
	// the two answers for the page.
	_, body = do(t, app, formReqNoBody("GET", PathWebauthnLoginBegin+"?owner=hanzo&name=nobody"))
	if decodeAny(t, body)["status"] != "error" {
		t.Errorf("a refused sign-in did not answer status:error, so the page would "+
			"hand it to navigator.credentials as options: %s", body)
	}
}

// mustDecode reads one base64url field the way the browser does, and returns it.
func mustDecode(t *testing.T, what, value string) []byte {
	t.Helper()
	if value == "" {
		t.Fatalf("%s is empty", what)
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%s is not base64url (%q): %v", what, value, err)
	}
	return b
}

func decodeAny(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return m
}

// The verification check does not depend on the challenge round-trip.
//
// The library derives its own UV check from session.UserVerification, and that value
// is carried on the challenge row as JSON. This reproduces the failure that would
// silently turn the check off — the requirement missing from the stored session —
// and demands the assertion still be refused. It is the ONLY test here that the
// library's own check cannot pass on our behalf, so it is what makes the direct read
// of the signed flag load-bearing rather than decorative.
func TestPasskeyVerificationSurvivesALostRequirement(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	forgetVerification(t, db, held)

	env := finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signUnverified, 1))
	if env["status"] == "ok" {
		t.Fatal("with the requirement lost from the stored session, an unverified " +
			"assertion signed somebody in: verification rides on the round trip alone")
	}

	// And the ceremony is otherwise intact — a VERIFIED assertion against the same
	// stripped session still signs in, so the refusal above is the flag being read
	// and not the tampering breaking the challenge.
	challenge, held = begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	forgetVerification(t, db, held)
	env = finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signPresent, 2))
	if env["status"] != "ok" {
		t.Fatalf("a verified assertion was refused for an unrelated reason: %v", env["msg"])
	}
}

// forgetVerification strips the user-verification requirement from the stored
// ceremony, leaving everything else about it intact.
func forgetVerification(t *testing.T, db orm.DB, held string) {
	t.Helper()
	id := strings.TrimPrefix(held, challengeCookie+"=")
	row, err := orm.Get[schema.LoginChallenge](db, challengeOwner+"/"+id)
	if err != nil {
		t.Fatalf("load challenge %q: %v", id, err)
	}
	var s wan.SessionData
	if err := json.Unmarshal([]byte(row.Payload), &s); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if s.UserVerification != protocol.VerificationRequired {
		t.Fatalf("the ceremony did not require verification to begin with (%q)", s.UserVerification)
	}
	s.UserVerification = ""
	payload, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	row.Payload = string(payload)
	if err := row.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("store stripped session: %v", err)
	}
}

// The same rule at enrollment: a passkey that was not released by a fingerprint,
// face or PIN is refused rather than stored, so nobody registers a credential that
// would fail every time they tried to use it.
func TestPasskeyUnverifiedEnrollmentIsRefused(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)

	env := enroll(t, app, cookie, a, attested&^flagUV)
	if env["status"] == "ok" {
		t.Fatal("a passkey attested without user verification was accepted")
	}
	if _, err := orm.Get[schema.WebauthnCredential](db, "hanzo/"+schema.CredentialName(a.id)); err == nil {
		t.Fatal("the refused passkey was stored anyway")
	}
}

// A passkey is bound to one relying party. An assertion signed for a DIFFERENT one
// — what a phishing page at another domain collects — does not verify here, which is
// the property that makes passkeys unphishable.
func TestPasskeyForAnotherRelyingPartyIsRefused(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	challenge, held := begin(t, app, PathWebauthnLoginBegin+"?owner=hanzo&name=alice", "")
	// The ONLY difference from the passing sign-in is the relying party the
	// authenticator hashed into what it signed.
	env := finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), "evil.example", signPresent, 1))
	if env["status"] == "ok" {
		t.Fatal("an assertion signed for another relying party signed somebody in")
	}
}

// The two ceremonies prove different things, so their challenges are not
// interchangeable. A challenge minted to ENROLL a passkey, answered as a SIGN-IN,
// would be a sign-in nobody authenticated.
func TestPasskeyRegistrationChallengeCannotSignIn(t *testing.T) {
	app, db, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	challenge, held := begin(t, app, PathWebauthnRegisterBegin, cookie)
	env := finish(t, app, PathWebauthnLoginFinish, held,
		a.sign(t, challenge, handleFor(t, db, "hanzo", "alice"), testRPID, signPresent, 1))
	if env["status"] == "ok" {
		t.Fatal("an enrollment challenge was spent as a sign-in")
	}
}

// Enrollment is not something a passer-by can start for somebody else: the account a
// passkey lands on is the caller's own, read from their session and never from the
// request.
func TestPasskeyEnrollmentNeedsACaller(t *testing.T) {
	app, _, _ := passkeyServer(t)
	resp, body := do(t, app, formReqNoBody("GET", PathWebauthnRegisterBegin))
	if resp.StatusCode == http.StatusNotFound {
		t.Fatal("the enrollment endpoint is not registered")
	}
	if env := decode(t, body); env["status"] == "ok" {
		t.Fatal("an anonymous caller was handed an enrollment challenge")
	}
}

// seedUserNamed adds a second account in the same organization, with the same
// password sessionCookieForNamed signs in with.
func seedUserNamed(t *testing.T, db orm.DB, name string) {
	t.Helper()
	alice, err := orm.Get[schema.User](db, "hanzo/alice")
	if err != nil {
		t.Fatalf("load the seeded user: %v", err)
	}
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = name
	u.Email = name + "@hanzo.ai"
	u.EmailVerified = true
	u.DisplayName = name
	u.PasswordHash = alice.PasswordHash
	u.PasswordType = alice.PasswordType
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// sessionCookieForNamed is sessionCookieFor for an account other than alice.
func sessionCookieForNamed(t *testing.T, app *zip.App, name string) string {
	t.Helper()
	resp, body := do(t, app, formReq("POST", PathLogin, map[string][]string{
		"organization": {"hanzo"}, "application": {"conf"},
		"username": {name}, "password": {"pw"}, "type": {"login"},
	}))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("login as %s failed: %s", name, body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}

// Signup never asks for a username, so the identifier a customer HAS is their
// email. A name-only lookup answers "no passkey is registered" for an account
// that has one — and that is the same refusal a real missing passkey gives, so
// the endpoint reports nothing an operator could act on. This endpoint resolves the
// way every other one does.
func TestPasskeySigninResolvesTheIdentifierACustomerHas(t *testing.T) {
	app, _, cookie := passkeyServer(t)
	a := newAuthenticator(t)
	if env := enroll(t, app, cookie, a, attested); env["status"] != "ok" {
		t.Fatalf("enrollment refused: %v", env["msg"])
	}

	for _, id := range []string{"alice", "alice@hanzo.ai"} {
		req, _ := http.NewRequest("GET", PathWebauthnLoginBegin+"?owner=hanzo&name="+id, nil)
		resp, body := do(t, app, req)
		if resp.StatusCode != 200 {
			t.Fatalf("%q did not reach the enrolled passkey (status=%d); body=%s", id, resp.StatusCode, body)
		}
		if strings.Contains(string(body), errNoPasskey) {
			t.Fatalf("%q was told no passkey is registered, but one is: %s", id, body)
		}
	}
}
