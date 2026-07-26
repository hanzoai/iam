// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/iam/internal/bootstrap"
)

// DELIVERY — the transport half of the code sign-in method, and the ONE thing
// that decides whether that method exists at all. codeDelivery returns the
// courier or the reason there is none; authMethods advertises on it and
// sendVerificationCode sends through it, so the login button and the endpoint
// light up and go dark together. Nothing else in iam2 may decide this.
//
// The peer is the notify rail folded into the hanzoai/cloud binary
// (cloud/clients/notify, HIP-0106) — "the native replacement for the standalone
// notifyd Deployment". It is already deployed and answering: GET
// /v1/notify/health returns {"service":"notify","status":"ok"} on the live
// cluster today. It owns the Twilio/Plivo credentials in KMS (org-scoped at
// orgs/<org>/notify/<service>/<key>), constructs the providers out of notifyd's
// own public packages, and is by its own doc the ONE platform sender. iam2 owns
// none of that and must not: an identity service that grows its own SMTP client
// grows a second place credentials live.
//
// Standing up the standalone notifyd Deployment would therefore be a REGRESSION,
// not the fix — a second sender, a second credential home, a second chance to
// diverge. There is one rail and this speaks to it.
//
// TWO deliberate choices:
//
//   - HTTP. cloud mounts /v1/notify/* on a zip app that listens on both ZAP
//     (:9653) and HTTP (:8000), so the same path is reachable either way — the
//     retired IAM_NOTIFY_ZAP_ADDR (cloud.hanzo.svc:9653) is the ZAP spelling of
//     this exact peer. HTTP is wired here because it is the leg that can be
//     verified from outside the mesh, and because the standalone notifyd's
//     internal/zaprpc is a STUB by its own doc comment (procedure constants, no
//     server) — so ZAP is not portable across both peers. Swapping transports is
//     this file and nothing else.
//   - The wire contract, not the module. github.com/hanzoai/notify carries 33
//     provider implementations and drags the AWS SDK, Firebase, discordgo and
//     mautrix behind it. Importing it to reach one POST would expand the identity
//     service's supply chain by an order of magnitude for no benefit. iam2 speaks
//     the documented JSON contract over sixty lines of net/http instead. The
//     shapes below are that contract, transcribed from cloud/clients/notify.
const (
	// notifyEndpointDefault is the in-cluster address of the cloud binary that
	// carries the notify rail (cloud.yaml: http listener on 8000). NOTIFY_ENDPOINT
	// overrides it the way IAM_ISSUER and KMS_ENDPOINT are overridden — it is
	// deployment configuration, not a toggle: there is no value of it that
	// turns the feature off while leaving it advertised, because reachability
	// is what codeDelivery reports.
	notifyEndpointDefault = "http://cloud.hanzo.svc.cluster.local:8000"

	// The notify rail's health and send paths.
	pathNotifyHealth = "/v1/notify/health"
	pathNotifySend   = "/v1/notify/send"

	// otpEvent tags the send in the notify rail's audit trail. cloud's fold
	// documents this exact identifier as IAM's contract, so the ledger keeps
	// showing OTP traffic under the name it has always had.
	otpEvent = "iam.otp_sent"

	// notifyHealthTTL bounds how stale a reachability answer may be. Every
	// login page load asks authMethods, so probing per request would put a
	// synchronous round trip in front of the login screen; caching for a few
	// seconds keeps the answer honest without that cost. A code sign-in
	// attempt is authoritative regardless — the send itself is the real test.
	notifyHealthTTL = 15 * time.Second

	// notifyProbeTimeout / notifySendTimeout bound the two calls. The probe is
	// short because a login page waits on it; the send is longer because
	// ?sync=true blocks on the upstream provider.
	notifyProbeTimeout = 2 * time.Second
	notifySendTimeout  = 20 * time.Second
)

// notifyClient is the outbound client for notify. It is deliberately NOT
// federationHTTPClient: that one refuses to dial a private or loopback address,
// which is exactly right for an admin-supplied IdP URL and exactly wrong here.
// notifyd is an in-cluster ClusterIP, so the SSRF dial guard would refuse every
// legitimate call. The guard is safe to omit because the target is not
// attacker-influenced: it comes from process configuration, never from a request.
// Redirects are still refused — a 3xx from an internal service is a fault, not a
// hop — and every response body is size-capped.
var notifyClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	},
}

// maxNotifyBodyBytes caps every notify response read. Send/health bodies are a
// few hundred bytes; a broken peer cannot exhaust memory.
const maxNotifyBodyBytes = 1 << 18 // 256 KiB

// courier carries a minted verification code to its destination. It holds the
// resolved endpoint and the service credential, so a caller that has one has
// everything needed to deliver — there is no second lookup between deciding
// delivery is possible and doing it.
type courier struct {
	base  string
	token string
}

// notifyHealth caches the last reachability answer, keyed by the endpoint it was
// taken against so a configuration change (or a test pointing at its own server)
// is never served a stale verdict.
var notifyHealth struct {
	mu       sync.Mutex
	endpoint string
	at       time.Time
	err      error
}

// codeDelivery returns the courier for verification codes, or the reason iam2
// cannot deliver one. It is the ONE authority on the code sign-in method:
// authMethods reports `code` only when this returns a courier, and
// sendVerificationCode refuses on the same call, so the method can never be
// advertised while it cannot be performed.
//
// Two things must hold. A service credential must be configured — notify's
// platform plugin derives the tenant from the caller's bearer, so an
// unauthenticated iam2 could not send for anyone. And notifyd must be answering
// its health endpoint. Both fail closed; neither is a switch anyone can flip to
// claim a capability that is absent.
func codeDelivery() (*courier, error) {
	token := bootstrap.ServiceToken()
	if token == "" {
		return nil, errors.New("verification-code delivery has no service credential configured")
	}
	base := notifyEndpoint()
	if err := notifyReachable(base); err != nil {
		return nil, err
	}
	return &courier{base: base, token: token}, nil
}

// notifyEndpoint resolves notifyd's base URL from configuration, defaulting to
// the in-cluster Service address.
func notifyEndpoint() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("NOTIFY_ENDPOINT")), "/"); v != "" {
		return v
	}
	return notifyEndpointDefault
}

// notifyReachable reports whether notifyd is answering, memoized for
// notifyHealthTTL against the endpoint probed. A failed probe is cached too —
// otherwise an unreachable notify would put a fresh timeout in front of every
// single login page load.
func notifyReachable(base string) error {
	notifyHealth.mu.Lock()
	defer notifyHealth.mu.Unlock()
	if notifyHealth.endpoint == base && nowFunc().Sub(notifyHealth.at) < notifyHealthTTL {
		return notifyHealth.err
	}
	err := probeNotify(base)
	notifyHealth.endpoint, notifyHealth.at, notifyHealth.err = base, nowFunc(), err
	return err
}

// probeNotify GETs notify's health endpoint under a short deadline. Any
// non-200, transport error, or timeout means "cannot deliver" — the caller
// withholds the method rather than guessing.
func probeNotify(base string) error {
	ctx, cancel := context.WithTimeout(context.Background(), notifyProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+pathNotifyHealth, nil)
	if err != nil {
		return errors.New("verification-code delivery endpoint is not a usable URL")
	}
	resp, err := notifyClient.Do(req)
	if err != nil {
		return errors.New("verification-code delivery is unavailable: notify is unreachable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNotifyBodyBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verification-code delivery is unavailable: notify health returned %d", resp.StatusCode)
	}
	return nil
}

// notifySendRequest is the POST /v1/notify/send body. It is the OTP contract
// cloud/clients/notify documents verbatim as IAM's — to, channel, event, and
// template_vars{otp,recipient,app} — so the rail renders the code with the same
// wording every other Hanzo OTP has used, and iam2 never ships message copy of
// its own that could drift from it.
type notifySendRequest struct {
	To             []string          `json:"to"`
	Channel        string            `json:"channel"`
	Event          string            `json:"event,omitempty"`
	TemplateVars   map[string]string `json:"template_vars,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

// notifySendResponse is the terminal shape ?sync=true returns.
type notifySendResponse struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// notifyChannel maps a verification type onto notify's channel vocabulary.
func notifyChannel(typ string) (string, error) {
	switch typ {
	case "email":
		return "email", nil
	case "phone":
		return "sms", nil
	default:
		return "", fmt.Errorf("no delivery channel for verification type %q", typ)
	}
}

// send delivers code to dest for org and returns only once the message has
// actually left — SYNCHRONOUSLY, by design. notify's default is async: it
// answers 202 {status:"queued"} and hands the work to a tasks worker. Accepting
// that here would recreate precisely the defect this change removes: iam2 would
// report success on a queue insertion and the user would wait for a code that a
// dead worker never sent. ?sync=true blocks on the provider's own answer, so a
// caller that sees nil knows the code went out.
//
// idempotency is the verification record's id, so a retried request reuses the
// same notify message instead of sending the user a second code.
func (d *courier) send(ctx context.Context, app, typ, dest, code, idempotency string) error {
	channel, err := notifyChannel(typ)
	if err != nil {
		return err
	}
	body, err := json.Marshal(notifySendRequest{
		To:      []string{dest},
		Channel: channel,
		Event:   otpEvent,
		// The variables the rail's OTP template renders, and nothing more. A
		// Message row is persisted per send, so anything added here is retained
		// downstream — an OTP is not the place for account detail.
		TemplateVars: map[string]string{
			"otp":       code,
			"recipient": dest,
			"app":       app,
		},
		IdempotencyKey: idempotency,
	})
	if err != nil {
		return errors.New("verification-code delivery could not encode the request")
	}

	ctx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+pathNotifySend+"?sync=true", bytes.NewReader(body))
	if err != nil {
		return errors.New("verification-code delivery endpoint is not a usable URL")
	}
	req.Header.Set("Content-Type", "application/json")
	// The credential is the whole tenancy story. The rail derives the sending
	// org from the VALIDATED principal behind this bearer and deliberately
	// ignores any client-supplied X-Org-Id — it moved to a publicly reachable
	// edge and hardened accordingly. So iam2 sends no org header: whichever org
	// this credential resolves to is the org the message and its KMS-held
	// provider credentials are scoped to, and that is the correct trust model.
	req.Header.Set("Authorization", "Bearer "+d.token)

	resp, err := notifyClient.Do(req)
	if err != nil {
		return errors.New("verification-code delivery failed: notify is unreachable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxNotifyBodyBytes))
	if err != nil {
		return errors.New("verification-code delivery failed: unreadable response")
	}
	if resp.StatusCode != http.StatusOK {
		// The upstream reason is deliberately NOT echoed to the caller: this
		// endpoint is public and a provider error can name the destination or
		// the account. It is a delivery failure, and that is all a client learns.
		return fmt.Errorf("verification-code delivery failed: notify returned %d", resp.StatusCode)
	}
	var out notifySendResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return errors.New("verification-code delivery failed: undecodable response")
	}
	// A sync send answers with the TERMINAL status. "sent" and "delivered" are
	// the two the rail reports as success; anything else — notably "queued",
	// which would mean the sync contract was not honored — is a failure, so
	// iam2 never persists a code it cannot vouch for.
	if out.Status != "sent" && out.Status != "delivered" {
		return fmt.Errorf("verification-code delivery failed: notify reported %q", out.Status)
	}
	return nil
}
