// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package httpx

// The caller's address, and the ONE rule IAM derives it by.
//
// An address is not a header. X-Forwarded-For is a list a client may write the
// first entries of and each hop appends to, so the LEFT-MOST entry is whatever
// the client typed — the one value in the chain that is always attacker
// controlled. Reading it as "the client" is how a sign-up flood from one host
// becomes a million distinct clients: it defeats per-address velocity, it writes
// a chosen address into a durable audit row, and it lets one caller poison
// another address's reputation while evading its own.
//
// THE RULE:
//
//	the socket peer is the truth. If the peer is not one of OUR proxies, it IS
//	the client — a TCP source address cannot be forged inside an established
//	connection.
//
//	only a trusted peer's chain is readable. When the peer IS one of ours, walk
//	X-Forwarded-For from the RIGHT — the end each hop appends to — and take the
//	first entry that is not itself one of ours. Everything to its left was
//	written before our infrastructure saw the request.
//
//	our own traffic has no client. A chain that is entirely our own addresses is
//	an in-cluster caller; it has no client address, and an empty address is
//	honest where a proxy's own address in a velocity counter is not.
//
// This is the same rule cloud applies (hanzoai/cloud clientip.go). Two services,
// one rule — stated twice because the two repos share no HTTP-boundary package
// today; the shared home for it is the zip framework, which owns the Ctx.

import (
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/zap-proto/zip"
)

// TrustedProxiesEnv names the operator knob: a comma-separated list of CIDRs and
// bare addresses that are OUR OWN forwarding hops. Set it when a deployment is
// fronted by a proxy on a PUBLIC address; the default below covers private space,
// which is every hop inside a cluster.
const TrustedProxiesEnv = "IAM_TRUSTED_PROXIES"

// defaultTrustedProxies is the address space our own hops live in when nobody
// says otherwise: loopback, the unspecified address (never a real peer), RFC1918
// private space, carrier-grade NAT, link-local, and IPv6 unique-local. A public
// address is NEVER trusted by default.
var defaultTrustedProxies = []string{
	"127.0.0.0/8", "::1/128",
	"0.0.0.0/32", "::/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16", "fe80::/10",
	"fc00::/7",
}

// maxForwardedHops bounds how much of a chain is read. Read from the right, so
// the bound only ever discards the least trustworthy end.
const maxForwardedHops = 32

var trustedProxies = sync.OnceValue(func() proxySet {
	if s := parseProxySet(os.Getenv(TrustedProxiesEnv)); len(s.nets) > 0 {
		return s
	}
	// An unset — or entirely unparseable — knob falls back to the defaults rather
	// than to an EMPTY set: trusting nothing would make the ingress itself the
	// "client", collapsing every caller into one address.
	return parseProxySet(strings.Join(defaultTrustedProxies, ","))
})

type proxySet struct{ nets []netip.Prefix }

func parseProxySet(spec string) proxySet {
	var s proxySet
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			s.nets = append(s.nets, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			s.nets = append(s.nets, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return s
}

func (s proxySet) has(a netip.Addr) bool {
	for _, n := range s.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP is the caller's own address: the socket peer for a direct caller, the
// right-most non-proxy entry of the forwarded chain for a proxied one, and "" for
// an in-cluster caller that never transited the edge.
//
// It reads EVERY X-Forwarded-For header line, not just the first: fasthttp keeps
// repeated headers apart, and a client that sends its own line before the proxy
// appends to a second would otherwise hide the real address behind its own.
func ClientIP(c *zip.Ctx) string {
	return clientAddr(c.Fiber().IP(), c.Fiber().Request().Header.PeekAll("X-Forwarded-For"), trustedProxies())
}

// clientAddr IS the rule, as a pure function of the three facts it turns on: the
// socket peer, the forwarded chain, and which addresses are ours.
func clientAddr(peerAddr string, forwarded [][]byte, tp proxySet) string {
	peer, ok := parseClientAddr(peerAddr)
	if !ok {
		return ""
	}
	if !tp.has(peer) {
		return peer.String()
	}
	seen := 0
	for i := len(forwarded) - 1; i >= 0; i-- {
		hops := strings.Split(string(forwarded[i]), ",")
		for j := len(hops) - 1; j >= 0; j-- {
			if seen++; seen > maxForwardedHops {
				return ""
			}
			a, ok := parseClientAddr(hops[j])
			if !ok || tp.has(a) {
				continue
			}
			return a.String()
		}
	}
	return ""
}

// parseClientAddr parses one entry into a canonical address, accepting a bare
// address or an address:port pair and UNMAPPING IPv4-in-IPv6 so one address is
// one key rather than two.
func parseClientAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}
