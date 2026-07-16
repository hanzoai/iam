// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package password

import "testing"

// The parameter choice in this package is a claim about latency and memory on a
// 2-CPU / 2 GiB pod. These benchmarks are that claim in executable form — run
// them with GOMAXPROCS=2 to mirror the iam pod:
//
//	GOMAXPROCS=2 go test ./internal/password/ -run XXX -bench . -benchmem
//
// Measured (GOMAXPROCS=2, 2026-07-16):
//
//	Hash (m=19456,t=2,p=1)            13.5 ms   19.9 MB/op
//	Verify live v1 (m=65536,t=1,p=2)  16.6 ms   67.1 MB/op
//	Verify bcrypt (cost 10)           39.3 ms    5.3 KB/op
//
// Two things follow. Argon2id at the OWASP baseline is ~3x FASTER than the
// bcrypt it replaces, so retiring bcrypt costs no login latency. And memory,
// not time, is the exposed axis: a live v1 row holds 67 MB per in-flight
// verify, so ~26 concurrent logins would reach this pod's 1750MiB GOMEMLIMIT.
// That is what `gate` bounds.

func BenchmarkHashPolicy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Hash(ctx(), "a representative password"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyLiveV1Params measures what the 85 live argon2id rows actually
// cost us on the login path — the parameters are theirs, not ours.
func BenchmarkVerifyLiveV1Params(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if ok, _ := Verify(ctx(), liveArgon2idDigest, liveArgon2idPassword); !ok {
			b.Fatal("did not verify")
		}
	}
}

// BenchmarkVerifyBcrypt10 measures the 40 live bcrypt rows, for comparison.
func BenchmarkVerifyBcrypt10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if ok, _ := Verify(ctx(), liveBcrypt10Digest, liveBcryptPassword); !ok {
			b.Fatal("did not verify")
		}
	}
}
