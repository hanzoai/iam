// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package cred is the ONE home for credential digests: how a secret is stored,
// and how a presented secret is checked against a stored one.
//
// The digest scheme is a property of the STORED ROW, never a constant. Live v1
// rows carry argon2id (the platform default, and the scheme every
// service-account secret was minted under); rows written by iam2's own user
// create/update carry bcrypt; the scheme's name travels with the row
// (schema.User.PasswordType, falling back to its organization's PasswordType —
// v1 object/check.go:244-249). Verify dispatches on that name, so an imported row
// verifies under the scheme it was actually written with. Hard-coding one
// algorithm silently locks out every account minted under another — the whole
// point of this package (MIGRATION.md, the argon2id blocker).
//
// Verify NEVER re-hashes. An upgrade-on-login is a deliberate write on the write
// path, not a side effect of a read.
package cred

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// The digest schemes a stored row can name. Argon2id is the platform default —
// what Hash writes and what every live v1 row carries.
const (
	Argon2id = "argon2id"
	Bcrypt   = "bcrypt"
)

// argon2id parameters, matching the live v1 mint (github.com/alexedwards/argon2id
// DefaultParams, used by object/service_account.go MintServiceAccountKey). They
// govern only what a NEW digest is written with: every stored PHC string carries
// the parameters it was created under, and Verify reads them from the hash, so a
// row minted under different parameters still verifies.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonSaltLen = 16
	argonKeyLen  = 32
	argonVersion = argon2.Version // 19
)

// errFormat is the single opaque parse failure. A caller only ever learns
// "this did not verify", never which part of a stored digest was malformed.
var errFormat = errors.New("cred: hash is not in the expected format")

// Hash derives the platform-default digest — argon2id, encoded as the standard
// PHC string `$argon2id$v=19$m=...,t=...,p=...$<salt>$<key>` that the Argon2
// reference implementation and every live v1 row use. The salt is fresh random
// per call, so two identical secrets never share a digest.
func Hash(secret string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether presented matches the stored digest under the scheme
// `kind` — the scheme the ROW says it was written with. An empty kind means the
// row never recorded one, which in v1 inherits the organization default and
// finally the platform default (argon2id): resolve that at the caller, which is
// the only layer holding the org, and pass the resolved name here.
//
// Fail-closed on every axis: an unknown scheme, an empty digest, an empty
// presented secret, or a malformed stored digest all report false. Both schemes
// compare in constant time (bcrypt inherently; argon2id via subtle).
func Verify(kind, stored, presented string) bool {
	if stored == "" || presented == "" {
		return false
	}
	switch kind {
	case Argon2id:
		return verifyArgon2id(stored, presented)
	case Bcrypt:
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(presented)) == nil
	}
	return false
}

// verifyArgon2id recomputes the key from the presented secret under the
// parameters and salt the stored PHC string carries, and compares the two keys
// in constant time.
func verifyArgon2id(stored, presented string) bool {
	time, memory, threads, salt, key, err := decode(stored)
	if err != nil {
		return false
	}
	other := argon2.IDKey([]byte(presented), salt, time, memory, threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(key, other) == 1
}

// decode parses a PHC argon2id string into the parameters, salt, and key it
// carries. It accepts exactly what the Argon2 reference format (and every live
// v1 row) emits, and refuses another variant or version rather than guessing.
func decode(hash string) (time, memory uint32, threads uint8, salt, key []byte, err error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != Argon2id {
		return 0, 0, 0, nil, nil, errFormat
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argonVersion {
		return 0, 0, 0, nil, nil, errFormat
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return 0, 0, 0, nil, nil, errFormat
	}
	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, errFormat
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, errFormat
	}
	if len(salt) == 0 || len(key) == 0 {
		return 0, 0, 0, nil, nil, errFormat
	}
	return time, memory, threads, salt, key, nil
}
