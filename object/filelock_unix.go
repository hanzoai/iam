// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build unix

package object

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// withExclusiveFileLock runs fn while holding an exclusive advisory lock
// (flock LOCK_EX) on lockPath, creating the lockfile if needed. The lock is a
// CROSS-PROCESS mutex: two IAM processes sharing the data directory (e.g. an
// accidental >1 replica on the RWO PVC, or a migration tool running beside the
// daemon) are serialized through it, so the "mint a fresh org DEK + create its
// db" critical section can never interleave and produce a mismatched .db/.dek
// pair (the V1 TOCTOU corruption).
//
// flock is per-open-file-description and released when the fd is closed, so a
// crashed holder's lock is reclaimed by the kernel — no stale lock survives a
// process death. The lock is advisory, which is sufficient here: every writer of
// these files is this same codebase and routes through this function.
//
// In-process callers are already serialized by OrgDBManager.mu; this guards the
// orthogonal cross-process case.
func withExclusiveFileLock(lockPath string, fn func() error) (err error) {
	// 0600: the lockfile lives in the 0700 data dir and holds no secrets, but
	// keep it owner-only for tidiness.
	f, openErr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if openErr != nil {
		return fmt.Errorf("open create-lock %q: %w", lockPath, openErr)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close create-lock %q: %w", lockPath, cerr)
		}
	}()

	if lerr := unix.Flock(int(f.Fd()), unix.LOCK_EX); lerr != nil {
		return fmt.Errorf("acquire create-lock %q: %w", lockPath, lerr)
	}
	// LOCK_UN before close is belt-and-suspenders; close releases it anyway.
	defer func() {
		if uerr := unix.Flock(int(f.Fd()), unix.LOCK_UN); uerr != nil && err == nil {
			err = fmt.Errorf("release create-lock %q: %w", lockPath, uerr)
		}
	}()

	return fn()
}
