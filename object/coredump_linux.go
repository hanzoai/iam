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

//go:build linux

package object

import "golang.org/x/sys/unix"

// init disables core dumps (RLIMIT_CORE = 0) for any process that links this
// package — iamd, iam, pg2sqlite. The master key, derived KEKs and unwrapped
// DEKs transit process memory; a core dump would write them to disk in the
// clear. Best-effort: a failure to set the limit must not stop the daemon
// (containers usually disable cores anyway), so the error is intentionally
// ignored. Linux-only — the production image is alpine/Linux.
func init() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
