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

//go:build !unix

package object

import "sync"

// createLockFallback serializes create-lock holders within a single process on
// platforms without flock (e.g. Windows). IAM ships only on Linux containers
// (RWO PVC, single-writer), so cross-process locking is not a deployment target
// here; this keeps the build green and preserves in-process safety. The lockPath
// is ignored — the process-wide mutex is strictly stronger in-process than a
// per-path lock and the cross-process case does not exist on these platforms.
var createLockFallback sync.Mutex

// withExclusiveFileLock runs fn under a process-wide mutex. See filelock_unix.go
// for the real cross-process (flock) implementation used in production.
func withExclusiveFileLock(_ string, fn func() error) error {
	createLockFallback.Lock()
	defer createLockFallback.Unlock()
	return fn()
}
