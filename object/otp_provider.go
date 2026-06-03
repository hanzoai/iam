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

package object

// IAM no longer ships in-process provider clients. The only OTP send
// path is notify_delivery.go → POST /v1/notify/send. The env-driven
// Twilio / SendGrid / SES / Plivo clients that used to live here were
// ripped in favor of one canonical fan-out point inside hanzoai/notify,
// where retry/fallback chains, per-tenant provider resolution, KMS
// credential loading, and metering all live in one place.
//
// Two symbols survive as no-ops for backwards source compatibility with
// the boot path and the sandbox-OTP read-side bypass:
//
//   - EnforceOTPProviderGuard — still called from iamserver.Init() at
//     boot. There is nothing to validate since IAM no longer reads
//     provider credentials from its own env; the function exists so the
//     boot ordering stays stable and an operator who still has
//     IAM_SMS_PROVIDER / IAM_EMAIL_PROVIDER in their manifest does not
//     panic IAM at startup. notify is the only provider knob now.
//
//   - SandboxOTPAllowed — read-side defence-in-depth for the
//     SANDBOX_GLOBAL_OTP pinned-code bypass at CheckVerificationCode.
//     Returns true unconditionally because all real sends are now
//     opaque to IAM (notify handles them) and the boot-time origin
//     guard (EnforceSandboxOriginGuard) is the only authoritative gate
//     for SANDBOX_GLOBAL_OTP. The boot guard panics if SANDBOX_GLOBAL_OTP
//     is set with a non-sandbox origin, which is the suspenders to the
//     belt this function would otherwise provide.

// EnforceOTPProviderGuard is a no-op. Kept so iamserver.Init() compiles
// unchanged after the env-direct provider paths were ripped.
func EnforceOTPProviderGuard() {}

// SandboxOTPAllowed always returns true. See file comment above for the
// rationale — the authoritative SANDBOX_GLOBAL_OTP gate is the origin
// guard at boot, not a read-side mode check.
func SandboxOTPAllowed() bool { return true }
