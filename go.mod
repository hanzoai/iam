module github.com/hanzoai/iam2

go 1.26.4

// Hanzo IAM v2 stack (MIGRATION.md §2) — no base, no consensus engine:
//   - github.com/zap-proto/zip — typed HTTP handlers on the zap-proto/fiber v3 engine
//   - github.com/hanzoai/orm   — typed Go records over SQLite / hanzoai/sql / hanzoai/datastore
require (
	github.com/hanzoai/orm v0.6.1
	github.com/spf13/cobra v1.10.2
	github.com/zap-proto/zip v1.8.3
	golang.org/x/crypto v0.52.0
)

// Migration-only: linked solely in `go build -tags migration` so `iam2 compare`
// can read the v1 Casdoor Postgres/MySQL database. The default (serving) build
// never links these — it is SQLite/ZAP-only, no external SQL driver.
require (
	github.com/go-sql-driver/mysql v1.9.3
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/go-webauthn/webauthn v0.10.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/luxfi/crypto v1.20.1
	github.com/pquerna/otp v1.5.0
	github.com/zap-proto/fiber/v3 v3.2.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/dop251/goja v0.0.0-20260607120635-348e6bea910d // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/evanw/esbuild v0.28.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/go-webauthn/x v0.1.9 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/pprof v0.0.0-20250317173921-a4b03ec1a45e // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hanzoai/dbx v1.16.0 // indirect
	github.com/hanzoai/kv-go/v9 v9.18.0 // indirect
	github.com/hanzoai/sqlite v0.2.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mattn/go-sqlite3 v1.14.47 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zap-proto/go v1.3.0 // indirect
	github.com/zap-proto/http v0.2.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.48.1 // indirect
)
