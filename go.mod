module github.com/hanzoai/iam

go 1.26.4

// Hanzo IAM stack (MIGRATION.md §2) — no base, no consensus engine:
//   - github.com/zap-proto/zip — typed HTTP handlers on the zap-proto/fiber v3 engine
//   - github.com/hanzoai/orm   — typed Go records over SQLite / hanzoai/sql / hanzoai/datastore
require (
	github.com/hanzoai/orm v0.6.16
	github.com/spf13/cobra v1.10.2
	github.com/zap-proto/zip v1.10.2
	golang.org/x/crypto v0.53.0
)

// Migration-only: linked solely in `go build -tags migration` so `iam compare`
// can read the v1 Casdoor Postgres/MySQL database. The default (serving) build
// never links these — it is SQLite/ZAP-only, no external SQL driver.
require (
	github.com/go-sql-driver/mysql v1.9.3
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/alexedwards/argon2id v1.0.0
	github.com/goccy/go-yaml v1.19.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/hanzoai/sqlcipher v0.1.0
	github.com/hanzoai/sqlite v0.3.2
	github.com/luxfi/crypto v1.20.1
	github.com/luxwallet/connect/go v0.1.4
	github.com/pquerna/otp v1.5.0
	github.com/valyala/fasthttp v1.72.0
	github.com/zap-proto/fiber/v3 v3.2.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/dop251/goja v0.0.0-20260607120635-348e6bea910d // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/evanw/esbuild v0.28.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/pprof v0.0.0-20250317173921-a4b03ec1a45e // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/hanzoai/builder v0.3.13 // indirect
	github.com/hanzoai/csqlite v0.1.0 // indirect
	github.com/hanzoai/dbx v1.17.2 // indirect
	github.com/hanzoai/xorm v1.4.4 // indirect
	github.com/hanzokv/go/v9 v9.22.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/codec v1.1.4 // indirect
	github.com/luxfi/container v0.0.4 // indirect
	github.com/luxfi/ids v1.2.10 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/metric v1.5.7 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oasisprotocol/curve25519-voi v0.0.0-20251114093237-2ab5a27a1729 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220614013038-64ee5596c38a // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/zap-proto/go v1.3.0 // indirect
	github.com/zap-proto/http v0.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)
