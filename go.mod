module github.com/hanzoai/iam

go 1.26.5

// This path carries two histories. Everything below v1.32.0 published the
// Casdoor-derived tree (Beego/xorm, controllers/); v1.32.0 and above publish
// this one (zip/orm, internal/). Same import path, no signal — which made
// `go get github.com/hanzoai/iam@v1.31.28` a lineage swap that still compiles.
//
// Those versions now live, byte-identical, at github.com/hanzoai/iam-v1.
// Deleting their tags here would not un-publish them: proxy.golang.org caches
// module versions immutably and already serves 506 of them. This retraction is
// therefore the only thing that reaches every resolver, proxied or direct.
retract [v1.0.0, v1.31.37] // Casdoor lineage; moved to github.com/hanzoai/iam-v1

// Hanzo IAM stack (MIGRATION.md §2) — no base, no consensus engine:
//   - github.com/zap-proto/zip — typed HTTP handlers on the zap-proto/fiber v3 engine
//   - github.com/hanzoai/orm   — typed Go records over SQLite / hanzoai/sql / hanzoai/datastore
require (
	github.com/hanzoai/orm v0.6.16
	github.com/spf13/cobra v1.10.2
	github.com/zap-proto/zip v1.31.4
	golang.org/x/crypto v0.54.0
)

// Migration-only: linked solely in `go build -tags migration` so `iam compare`
// can read the legacy v1 Postgres/MySQL database. The default (serving) build
// never links these — it is SQLite/ZAP-only, no external SQL driver.
require (
	github.com/go-sql-driver/mysql v1.9.3
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/alexedwards/argon2id v1.0.0
	github.com/go-webauthn/webauthn v0.17.4
	github.com/goccy/go-yaml v1.19.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.1-0.20241114170450-2d3c2a9cc518
	github.com/hanzoai/account v0.2.1
	github.com/luxfi/crypto v1.20.2
	github.com/luxwallet/connect/go v0.1.4
	github.com/pquerna/otp v1.5.0
	github.com/valyala/fasthttp v1.72.0
	github.com/zap-proto/fiber/v3 v3.2.1
)

require github.com/zap-proto/mcp v1.0.5 // indirect

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/hanzoai/authz v1.10.32
	github.com/hanzoai/builder v0.3.13 // indirect
	github.com/hanzoai/csqlite v0.1.0 // indirect
	github.com/hanzoai/dbx v1.17.2 // indirect
	github.com/hanzoai/sqlcipher v0.1.1 // indirect
	github.com/hanzoai/sqlite v0.5.0 // indirect
	github.com/hanzoai/xorm v1.4.4 // indirect
	github.com/hanzokv/go/v9 v9.22.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/cache v1.3.1 // indirect
	github.com/luxfi/container v0.2.1 // indirect
	github.com/luxfi/ids v1.3.2 // indirect
	github.com/luxfi/log v1.5.0 // indirect
	github.com/luxfi/math v1.5.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.1 // indirect
	github.com/luxfi/metric v1.10.0 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/zap v1.2.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oasisprotocol/curve25519-voi v0.0.0-20251114093237-2ab5a27a1729 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zap-proto/go v1.3.0 // indirect
	github.com/zap-proto/http v0.3.5 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.51.0 // indirect
)
