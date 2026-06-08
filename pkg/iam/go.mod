// Submodule for the in-process Embed + Mount entry points.
//
// Kept separate from the root iam module so consumers that only need
// the SDK don't transitively pull cloud and zip (which are still
// v0.0.0 + local replace). Consumers that want the embedded server
// (e.g. cmd/cloud) import this module explicitly via blank-import:
//
//	import _ "github.com/hanzoai/iam/pkg/iam"
//
// At standard tag-time the cmd/cloud go.mod adds the replace for
// hanzoai/cloud and hanzoai/zip until those publish stable tags.
module github.com/hanzoai/iam/pkg/iam

go 1.26.3

require (
	github.com/hanzoai/cloud v0.1.1
	github.com/hanzoai/zip v0.2.0
)

require (
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/gofiber/fiber/v3 v3.2.0 // indirect
	github.com/gofiber/schema v1.7.1 // indirect
	github.com/gofiber/utils/v2 v2.0.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/hanzoai/iam => ../..
