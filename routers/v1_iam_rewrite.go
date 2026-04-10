package routers

import (
	"strings"

	"github.com/beego/beego/v2/server/web/context"
)

// V1IAMRewriteFilter rewrites /v1/iam/* requests to /api/* so the
// canonical /<version>/<service>/<path> pattern works without
// duplicating every route in router.go.
//
// Example: /v1/iam/get-organizations → /api/get-organizations
func V1IAMRewriteFilter(ctx *context.Context) {
	path := ctx.Request.URL.Path
	if strings.HasPrefix(path, "/v1/iam/") {
		newPath := "/api/" + strings.TrimPrefix(path, "/v1/iam/")
		ctx.Request.URL.Path = newPath
		ctx.Request.RequestURI = newPath
		if ctx.Request.URL.RawQuery != "" {
			ctx.Request.RequestURI = newPath + "?" + ctx.Request.URL.RawQuery
		}
	}
}
