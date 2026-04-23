package routers

import (
	"strings"

	"github.com/beego/beego/v2/server/web/context"
)

// V1IAMRewriteFilter rewrites /v1/iam/* requests to the underlying Casdoor
// route so the canonical /<version>/<service>/<path> pattern works without
// duplicating every route in router.go.
//
// Most API endpoints live under /api/*. A few intentionally live at root
// because standards expect them unprefixed. The filter maps:
//
//	/v1/iam/login/oauth/* → /login/oauth/*    (OAuth2 standard path)
//	/v1/iam/oauth/*       → /oauth/*          (OAuth2 + OIDC aliases)
//	/v1/iam/.well-known/* → /.well-known/*    (OIDC discovery + JWKS)
//	/v1/iam/X             → /api/X            (everything else)
func V1IAMRewriteFilter(ctx *context.Context) {
	path := ctx.Request.URL.Path
	if !strings.HasPrefix(path, "/v1/iam/") {
		return
	}
	rest := strings.TrimPrefix(path, "/v1/iam/")
	var newPath string
	switch {
	case strings.HasPrefix(rest, "login/oauth/"):
		newPath = "/" + rest
	case strings.HasPrefix(rest, "oauth/"):
		newPath = "/" + rest
	case strings.HasPrefix(rest, ".well-known/"):
		newPath = "/" + rest
	default:
		newPath = "/api/" + rest
	}
	ctx.Request.URL.Path = newPath
	ctx.Request.RequestURI = newPath
	if ctx.Request.URL.RawQuery != "" {
		ctx.Request.RequestURI = newPath + "?" + ctx.Request.URL.RawQuery
	}
}
