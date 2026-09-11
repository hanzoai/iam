package authz

import (
	"context"

	"github.com/zap-proto/zip"
)

// refused asks the one question these tests ask of the seam: was this call let
// through. It exists because the seam's answer is now a [zip.Decision] and an
// error — a refusal is a Deny carrying the clause that made it, while the error
// lane is for a check that could not be made at all — and a test that read only
// one of the two would report a refusal as an admission.
func refused(ctx context.Context, op zip.Op, in any) bool {
	d, err := Authorize(ctx, op, in)
	return err != nil || d.Effect == zip.Deny
}
