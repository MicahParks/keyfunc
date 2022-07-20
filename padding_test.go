package keyfunc_test

import (
	"testing"

	"github.com/MicahParks/keyfunc"
)

const (
	// jwksWithPadding has trailing = for base64url padding, which is non-RFC compliant padding, but still supported.
	jwksWithPadding = `{"keys":[{"kty":"RSA","use":"sig","kid":"hw1T/zfqTKIT2DYbY1vweU1sLxT4SmhsgkCsHq00Ix8=","n":"0P9Deg7S0HYuM7QdDOVpXycDErBfpPqxtxKURsNCyrtlopsbW3V-kXdQSj3_QXNaaJh9hTT9l46sl6e1x713ZMcBQI1-3xjfqSPK7POu21KIQG76eSt1A4xfOU7Wj_tfhaYuu_Axwr8RcmHCxNm0umqEIMjoyd1o30xBYkpeSCiaNnqpAldyzVVFox5WAkUaQo0GFmuf9RKddprIwtDSq4DpmlPV41Qe6NUBnQ5mZnWFsJohzpnI1YacpUUfdA7ZWbnEhg5ZKlb9hl80yPKQUBjVoeMZUuB1BDOyP-HBAQgmtCrCfsm26JX2bZtagl3xdy9yQNuIK9Ly75iSXIIrFw==","e":"AQAB","alg":"RS256"}]}`
)

// TestNonRFCPadding confirms that a JWKS with keys that contain padding at the end values for base64url encoded public
// keys. Having this trailing padding is not RFC compliant, but supported anyway.
func TestNonRFCPadding(t *testing.T) {
	jwks, err := keyfunc.NewJSON([]byte(jwksWithPadding))
	if err != nil {
		t.Fatalf(logFmt, "Failed to parse the JWKS with padding.", err)
	}

	// Confirm all the keys in the JWKS were parsed.
	if len(jwks.KIDs()) != 1 {
		t.Fatalf("Not all keys with padding were parsed.\n  Expected: %d\n  Actual: %d", 1, len(jwks.KIDs()))
	}
}
