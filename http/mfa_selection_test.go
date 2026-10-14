package identityhttp_test

import (
	identityhttp "github.com/faustbrian/go-identity/http"
	"net/http"
	"testing"
	"time"
)

func TestMFAVerifyConditionalStoredSessionPolicyIsNarrow(t *testing.T) {
	for _, mode := range []identityhttp.CSRFMode{identityhttp.CSRFSessionState, identityhttp.CSRFVariantOriginSessionState} {
		policy := identityhttp.CSRFPolicy{Mode: mode, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
		c := identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: policy, MaximumSerializedBytes: 16384}
		if _, err := identityhttp.NewCanonicalOperation(c); err != nil {
			t.Fatal("owned confirmation profile denied", err)
		}
		for _, change := range []func(*identityhttp.CanonicalOperationConfig){func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.TokenMaximumAge = time.Minute }, func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.TokenHeader = "Other-Token" }, func(c *identityhttp.CanonicalOperationConfig) {
			c.CSRF.RefererFallback = identityhttp.RefererFallbackSameOriginHTTPS
		}, func(c *identityhttp.CanonicalOperationConfig) { c.OperationID = "identity.admin.mfa-reset" }} {
			bad := c
			change(&bad)
			if _, err := identityhttp.NewCanonicalOperation(bad); err == nil {
				t.Fatal("variant policy broadened unsupported ownership")
			}
		}
	}
}

// Selection validates the owned policy boundary, not authentication. Runtime
// original-session/CSRF enforcement is exercised by the optional MFA handler.
func TestMFAEnrollmentStoredCSRFProfileIsNarrow(t *testing.T) {
	valid := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}
	c := identityhttp.CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.enable", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: valid, MaximumSerializedBytes: 32768}
	if _, err := identityhttp.NewCanonicalOperation(c); err != nil {
		t.Fatal("owned stored-session enrollment profile denied", err)
	}
	for _, policy := range []identityhttp.CSRFPolicy{
		{Mode: identityhttp.CSRFNone},
		{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "Other-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny},
	} {
		bad := c
		bad.CSRF = policy
		if _, err := identityhttp.NewCanonicalOperation(bad); err == nil {
			t.Fatal("weaker or independently aged enrollment profile admitted")
		}
	}
	uri := c
	uri.OperationID = "identity.mfa.totp-uri"
	if _, err := identityhttp.NewCanonicalOperation(uri); err != nil {
		t.Fatal("owned stored-session URI profile denied", err)
	}
	regeneration := c
	regeneration.OperationID = "identity.mfa.recovery-regenerate"
	if _, err := identityhttp.NewCanonicalOperation(regeneration); err != nil {
		t.Fatal("owned stored-session replacement profile denied", err)
	}
	disable := c
	disable.OperationID = "identity.mfa.disable"
	if _, err := identityhttp.NewCanonicalOperation(disable); err != nil {
		t.Fatal("explicit disable stored-session CSRF denied", err)
	}
	for _, id := range []string{"identity.admin.mfa-reset"} {
		bad := c
		bad.OperationID = id
		if _, err := identityhttp.NewCanonicalOperation(bad); err == nil {
			t.Fatal("enrollment extension broadened unrelated operation", id)
		}
	}
}
