//go:build integration

package reference_test

import "testing"

// Reuse the real public registration, encrypted delivery and HTTPS owners, but
// select durable PostgreSQL admission rather than the legacy Valkey fixture.
// No account, original browser, link grant or session is seeded by these cases.
func TestReferencePostgresMagicLinkHTTPS(t *testing.T) {
	for _, profile := range []struct {
		name             string
		signup, existing bool
	}{
		{"signin-existing", false, true},
		{"signup-new", true, false},
		{"signup-existing", true, true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true}, false, true, false, false, profile.signup, profile.existing)
		})
	}
}

func TestReferencePostgresMagicLinkCommitRecoveryHTTPS(t *testing.T) {
	for _, signup := range []bool{false, true} {
		name := "signin-existing"
		if signup {
			name = "signup-new"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, completionCommitFault: true}, false, true, false, false, signup, false)
		})
	}
}
