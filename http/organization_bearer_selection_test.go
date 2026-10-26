package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// This is the constructor's closed policy-admission contract, not evidence of
// bearer authentication. The selected organization leaf must independently
// prove strict header acquisition and reject ambient-cookie fallback.
func TestCanonicalOrganizationSelectsOnlyExactBearerMutationPolicies(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	bearer := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
	for _, operation := range []string{"identity.organization.create", "identity.organization.update", "identity.organization.member.add", "identity.organization.member.update", "identity.organization.member.remove", "identity.organization.member.leave", "identity.organization.invitation-send", "identity.organization.invitation.accept", "identity.organization.invitation.resend", "identity.organization.invitation.cancel", "identity.organization.invitation.reject", "identity.organization.invitation.expire", "identity.organization.owner-transfer", "identity.organization.archive", "identity.organization.restore", "identity.organization.team.member-add", "identity.organization.team.member-remove", "identity.organization.team.create", "identity.organization.team.update", "identity.organization.team.delete"} {
		t.Run(operation, func(t *testing.T) {
			config := identityhttp.CanonicalOperationConfig{Owner: "organization", OperationID: operation, Handler: handler, CSRF: bearer, MaximumSerializedBytes: 16384}
			selected, err := identityhttp.NewCanonicalOperation(config)
			if err != nil || selected.Route.CSRF != bearer || selected.Record.CSRFOrigin != bearer {
				t.Fatal("exact bearer-only organization mutation rejected", err)
			}
			for _, change := range []func(*identityhttp.CSRFPolicy){
				func(p *identityhttp.CSRFPolicy) { p.TokenHeader = "X-CSRF-Token" },
				func(p *identityhttp.CSRFPolicy) { p.TokenMaximumAge = time.Minute },
				func(p *identityhttp.CSRFPolicy) { p.RefererFallback = identityhttp.RefererFallbackSameOriginHTTPS },
			} {
				invalid := config
				change(&invalid.CSRF)
				if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
					t.Fatal("mixed bearer/cookie CSRF policy admitted")
				}
			}
			// The original cookie-protected catalog profile remains explicit and
			// unchanged; choosing bearer does not relax the cookie profile.
			config.CSRF = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}
			original, err := identityhttp.NewCanonicalOperation(config)
			if err != nil || original.Route.CSRF.Mode == identityhttp.CSRFNone {
				t.Fatal("canonical cookie protection changed", err)
			}
			config.CSRF = identityhttp.CSRFPolicy{}
			if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
				t.Fatal("missing explicit security profile accepted")
			}
		})
	}
	for _, operation := range []string{"identity.organization.delete", "identity.organization.team.active-set", "identity.organization.role.update"} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "organization", OperationID: operation, Handler: handler, CSRF: bearer, MaximumSerializedBytes: 16384}); err == nil {
			t.Fatal("bearer exception leaked to unselected operation", operation)
		}
	}
}
