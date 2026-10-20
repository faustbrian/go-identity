//go:build integration

package passwordpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/password"
	database "github.com/faustbrian/go-postgres"
)

// The parent calls this from the actual native request fixture, before and
// after successful protected consumption. No domain stores or fake issuance
// are introduced. The direct fixture SQL is an independent read-only oracle
// for the actual SMS interval, not a production metadata lookup or permission.
func testPhoneResetCompletionRateSource(t *testing.T, ctx context.Context, pool *database.Pool, fresh func() *PhonePasswordResetRequestService, proof capability.Proof, flow otp.SendFlow, caller authorization.DecisionContext, origin password.ResetGrantSpec) {
	t.Helper()
	owner, ok := any(fresh()).(phoneResetCompletionRateSource)
	if !ok {
		t.Fatal("actual phone reset lacks original-custody rate source")
	}
	var issued, expires time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT issued_at,expires_at FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND issue_command_purpose='identity.phone.password-reset-request'`, string(origin.TenantID), origin.Phone.OTPChallengeID).Scan(&issued, &expires); err != nil {
		t.Fatal("actual SMS interval oracle unavailable", err)
	}
	user, credential, challenge, lifetime, err := owner.PasswordResetCompletionRateSource(ctx, proof, flow, caller)
	if err != nil || user != origin.UserID || credential != origin.CredentialID || challenge != origin.Phone.OTPChallengeID || lifetime != expires.Sub(issued) || lifetime <= 0 {
		t.Fatal("rate source lost original durable SMS scope/interval", err)
	}
	if proof.ValidateBounds(32, 4096) != nil {
		t.Fatal("rate lookup consumed borrowed canonical proof")
	}
	for name, change := range map[string]func(*phoneResetRequestService){
		"number-profile":         func(n *phoneResetRequestService) { n.c.NumberBindingKeyVersion++ },
		"original-input-profile": func(n *phoneResetRequestService) { n.profile[0] ^= 1 },
		"original-directory": func(n *phoneResetRequestService) {
			source := *n.source
			source.global = "foreign"
			n.source = &source
		},
		"original-authorization": func(n *phoneResetRequestService) {
			source := *n.source
			source.namespace = "foreign"
			n.source = &source
		},
	} {
		t.Run(name, func(t *testing.T) {
			native := *fresh().read()
			change(&native)
			foreign := &PhonePasswordResetRequestService{read: func() *phoneResetRequestService { return &native }}
			u, c, id, ttl, e := foreign.PasswordResetCompletionRateSource(ctx, proof, flow, caller)
			if e == nil || u != "" || c != "" || id != "" || ttl != 0 {
				t.Fatal("foreign configured original source exposed rate metadata")
			}
		})
	}
	for name, change := range map[string]func(*authorization.DecisionContext){
		"tenant":   func(c *authorization.DecisionContext) { c.Request.Tenant = "foreign" },
		"action":   func(c *authorization.DecisionContext) { c.Request.Action = "identity.phone.password-reset-request" },
		"revision": func(c *authorization.DecisionContext) { c.PolicyRevision++ },
		"target": func(c *authorization.DecisionContext) {
			c.Request.Resource.ID = authorization.ResourceID(origin.UserID)
		},
		"foreign-target": func(c *authorization.DecisionContext) { c.Request.Resource.ID = "foreign" },
		"resource":       func(c *authorization.DecisionContext) { c.Request.Resource.Type = "identity.credential" },
		"actor-kind":     func(c *authorization.DecisionContext) { c.Request.Subject.Kind = authorization.SubjectUser },
	} {
		t.Run(name, func(t *testing.T) {
			changed := caller.Clone()
			change(&changed)
			u, c, id, ttl, e := owner.PasswordResetCompletionRateSource(ctx, proof, flow, changed)
			if e == nil || u != "" || c != "" || id != "" || ttl != 0 {
				t.Fatal("foreign rate-source caller exposed historical scope")
			}
		})
	}
	_, id, _, err := flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(id), auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []otp.SendFlow{{}, foreign} {
		u, c, id, ttl, e := owner.PasswordResetCompletionRateSource(ctx, proof, bad, caller)
		if e == nil || u != "" || c != "" || id != "" || ttl != 0 {
			t.Fatal("rate lookup accepted another original browser")
		}
	}
	u, c, id, ttl, e := owner.PasswordResetCompletionRateSource(ctx, capability.Proof{}, flow, caller)
	if e == nil || u != "" || c != "" || id != "" || ttl != 0 {
		t.Fatal("absent canonical proof disclosed rate metadata")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	u, c, id, ttl, e = owner.PasswordResetCompletionRateSource(canceled, proof, flow, caller)
	if !errors.Is(e, context.Canceled) || u != "" || c != "" || id != "" || ttl != 0 {
		t.Fatal("rate lookup lost cancellation or exposed partial metadata", e)
	}
}
