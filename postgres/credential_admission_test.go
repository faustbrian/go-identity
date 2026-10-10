package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestCredentialAdmissionRejectsUnownedScopeBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	newWork := func() Work {
		return Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
	}
	valid := CredentialAdmission{Credential: identity.CredentialRef{ID: "credential-sensitive", TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}
	for _, c := range []CredentialAdmission{{}, func() CredentialAdmission { c := valid; c.Credential.TenantID = "foreign"; return c }(), func() CredentialAdmission { c := valid; c.UserAuthorityVersion = 0; return c }()} {
		w := newWork()
		if now, err := w.RequireActiveCredential(context.Background(), native, c); err == nil || !now.IsZero() || w.state.sqlStarted {
			t.Fatal("malformed scope reached SQL")
		}
	}
	for _, p := range []FeatureExecutionContributor{nil, foreign} {
		w := newWork()
		if now, err := w.RequireActiveCredential(context.Background(), p, valid); err == nil || !now.IsZero() || w.state.sqlStarted {
			t.Fatal("unowned participant reached SQL")
		}
	}
	if now, err := (Work{}).RequireActiveCredential(context.Background(), native, valid); err == nil || !now.IsZero() {
		t.Fatal("zero Work admitted")
	}
	if bytes, err := json.Marshal(valid); err == nil || len(bytes) != 0 {
		t.Fatal("correlated admission serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", valid), "credential-sensitive") {
		t.Fatal("correlated admission formatted")
	}
}

func TestRecipientCredentialRejectsMismatchedOriginalBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	q := RecipientQuery{TenantID: "tenant", Kind: identity.IdentifierEmail, CanonicalValue: "Canonical@example.test", Eligibility: RecipientVerified}
	recipient, err := decodeRecipient(q, recipientRowFixture(), "19", "23")
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.TenantID, spec.Binding.UserID, spec.Binding.AnonymousFlowID = "tenant", "", "original-flow"
	valid := CredentialAdmission{Credential: identity.CredentialRef{ID: "ref", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 19, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 23}
	newWork := func() Work {
		return Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
	}
	for _, mode := range []string{"zero-recipient", "foreign-query", "known-query", "foreign-user", "foreign-tenant", "user-epoch", "identifier-epoch", "credential-epoch", "zero-credential", "suppressed", "nil-context", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			w, r, c, ctx, p := newWork(), recipient, valid, context.Background(), FeatureExecutionContributor(native)
			switch mode {
			case "zero-recipient":
				r = RecipientRecord{}
			case "foreign-query":
				r.Query.TenantID = "other"
			case "known-query":
				r.Query.UserID = "user"
			case "foreign-user":
				c.Credential.UserID = "other"
			case "foreign-tenant":
				c.Credential.TenantID = "other"
			case "user-epoch":
				c.UserAuthorityVersion++
			case "identifier-epoch":
				c.IdentifierAuthorityVersion++
			case "credential-epoch":
				c.CredentialAuthorityVersion++
			case "zero-credential":
				c = CredentialAdmission{}
			case "suppressed":
				r = RecipientRecord{Query: q, Suppressed: true}
			case "nil-context":
				ctx = nil
			case "foreign-owner":
				p = foreign
			}
			reader, ok := any(w).(interface {
				RequireRecipientCredential(context.Context, FeatureExecutionContributor, RecipientRecord, CredentialAdmission) (time.Time, error)
			})
			if !ok {
				t.Fatal("selected-recipient credential fence missing")
			}
			if now, err := reader.RequireRecipientCredential(ctx, p, r, c); err == nil || !now.IsZero() || w.state.sqlStarted {
				t.Fatal("mismatched original reached SQL")
			}
			if w.state.binding != spec.Binding {
				t.Fatal("selected credential rewrote original scope")
			}
			if w.state.failed == nil {
				t.Fatal("ignored admission denial left Work usable")
			}
		})
	}
}
