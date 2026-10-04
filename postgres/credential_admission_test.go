package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

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
