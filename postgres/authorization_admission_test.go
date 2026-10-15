package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

func TestUserAuthorizationAdmissionRejectsAndPoisonsBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	newWork := func() Work {
		return Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
	}
	valid := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: authorization.TenantID(spec.Binding.TenantID), PolicyNamespace: "users-sensitive", SubjectID: authorization.SubjectID(spec.Binding.UserID)}, Version: 1}
	for _, change := range []func(*UserAuthorizationAdmission){
		func(a *UserAuthorizationAdmission) { a.Version = 0 },
		func(a *UserAuthorizationAdmission) { a.Scope.TenantID = "foreign" },
		func(a *UserAuthorizationAdmission) { a.Scope.SubjectID = "foreign" },
		func(a *UserAuthorizationAdmission) { a.Scope.PolicyNamespace = "" },
	} {
		w := newWork()
		expected := valid
		change(&expected)
		var invalid identity.InvalidInputError
		if err := w.RequireActiveUserAuthorization(context.Background(), native, expected); !errors.As(err, &invalid) || w.state.sqlStarted {
			t.Fatal("malformed scope reached SQL or wrong classification", err)
		}
		if _, err := w.Scope(); !errors.As(err, &invalid) {
			t.Fatal("ignored invalid admission left usable Work", err)
		}
	}
	var nilParticipant *scopeFeatureParticipant
	for _, p := range []FeatureExecutionContributor{nil, nilParticipant, foreign} {
		w := newWork()
		if err := w.RequireActiveUserAuthorization(context.Background(), p, valid); err == nil || w.state.sqlStarted {
			t.Fatal("unowned participant reached SQL")
		}
		if _, err := w.Scope(); err == nil {
			t.Fatal("ignored invocation failure left usable Work")
		}
	}
	w := newWork()
	if err := w.RequireActiveUserAuthorization(nil, native, valid); err == nil || w.state.failed == nil || w.state.sqlStarted {
		t.Fatal("nil context left usable Work")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	w = newWork()
	if err := w.RequireActiveUserAuthorization(cancelled, native, valid); !errors.Is(err, context.Canceled) || w.state.sqlStarted || w.state.failed == nil {
		t.Fatal("cancelled admission was not bounded or poisoned", err)
	}
	w = newWork()
	w.state.featureInvocation = nil
	if err := w.RequireActiveUserAuthorization(context.Background(), native, valid); err == nil || w.state.failed == nil || w.state.sqlStarted {
		t.Fatal("post-invocation admission was usable")
	}
	w = newWork()
	w.state.ctx = cancelled
	if err := w.RequireActiveUserAuthorization(context.Background(), native, valid); !errors.Is(err, context.Canceled) || w.state.sqlStarted {
		t.Fatal("expired Work renewed admission", err)
	}
	for _, w := range []Work{{}, {state: &workState{closed: true}}} {
		if err := w.RequireActiveUserAuthorization(context.Background(), native, valid); err == nil {
			t.Fatal("zero or closed Work admitted")
		}
	}
	if data, err := json.Marshal(valid); err == nil || len(data) != 0 || strings.Contains(fmt.Sprintf("%#v", valid), "users-sensitive") {
		t.Fatal("correlated admission disclosed")
	}
}
