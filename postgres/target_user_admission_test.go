package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type targetUserAdmitter interface {
	RequireActiveTargetUser(context.Context, FeatureExecutionContributor, identity.User) error
}

func TestTargetUserAdmissionRejectsForeignAndUnownedBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native := &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	for _, mode := range []string{"zero-work", "foreign-tenant", "foreign-user", "inactive", "zero-version", "nil-context", "canceled", "work-canceled", "foreign-owner", "returned"} {
		t.Run(mode, func(t *testing.T) {
			w := Work{state: &workState{ctx: t.Context(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
			expected := identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 17}
			ctx, owner := context.Context(t.Context()), FeatureExecutionContributor(native)
			switch mode {
			case "zero-work":
				w = Work{}
			case "foreign-tenant":
				expected.TenantID = "another-tenant"
			case "foreign-user":
				expected.ID = "another-user"
			case "inactive":
				expected.Status = identity.StatusSuspended
			case "zero-version":
				expected.Version = 0
			case "nil-context":
				ctx = nil
			case "canceled", "work-canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				if mode == "work-canceled" {
					w.state.ctx = ctx
				}
			case "foreign-owner":
				owner = &scopeFeatureParticipant{}
			case "returned":
				w.state.featureInvocation = nil
			}
			admission, ok := any(w).(targetUserAdmitter)
			if !ok {
				t.Fatal("missing native target-user admission; aggregate versions cannot substitute for security epochs")
			}
			err := admission.RequireActiveTargetUser(ctx, owner, expected)
			if err == nil || w.state != nil && w.state.sqlStarted {
				t.Fatal("invalid target scope reached SQL or was admitted", err)
			}
			if (mode == "canceled" || mode == "work-canceled") && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation identity", err)
			}
			if w.state != nil && mode != "returned" && w.state.failed == nil {
				t.Fatal("ignored live admission rejection did not poison Work")
			}
		})
	}
}
