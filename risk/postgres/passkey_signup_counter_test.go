package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func passkeySignupCommand(t *testing.T, tenant, action string) identity.Command {
	t.Helper()
	s, _ := protectedCommand(t, tenant).Feature()
	s.Operation = identity.FeatureOperation{Owner: "passkey", OperationID: action, SchemaID: action + ".signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = action, s.Operation.SchemaID
	s.Binding.UserID, s.Binding.AnonymousFlowID, s.Binding.RecordID = "", "original-browser", "original-registration"
	s.Binding.ActorID, s.Binding.ActorKind = "signup-service", authorization.SubjectServiceAccount
	c, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNativePasskeySignupCounters(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	preparer, ok := any(r).(interface {
		PreparePasskeySignupCommandCounters(identity.Command, risk.Subject, time.Time) (identity.Command, kernel.CommandCounterPlan, error)
	})
	if !ok {
		t.Fatal("native anonymous passkey signup counter preparation unavailable")
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	subject := risk.Subject{Network: "2001:db8::1", Device: "original-device"}
	for _, action := range []string{"identity.passkey.register-options", "identity.passkey.register-verify"} {
		t.Run(action, func(t *testing.T) {
			original := passkeySignupCommand(t, "signup-tenant", action)
			mapped, plan, err := preparer.PreparePasskeySignupCommandCounters(original, subject, at)
			if err != nil || r.ValidateCommandCounters(mapped, plan) != nil {
				t.Fatal("signup counters unavailable", err)
			}
			before, _ := original.Feature()
			after, _ := mapped.Feature()
			if before.Binding != after.Binding || after.Binding.UserID != "" {
				t.Fatal("invented account ownership")
			}
			restored, err := r.restoreCounter(mapped, plan)
			if err != nil || restored.validateAt(at) != nil || restored.current.Limit != 5 || restored.current.Window != 15*time.Minute || len(restored.current.Targets) != 4 || restored.current.Targets[1].Dimension != risk.BrowserFlowDimension || restored.current.Targets[3].Dimension != risk.DeviceDimension {
				t.Fatal("signup changed canonical policy or dimensions", err)
			}
			if restored.validateAt(at.Add(15*time.Minute)) == nil {
				t.Fatal("exclusive expiry renewed")
			}
			if _, _, err := r.PrepareCommandCounters(original, subject, at); err == nil {
				t.Fatal("generic counters adopted signup")
			}
			if _, _, err := preparer.PreparePasskeySignupCommandCounters(mapped, subject, at); err == nil {
				t.Fatal("duplicate counter preparation")
			}
			for _, mutate := range []func(*identity.FeatureCommandSpec){
				func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "foreign-browser" },
				func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign-tenant" },
				func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/passkey" },
				func(s *identity.FeatureCommandSpec) {
					s.Operation.SchemaID = action + ".native-v1"
					s.Binding.SchemaID = s.Operation.SchemaID
				},
				func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = authorization.SubjectUser },
				func(s *identity.FeatureCommandSpec) {
					s.Fields = append(s.Fields, textField("counter.browser", "foreign-browser"))
				},
				func(s *identity.FeatureCommandSpec) {
					for i := range s.Fields {
						if s.Fields[i].Name == "counter.device" {
							s.Fields[i].Value.Text = "foreign-device"
						}
					}
				},
			} {
				s, _ := mapped.Feature()
				mutate(&s)
				bad, err := identity.NewFeatureCommand(s)
				if err == nil && r.ValidateCommandCounters(bad, plan) == nil {
					t.Fatal("foreign scope adopted original counter plan")
				}
			}
			for _, bad := range []risk.Subject{{Network: subject.Network}, {Network: subject.Network, Device: subject.Device, User: "invented"}, {Network: subject.Network, Device: subject.Device, Session: "invented"}} {
				if _, _, err := preparer.PreparePasskeySignupCommandCounters(original, bad, at); err == nil {
					t.Fatal("malformed signup dimensions admitted")
				}
			}
		})
	}
}
