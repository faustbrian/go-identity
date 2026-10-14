package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestNativeMFALoginSendCountersPreserveBrowserAndAnonymousJournal(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := protectedCommand(t, "mfa-tenant").Feature()
	s.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	s.Binding.UserID, s.Binding.RecordID, s.Binding.AnonymousFlowID = "", "AQEBAQEBAQEBAQEBAQEBAQ", "bbbbbbbbbbbbbbbbbbbbbg"
	cookie := auth.NewBearerCredential(strings.Repeat("A", 43))
	original, err := identity.NewFeaturePreAuthCommand(s, cookie)
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: "original-subject", Network: "127.0.0.1"}
	at := time.Now().UTC().Truncate(time.Microsecond)
	mapped, plan, err := r.PrepareMFALoginSendCommandCounters(original, subject, at)
	if err != nil || r.ValidateCommandCounters(mapped, plan) != nil {
		t.Fatal("anonymous MFA send counter projection unavailable", err)
	}
	got, ok := mapped.PreAuthCookie()
	fields, _ := mapped.Feature()
	if !ok || got != cookie || fields.Binding != s.Binding || fields.Binding.UserID != "" {
		t.Fatal("counter mapping dropped browser or invented authenticated journal ownership")
	}
	if _, ok := mapped.SessionToken(); ok {
		t.Fatal("anonymous send fabricated a session")
	}
	restored, err := r.restoreCounter(mapped, plan)
	if err != nil || restored.subject.User != subject.User || len(restored.current.Targets) != 4 || restored.current.Targets[2].Dimension != risk.BrowserFlowDimension || restored.validateAt(at) != nil {
		t.Fatal("native restoration lost original browser/account profile", err)
	}
	if _, _, err := r.PrepareCommandCounters(original, subject, at); err == nil {
		t.Fatal("ordinary session counters adopted anonymous login")
	}
	if _, _, err := r.PrepareMFALoginSendCommandCounters(mapped, subject, at); err == nil {
		t.Fatal("mapped command received another preparation")
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "cccccccccccccccccccccg" },
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "counter.subject" {
					s.Fields[i].Value.Text = "other-subject"
				}
			}
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, textField("counter.capability", "invented-child"))
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectUser
			s.Binding.UserID, s.Binding.AnonymousFlowID = "original-subject", ""
		},
	} {
		bad, _ := mapped.Feature()
		change(&bad)
		command, err := identity.NewFeaturePreAuthCommand(bad, cookie)
		if err == nil && r.ValidateCommandCounters(command, plan) == nil {
			t.Fatal("substituted profile adopted retained counter custody")
		}
	}
	bare, _ := identity.NewFeatureCommand(s)
	if _, _, err := r.PrepareMFALoginSendCommandCounters(bare, subject, at); err == nil {
		t.Fatal("anonymous send without browser possession admitted")
	}
	if _, err := r.ReserveCommandCounters(context.Background(), kernel.CommandCounterWork{}); err == nil || r.CheckCommandCounters(context.Background(), kernel.CommandCounterAdmissionWork{}) == nil {
		t.Fatal("zero Work supplied counter reservation/admission")
	}
}
