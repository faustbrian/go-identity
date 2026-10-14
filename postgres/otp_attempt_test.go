package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

type otpAttemptProbe struct{ deny, panicValidation bool }

func (*otpAttemptProbe) Descriptor() ContributorDescriptor { return otpDescriptor() }
func (p *otpAttemptProbe) ValidateOTPAttemptCommand(identity.Command, OTPAttemptPlan) error {
	if p.panicValidation {
		panic("private attempt detail")
	}
	if p.deny {
		return identity.ForbiddenError{}
	}
	return nil
}
func (*otpAttemptProbe) RecordOTPAttemptDenial(context.Context, OTPAttemptWork) (OTPAttemptDisposition, error) {
	return OTPAttemptDenied, nil
}
func (*otpAttemptProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func otpAttemptFixture(t *testing.T, owner Contributor) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, p := featurePlanFixture(t)
	s := featureCodecSpec()
	native := &scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}
	r, err := NewContributorRegistry([]Contributor{&riskPassiveProbe{registryContributor{p.Contributors[0]}}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, native, owner})
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	_, declared := otpPlanFixture(t)
	p.OTP = declared.OTP
	p.Contributors = r.Descriptors()
	p.Feature.Contributor = native.Descriptor()
	p.SubjectType = "session"
	p.Audits[0].RetentionClass = "protected"
	p.Audits[0].BindingDigest = securityAuditScopeDigest(s.Binding, &s.Operation, p.SubjectType, s.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
	return c, codeCodecCommand(t, s, "123456"), p
}

func TestOTPAttemptPreparationFreezesNativeCustody(t *testing.T) {
	owner := &otpAttemptProbe{}
	c, command, p := otpAttemptFixture(t, owner)
	s, _ := command.Feature()
	prepared, err := c.PrepareOTPAttemptPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	p.OTP.AttemptFingerprint[0]++
	if *prepared.OTP == *p.OTP {
		t.Fatal("prepared custody aliases input")
	}
	owner.deny = true
	if _, err := c.PrepareOTPAttemptPlan(s.Binding, command, prepared); err == nil {
		t.Fatal("native denial ignored")
	}
	owner.deny, owner.panicValidation = false, true
	if _, err := c.PrepareOTPAttemptPlan(s.Binding, command, prepared); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("native panic admitted or leaked")
	}
	owner.panicValidation = false
	plain, _ := identity.NewFeatureCommand(s)
	if _, err := c.PrepareOTPAttemptPlan(s.Binding, plain, prepared); err == nil {
		t.Fatal("code-free command enabled denial")
	}
}

func TestOTPAttemptWorkZeroAndDiagnostics(t *testing.T) {
	var w OTPAttemptWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero disclosed custody")
	}
	if _, err := w.NativeCommand(nil); err == nil {
		t.Fatal("zero disclosed code")
	}
	if _, err := w.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero read primary")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero mutated primary")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero read clock")
	}
	for _, value := range []any{w, OTPAttemptBinding{}} {
		if _, err := json.Marshal(value); err == nil || !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
			t.Fatal("private attempt work exposed")
		}
	}
}

func TestOTPAttemptWorkIncompleteInternalReservationDenies(t *testing.T) {
	c, _, _ := coordinatorFixture(t)
	w := OTPAttemptWork{state: &otpAttemptState{active: true, work: Work{state: &workState{registry: c.registry.state, execution: &domainExecution{coordinator: c, reservation: &reservationState{}}}}}}
	if _, err := w.Binding(&otpAttemptProbe{}); err == nil {
		t.Fatal("incomplete internal reservation admitted")
	}
}
