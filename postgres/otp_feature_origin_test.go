package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type phoneOriginFeatureProbe struct{ scopeFeatureParticipant }

func (*phoneOriginFeatureProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}

type otpFeatureOriginGuard interface {
	RequireFeatureOrigin(context.Context, OTPReservationContributor, FeatureExecutionContributor, Work) error
}

// This tests only unforgeable cross-phase correlation, not factor verification
// or PostgreSQL execution. The native OTP/MFA consumer supplies that proof.
func TestOTPFeatureOriginRequiresSameLiveCompletedPhoneWork(t *testing.T) {
	for _, mode := range []string{"original", "same-value-foreign-work", "foreign-otp-owner", "nil-otp-owner", "foreign-feature-owner", "nil-feature-owner", "zero-otp-work", "no-origin", "not-applied", "not-attempted", "inside-apply", "feature-callback", "wrong-receipt", "foreign-operation", "missing-risk", "wrong-generation", "closed", "returned-otp", "nil-context", "cancelled-context"} {
		t.Run(mode, func(t *testing.T) {
			command, plan := phoneResetPlanFixture(t)
			spec, _ := command.PhonePasswordResetFeature()
			feature := &phoneOriginFeatureProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}}
			otp := &otpExecutionProbe{}
			registry, err := NewContributorRegistry([]Contributor{feature, otp})
			if err != nil {
				t.Fatal(err)
			}
			c := &Coordinator{registry: registry}
			p := &admittedKernelPlan{registry: registry.state, binding: spec.Binding, fingerprint: [32]byte{1}, feature: plan.Feature, subjectType: plan.SubjectType, lifecycle: plan.Lifecycle, capability: plan.Capability, otp: plan.OTP, risk: plan.RiskEvidence, contributors: registry.state.entries}
			w := Work{state: &workState{ctx: context.Background(), registry: registry.state, binding: spec.Binding, generation: 3, feature: p.feature, featureAttempted: true, featureReceipt: &identity.FeatureReceipt{Operation: spec.Operation}, execution: &domainExecution{coordinator: c, reservation: &reservationState{plan: p, journal: journalReservation{generation: 3}}}}}
			s := &otpExecutionState{reservation: otpReservationState{coordinator: c, work: w, plan: p, command: command, owner: otp, active: true}, phase: otpCheck}
			reader, ok := any(OTPApplyWork{state: s}).(otpFeatureOriginGuard)
			if !ok {
				t.Fatal("final OTP check cannot correlate actual MFA completion to its originating Work")
			}
			origin, otpOwner, featureOwner, ctx := w, OTPReservationContributor(otp), FeatureExecutionContributor(feature), context.Background()
			switch mode {
			case "same-value-foreign-work":
				copy := *w.state
				origin = Work{state: &copy}
			case "foreign-otp-owner":
				otpOwner = &otpExecutionProbe{}
			case "nil-otp-owner":
				otpOwner = nil
			case "foreign-feature-owner":
				featureOwner = &phoneOriginFeatureProbe{feature.scopeFeatureParticipant}
			case "nil-feature-owner":
				featureOwner = nil
			case "zero-otp-work":
				reader = OTPApplyWork{}
			case "no-origin":
				origin = Work{}
			case "not-applied":
				w.state.featureReceipt = nil
			case "not-attempted":
				w.state.featureAttempted = false
			case "inside-apply":
				w.state.featureApplying = true
			case "feature-callback":
				w.state.featureInvocation = feature
			case "wrong-receipt":
				w.state.featureReceipt.Operation.SchemaID = "foreign"
			case "foreign-operation":
				p.feature = &FeatureRegistration{Contributor: feature.Descriptor(), Operation: credentialResetOperation()}
			case "missing-risk":
				p.risk = nil
			case "wrong-generation":
				w.state.execution.reservation.journal.generation++
			case "closed":
				w.state.closed = true
			case "returned-otp":
				s.reservation.active = false
			case "nil-context":
				ctx = nil
			case "cancelled-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = reader.RequireFeatureOrigin(ctx, otpOwner, featureOwner, origin)
			if mode == "original" && err != nil {
				t.Fatal("exact originating completed phone Work denied", err)
			}
			if mode != "original" && err == nil {
				t.Fatal("foreign, inactive or merely scalar-matching completion admitted")
			}
		})
	}
}
