package postgres

import (
	"context"
	"testing"
)

func otpUserCheck(t *testing.T, ctx context.Context, phase, mode string) (Work, func(context.Context, UserAuthorityAdmission) error, func()) {
	t.Helper()
	fixturePhase := phase
	if phase == "feature" {
		fixturePhase = "attempt"
	}
	w, _, _ := otpAuthorityFixture(t, ctx, fixturePhase, "")
	plan := w.state.execution.reservation.plan
	owner := otpExecutionOwner(plan)
	if phase == "feature" {
		native := &scopeFeatureParticipant{}
		var selected FeatureExecutionContributor = native
		if mode == "foreign" {
			selected = &scopeFeatureParticipant{}
		}
		if mode == "nil-owner" {
			selected = nil
		}
		w.state.feature = &FeatureRegistration{}
		w.state.lifecycle = &workLifecycle{}
		w.state.featureInvocation = native
		return w, func(ctx context.Context, expected UserAuthorityAdmission) error {
			return w.RequireActiveUserAuthority(ctx, selected, expected)
		}, func() { w.state.featureInvocation = nil }
	}
	selected := owner
	if mode == "foreign" {
		selected = &otpExecutionProbe{}
	}
	if mode == "nil-owner" {
		selected = nil
	}
	r := otpReservationState{coordinator: w.state.execution.coordinator, work: w, plan: plan, owner: owner, active: true}
	switch phase {
	case "attempt":
		h := OTPAttemptWork{state: &otpAttemptState{work: w, owner: owner, active: true}}
		return w, func(ctx context.Context, expected UserAuthorityAdmission) error {
			return h.RequireActiveUserAuthority(ctx, selected, expected)
		}, func() { h.state.active = false }
	case "reservation":
		h := OTPReservationWork{state: &r}
		return w, func(ctx context.Context, expected UserAuthorityAdmission) error {
			return h.RequireActiveUserAuthority(ctx, selected, expected)
		}, func() { h.state.active = false }
	case "apply":
		h := OTPApplyWork{state: &otpExecutionState{reservation: r, phase: otpCheck}}
		return w, func(ctx context.Context, expected UserAuthorityAdmission) error {
			return h.RequireActiveUserAuthority(ctx, selected, expected)
		}, func() { h.state.reservation.active = false }
	case "finalize":
		h := OTPFinalizeWork{state: &otpExecutionState{reservation: r, phase: otpFinalize}}
		return w, func(ctx context.Context, expected UserAuthorityAdmission) error {
			return h.RequireActiveUserAuthority(ctx, selected, expected)
		}, func() { h.state.reservation.active = false }
	default:
		t.Fatal("unknown phase")
		return Work{}, nil, nil
	}
}

func TestOTPUserAuthorityRejectsUnownedAndMalformed(t *testing.T) {
	for _, phase := range []string{"attempt", "reservation", "apply", "finalize", "feature"} {
		for _, mode := range []string{"zero-epoch", "foreign", "nil-owner", "nil-context", "canceled", "returned", "open-cursor"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				w, check, deactivate := otpUserCheck(t, context.Background(), phase, mode)
				expected := UserAuthorityAdmission{UserAuthorityVersion: 3, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 7}
				ctx := context.Background()
				switch mode {
				case "zero-epoch":
					expected.IdentifierAuthorityVersion = 0
				case "nil-context":
					ctx = nil
				case "canceled":
					c, cancel := context.WithCancel(ctx)
					cancel()
					ctx = c
				case "returned":
					deactivate()
				case "open-cursor":
					w.state.rows = &WorkRows{}
				}
				err := check(ctx, expected)
				w.state.rows = nil
				if err == nil || w.state.sqlStarted {
					t.Fatal("invalid admission reached primary")
				}
				if mode == "returned" {
					if w.state.failed != nil || w.usable() != nil {
						t.Fatal("expired handle poisoned another invocation")
					}
				} else if w.state.failed == nil || w.usable() == nil {
					t.Fatal("ignored live denial left Work usable")
				}
			})
		}
	}
}
