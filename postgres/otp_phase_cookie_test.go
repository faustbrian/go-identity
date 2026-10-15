package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestOTPProtectedPhaseLendsOnlySubmittedCookie(t *testing.T) {
	for _, phase := range []otpExecutionPhase{otpCheck, otpFinalize} {
		for _, mode := range []string{"exact", "wrong-cookie", "absent", "foreign", "returned", "zero"} {
			t.Run(string(rune('0'+phase))+"/"+mode, func(t *testing.T) {
				w, _, _ := otpAuthorityFixture(t, context.Background(), "apply", "")
				plan := w.state.execution.reservation.plan
				owner := otpExecutionOwner(plan)
				_, original, _ := otpAttemptFixture(t, owner)
				spec, _ := original.Feature()
				code, _ := authentication.NewOneTimeCode("123456")
				marker := byte(0x11)
				if mode == "wrong-cookie" {
					marker = 0x12
				}
				wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{marker}, 32))
				command, err := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, authentication.NewBearerCredential(wire))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "absent" {
					command = original
				}
				s := &otpExecutionState{reservation: otpReservationState{coordinator: w.state.execution.coordinator, work: w, plan: plan, command: command, owner: owner, active: true}, phase: phase}
				selected := owner
				if mode == "foreign" {
					selected = &otpExecutionProbe{}
				}
				if mode == "returned" {
					s.reservation.active = false
				}
				if mode == "zero" {
					s = nil
				}
				var cookie authentication.BearerCredential
				if phase == otpCheck {
					cookie, err = (OTPApplyWork{state: s}).PreAuthCookie(selected)
				} else {
					cookie, err = (OTPFinalizeWork{state: s}).PreAuthCookie(selected)
				}
				if mode == "exact" || mode == "wrong-cookie" {
					if err != nil || cookie.Token() != wire {
						t.Fatal("original separately submitted cookie lost")
					}
					s.reservation.active = false
					if phase == otpCheck {
						cookie, err = (OTPApplyWork{state: s}).PreAuthCookie(selected)
					} else {
						cookie, err = (OTPFinalizeWork{state: s}).PreAuthCookie(selected)
					}
					if err == nil || cookie.Token() != "" {
						t.Fatal("returned phase retained cookie access")
					}
				} else if err == nil || cookie.Token() != "" {
					t.Fatal("unowned or missing cookie lent")
				}
			})
		}
	}
}

type otpCookieDispatchProbe struct {
	otpExecutionProbe
	want     string
	apply    OTPApplyWork
	finalize OTPFinalizeWork
}

func (p *otpCookieDispatchProbe) CheckOTP(_ context.Context, w OTPApplyWork) error {
	p.apply = w
	cookie, err := w.PreAuthCookie(p)
	if err != nil || cookie.Token() != p.want {
		return invalidWork()
	}
	return nil
}

func (p *otpCookieDispatchProbe) FinalizeOTP(_ context.Context, w OTPFinalizeWork) error {
	p.finalize = w
	cookie, err := w.PreAuthCookie(p)
	if err != nil || cookie.Token() != p.want {
		return invalidWork()
	}
	return nil
}

func TestOTPProtectedCookieActualDispatchLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &otpCookieDispatchProbe{want: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x13}, 32))}
	c, original, plan := otpAttemptFixture(t, owner)
	spec, _ := original.Feature()
	code, _ := authentication.NewOneTimeCode("123456")
	command, err := identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, authentication.NewBearerCredential(owner.want))
	if err != nil {
		t.Fatal(err)
	}
	_, _, admitted, err := c.prepareOTPReservation(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 1, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, journal: journalReservation{generation: 1}}}
	for _, phase := range []otpExecutionPhase{otpCheck, otpFinalize} {
		if err = c.runOTPExecution(ctx, w, command, phase); err != nil {
			t.Fatal(err)
		}
	}
	for _, get := range []func(OTPReservationContributor) (authentication.BearerCredential, error){owner.apply.PreAuthCookie, owner.finalize.PreAuthCookie} {
		cookie, e := get(owner)
		if e == nil || cookie.Token() != "" {
			t.Fatal("returned dispatch exposed original bearer")
		}
	}
	if w.state.failed != nil || w.usable() != nil {
		t.Fatal("returned accessor poisoned later invocation")
	}
}
