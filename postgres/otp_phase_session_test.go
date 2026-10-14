package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

func TestOTPProtectedPhaseLendsOnlyDisjointSessionToken(t *testing.T) {
	for _, phase := range []otpExecutionPhase{otpCheck, otpFinalize} {
		for _, mode := range []string{"exact", "preauth", "absent", "foreign", "returned", "zero"} {
			t.Run(string(rune('0'+phase))+"/"+mode, func(t *testing.T) {
				w, _, _ := otpAuthorityFixture(t, context.Background(), "apply", "")
				plan := w.state.execution.reservation.plan
				owner := otpExecutionOwner(plan)
				_, original, _ := otpAttemptFixture(t, owner)
				spec, _ := original.Feature()
				code, _ := auth.NewOneTimeCode("123456")
				wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
				command, err := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(wire))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "preauth" {
					command, _ = identity.NewFeatureOneTimeCodePreAuthCommand(spec, code, auth.NewBearerCredential(wire))
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
				var token auth.BearerCredential
				if phase == otpCheck {
					token, err = (OTPApplyWork{state: s}).SessionToken(selected)
				} else {
					token, err = (OTPFinalizeWork{state: s}).SessionToken(selected)
				}
				if mode != "exact" {
					if err == nil || token.Token() != "" {
						t.Fatal("missing or unowned session token lent")
					}
					return
				}
				if err != nil || token.Token() != wire {
					t.Fatal("original session token lost")
				}
				s.reservation.active = false
				if phase == otpCheck {
					token, err = (OTPApplyWork{state: s}).SessionToken(selected)
				} else {
					token, err = (OTPFinalizeWork{state: s}).SessionToken(selected)
				}
				if err == nil || token.Token() != "" {
					t.Fatal("returned phase disclosed session token")
				}
			})
		}
	}
}
