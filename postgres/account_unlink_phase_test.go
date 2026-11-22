package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func unlinkInvocationFixture(t *testing.T) (*Coordinator, Work, identity.Command, *unlinkOwnerProbe) {
	t.Helper()
	c, command, plan := unlinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountUnlinkCounterCommand()
	q, _, admitted, err := c.prepare(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 1, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, request: q}}
	return c, w, command, admitted.accountUnlink.contributor.(*unlinkOwnerProbe)
}

func TestAccountUnlinkPhaseInvocationExpiresAndCannotRepeat(t *testing.T) {
	c, w, command, owner := unlinkInvocationFixture(t)
	var retained AccountUnlinkWork
	owner.check = func(h AccountUnlinkWork) error {
		retained = h
		_, final, err := h.Command(owner)
		if err != nil || final {
			t.Fatal("initial callback lost original intent", err)
		}
		return nil
	}
	if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, command, accountUnlinkCheck, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := retained.Command(owner); err == nil {
		t.Fatal("returned unlink invocation retained transaction custody")
	}
	if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, command, accountUnlinkCheck, nil); err == nil || w.usable() == nil {
		t.Fatal("repeated initial admission was not terminal to Work")
	}
}

func TestAccountUnlinkPhaseDenialAndPanicCannotBeIgnored(t *testing.T) {
	for _, mode := range []string{"foreign", "read-only", "panic", "error", "final-before-apply", "changed-command"} {
		t.Run(mode, func(t *testing.T) {
			c, w, command, owner := unlinkInvocationFixture(t)
			owner.check = func(h AccountUnlinkWork) error {
				switch mode {
				case "foreign":
					_, _, _ = h.Command(&unlinkOwnerProbe{})
				case "read-only":
					_, _ = h.Exec(w.state.ctx, "SELECT 1")
				case "panic":
					panic("private diagnostic")
				case "error":
					return fmt.Errorf("private diagnostic")
				}
				return nil
			}
			phase := accountUnlinkCheck
			if mode == "final-before-apply" {
				phase = accountUnlinkFinalCheck
			}
			if mode == "changed-command" {
				spec, counters, _ := command.AccountUnlinkCounterCommand()
				counters.Network = "192.0.2.200"
				base, _ := identity.NewAccountUnlinkCommand(spec)
				command, _ = identity.NewAccountUnlinkCounterCommand(base, counters)
			}
			if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, command, phase, nil); err == nil || w.usable() == nil {
				t.Fatal("unlink phase denial did not poison original Work")
			}
		})
	}
}

func TestAccountUnlinkEligibilityOwnerCannotReplaceStoredCredentialFacts(t *testing.T) {
	// The probe tests kernel projection custody only, not genuine password
	// eligibility. The real native journey must use the actual credential owner.
	for _, mode := range []string{"allowed", "changed-record", "omitted-record", "extra-record"} {
		t.Run(mode, func(t *testing.T) {
			c, w, command, owner := unlinkInvocationFixture(t)
			if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, command, accountUnlinkCheck, nil); err != nil {
				t.Fatal(err)
			}
			spec, _, _ := command.AccountUnlinkCounterCommand()
			methods := []identity.LoginMethod{{Credential: identity.CredentialRef{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, ID: "password-a", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}}}
			owner.eligible = func(h AccountUnlinkWork, input []identity.LoginMethod) ([]identity.LoginMethod, error) {
				if _, _, err := h.Command(owner); err != nil {
					return nil, err
				}
				input[0].Usable = true
				switch mode {
				case "changed-record":
					input[0].Credential.Version++
				case "omitted-record":
					return nil, nil
				case "extra-record":
					input = append(input, input[0])
				}
				return input, nil
			}
			got, err := c.runAccountUnlinkPhase(w.state.ctx, w, command, accountUnlinkEligibility, methods)
			if mode != "allowed" {
				if err == nil || got != nil || w.usable() == nil {
					t.Fatal("eligibility replaced locked kernel-owned method facts")
				}
				return
			}
			if err != nil || len(got) != 1 || !got[0].Usable || methods[0].Usable {
				t.Fatal("eligibility did not preserve independently owned method projections", err)
			}
			got[0].Credential.ID = "changed"
			if methods[0].Credential.ID != "password-a" {
				t.Fatal("returned eligibility aliases original snapshot")
			}
		})
	}
}
