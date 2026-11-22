package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type unlinkOwnerProbe struct {
	check    func(AccountUnlinkWork) error
	eligible func(AccountUnlinkWork, []identity.LoginMethod) ([]identity.LoginMethod, error)
}

func (*unlinkOwnerProbe) Descriptor() ContributorDescriptor { return accountUnlinkOwnerDescriptor() }
func (*unlinkOwnerProbe) PrepareAccountUnlink(context.Context, identity.Command) (identity.Command, CommandCounterPlan, CapabilityPlan, error) {
	return identity.Command{}, CommandCounterPlan{}, CapabilityPlan{}, invalidPlan()
}
func (*unlinkOwnerProbe) ValidateAccountUnlink(identity.Command, CommandPlan) error { return nil }
func (p *unlinkOwnerProbe) CheckAccountUnlink(_ context.Context, h AccountUnlinkWork) error {
	if p.check != nil {
		return p.check(h)
	}
	_, _, err := h.Command(p)
	return err
}
func (p *unlinkOwnerProbe) EligibleAccountUnlinkMethods(_ context.Context, h AccountUnlinkWork, methods []identity.LoginMethod) ([]identity.LoginMethod, error) {
	if p.eligible != nil {
		return p.eligible(h, methods)
	}
	return nil, invalidWork()
}
func (*unlinkOwnerProbe) PersistAccountUnlink(context.Context, AccountUnlinkWork) error  { return nil }
func (*unlinkOwnerProbe) FinalizeAccountUnlink(context.Context, AccountUnlinkWork) error { return nil }
func (*unlinkOwnerProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func unlinkWorkFixture(t *testing.T, phase accountUnlinkPhase) (AccountUnlinkWork, *unlinkOwnerProbe) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	command := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil)
	spec, _ := command.UnlinkAccount()
	owner := &unlinkOwnerProbe{}
	work := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 1}}
	return AccountUnlinkWork{state: &accountUnlinkInvocation{work: work, participant: owner, command: spec, phase: phase, active: true}}, owner
}

func TestAccountUnlinkWorkOriginalCustodyAndLifetime(t *testing.T) {
	h, owner := unlinkWorkFixture(t, accountUnlinkCheck)
	spec, final, err := h.Command(owner)
	if err != nil || final || spec.RevokeProvider {
		t.Fatal("initial unlink intent unavailable", err)
	}
	spec.SessionID = "changed"
	again, _, err := h.Command(owner)
	if err != nil || again.SessionID == "changed" {
		t.Fatal("borrower changed retained unlink intent", err)
	}
	if fmt.Sprintf("%#v", h) != "postgres.AccountUnlinkWork(redacted)" {
		t.Fatal("unlink handle exposed original proof or transactional correlation")
	}
	if wire, err := json.Marshal(h); err == nil || len(wire) != 0 {
		t.Fatal("unlink invocation serialized")
	}
	if wire, err := h.MarshalText(); err == nil || len(wire) != 0 {
		t.Fatal("unlink invocation exported as text")
	}
	h.state.active = false
	if _, _, err := h.Command(owner); err == nil {
		t.Fatal("retained invocation usable after callback")
	}
	var zero AccountUnlinkWork
	if _, _, err := zero.Command(owner); err == nil {
		t.Fatal("zero invocation accepted")
	}
	if rows, err := zero.Query(context.Background(), "SELECT 1"); rows != nil || err == nil {
		t.Fatal("zero invocation queried")
	}
}

func TestAccountUnlinkWorkCurrentAuthorityCannotEscapeOwnerOrContext(t *testing.T) {
	for _, scope := range []string{"credential", "directory", "user-authorization"} {
		for _, fault := range []string{"foreign-owner", "nil-context"} {
			t.Run(scope+"/"+fault, func(t *testing.T) {
				h, owner := unlinkWorkFixture(t, accountUnlinkCheck)
				ctx := context.Background()
				if fault == "foreign-owner" {
					owner = &unlinkOwnerProbe{}
				} else {
					ctx = nil
				}
				var err error
				switch scope {
				case "credential":
					_, err = h.RequireActiveCredential(ctx, owner, CredentialAdmission{})
				case "directory":
					err = h.RequireActiveDirectoryAuthority(ctx, owner, DirectoryAuthorityAdmission{})
				case "user-authorization":
					err = h.RequireActiveUserAuthorization(ctx, owner, UserAuthorizationAdmission{})
				}
				if err == nil || h.state.work.usable() == nil {
					t.Fatal("unowned current-authority check reached SQL or left Work usable")
				}
			})
		}
	}
}

func TestAccountUnlinkWorkCannotAdoptAnUnownedEpochOrConsumeOutsidePersistence(t *testing.T) {
	h, owner := unlinkWorkFixture(t, accountUnlinkCheck)
	spec, _, err := h.Command(owner)
	if err != nil {
		t.Fatal(err)
	}
	if version, err := h.CredentialAuthorityVersion(owner); err != nil || version != spec.Change.ExpectedCredentialVersion {
		t.Fatal("initial check did not retain the original epoch", err)
	}
	if _, err := h.PersistenceIntent(owner); err == nil || h.state.work.usable() == nil {
		t.Fatal("initial check could claim persistence authority")
	}
	h, owner = unlinkWorkFixture(t, accountUnlinkFinalCheck)
	if version, err := h.CredentialAuthorityVersion(owner); err == nil || version != 0 || h.state.work.usable() == nil {
		t.Fatal("final check invented the epoch without its own applied result")
	}
	h, owner = unlinkWorkFixture(t, accountUnlinkPersist)
	if _, err := h.PersistenceIntent(&unlinkOwnerProbe{}); err == nil || h.state.work.usable() == nil {
		t.Fatal("foreign owner claimed original password consumption")
	}
}

func TestAccountUnlinkWorkForeignOwnerAndReadPhaseDenyPoison(t *testing.T) {
	for _, mode := range []string{"foreign", "read-phase-write", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			h, owner := unlinkWorkFixture(t, accountUnlinkCheck)
			var err error
			switch mode {
			case "foreign":
				_, _, err = h.Command(&unlinkOwnerProbe{})
			case "read-phase-write":
				_, err = h.Exec(h.state.work.state.ctx, "SELECT 1")
			case "nil-context":
				_, err = h.Query(nil, "SELECT 1")
			}
			if err == nil || h.state.work.usable() == nil {
				t.Fatal("ignored unlink denial left original Work committable")
			}
			if _, _, err := h.Command(owner); err == nil {
				t.Fatal("poisoned invocation recovered authority")
			}
		})
	}
	for _, phase := range []accountUnlinkPhase{accountUnlinkFinalCheck, accountUnlinkFinalize} {
		h, owner := unlinkWorkFixture(t, phase)
		if _, final, err := h.Command(owner); err != nil || !final {
			t.Fatal("final invocation renewed or lost original phase", err)
		}
	}
}
