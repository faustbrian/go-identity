package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

// Admission is a serial coordinator boundary, not a reusable authority lease.
// Final checks may adopt only the successor persisted by this exact mutation.
func TestIdentifierAdmissionRejectsFinalBeforeInitial(t *testing.T) {
	p := &identifierAdmissionProbe{}
	c, w, cmd := identifierAdmissionFixture(t, p)
	if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, true); err == nil || w.usable() == nil || p.retained.state != nil {
		t.Fatal("final callback admitted without an initial check")
	}
}

func TestIdentifierAdmissionRejectsRepeatedInitial(t *testing.T) {
	p := &identifierAdmissionProbe{}
	c, w, cmd := identifierAdmissionFixture(t, p)
	if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err != nil {
		t.Fatal(err)
	}
	p.retained = IdentifierAdmissionWork{}
	if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err == nil || w.usable() == nil || p.retained.state != nil {
		t.Fatal("initial admission renewed")
	}
}

func TestIdentifierAdmissionOwnsSuccessorAndFinalizesOnce(t *testing.T) {
	p := &identifierAdmissionProbe{}
	c, w, cmd := identifierAdmissionFixture(t, p)
	s, _ := cmd.ChangeIdentifier()
	p.inspect = func(h IdentifierAdmissionWork) error {
		_, final, err := h.Command(p)
		if err != nil {
			return err
		}
		epoch, err := h.IdentifierAuthorityVersion(p)
		want := s.Change.ExpectedAuthorityVersion
		if final {
			want++
		}
		if err != nil || epoch != want {
			t.Fatal("wrong owned epoch", epoch, err)
		}
		return nil
	}
	if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.retained.IdentifierAuthorityVersion(p); err == nil {
		t.Fatal("retained epoch authority")
	}
	w.state.identifier = identifierOwnedAdmissionResult(t, cmd)
	if err := c.finalizeIdentifierCapability(w); err != nil {
		t.Fatal(err)
	}
	if !w.state.identifier.proofFinalized {
		t.Fatal("proof not finalized")
	}
	if err := c.finalizeIdentifierCapability(w); err == nil || w.usable() == nil {
		t.Fatal("duplicate terminal admission")
	}
}

func identifierOwnedAdmissionResult(t *testing.T, cmd identity.Command) *identifierWorkResult {
	t.Helper()
	s, _ := cmd.ChangeIdentifier()
	d, err := identity.IdentifierIntentDigest(s.Change)
	if err != nil {
		t.Fatal(err)
	}
	return &identifierWorkResult{
		user:          identity.User{TenantID: s.Binding.TenantID, ID: s.Binding.UserID, Status: identity.StatusActive, Version: s.Change.ExpectedUserVersion + 1},
		receipt:       identity.IdentifierReceipt{IdentifierID: s.Change.ID, Action: s.Change.Action, ExpectedAuthorityVersion: s.Change.ExpectedAuthorityVersion, AuthorityVersion: s.Change.ExpectedAuthorityVersion + 1, IntentDigest: d},
		proofConsumed: true,
	}
}

func TestIdentifierAdmissionRejectsUnownedSuccessor(t *testing.T) {
	for name, alter := range map[string]func(*identifierWorkResult){
		"missing":      nil,
		"unconsumed":   func(r *identifierWorkResult) { r.proofConsumed = false },
		"finalized":    func(r *identifierWorkResult) { r.proofFinalized = true },
		"other user":   func(r *identifierWorkResult) { r.user.ID = "other" },
		"user version": func(r *identifierWorkResult) { r.user.Version++ },
		"blocked":      func(r *identifierWorkResult) { r.user.Status = identity.StatusBanned },
		"other record": func(r *identifierWorkResult) { r.receipt.IdentifierID = "other" },
		"other action": func(r *identifierWorkResult) { r.receipt.Action = identity.IdentifierRemove },
		"predecessor":  func(r *identifierWorkResult) { r.receipt.ExpectedAuthorityVersion++ },
		"successor":    func(r *identifierWorkResult) { r.receipt.AuthorityVersion++ },
		"intent":       func(r *identifierWorkResult) { r.receipt.IntentDigest = [32]byte{9} },
	} {
		t.Run(name, func(t *testing.T) {
			p := &identifierAdmissionProbe{}
			c, w, cmd := identifierAdmissionFixture(t, p)
			if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, false); err != nil {
				t.Fatal(err)
			}
			if alter != nil {
				w.state.identifier = identifierOwnedAdmissionResult(t, cmd)
				alter(w.state.identifier)
			}
			p.retained = IdentifierAdmissionWork{}
			if err := c.runIdentifierAdmission(w.state.ctx, w, cmd, true); err == nil || w.usable() == nil || p.retained.state != nil {
				t.Fatal("unowned final successor admitted")
			}
		})
	}
}
