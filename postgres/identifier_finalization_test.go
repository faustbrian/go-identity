package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestIdentifierFinalizationRequiresConsumptionAndRunsOnce(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		p := &capabilityExecutionProbe{}
		c, w := capabilityDomainFixture(t, p)
		w.state.identifier = &identifierWorkResult{proofConsumed: consumed}
		err := c.finalizeIdentifierCapability(w)
		if !consumed {
			if err == nil || w.usable() == nil || p.finalize.state != nil {
				t.Fatal("unconsumed proof finalized")
			}
			continue
		}
		if err != nil || p.finalize.state == nil || !w.state.identifier.proofFinalized {
			t.Fatal("consumed identifier not finalized", err)
		}
		if _, err := p.finalize.Binding(p); err == nil {
			t.Fatal("finalization authority retained")
		}
		if err := c.finalizeIdentifierCapability(w); err == nil || w.usable() == nil {
			t.Fatal("duplicate finalization accepted")
		}
	}
}

func TestIdentifierFinalizationFailureNeverBecomesSuccess(t *testing.T) {
	for _, panics := range []bool{false, true} {
		p := &capabilityExecutionProbe{failure: identity.ConflictError{}, panicPhase: panics}
		c, w := capabilityDomainFixture(t, p)
		w.state.identifier = &identifierWorkResult{proofConsumed: true}
		if err := c.finalizeIdentifierCapability(w); err == nil || w.usable() == nil || w.state.identifier.proofFinalized {
			t.Fatal("failed finalization accepted", err)
		}
	}
	p := &capabilityExecutionProbe{}
	c, w := capabilityDomainFixture(t, p)
	w.state.identifier = &identifierWorkResult{proofConsumed: true}
	w.state.cancel()
	var cancelled identity.CancelledError
	if err := c.finalizeIdentifierCapability(w); !errors.As(err, &cancelled) || p.finalize.state != nil {
		t.Fatal("expired Work reached finalization", err)
	}
}

func TestIdentifierFinalizationDoesNotInvokeOtherDomainOrForeignWork(t *testing.T) {
	p := &capabilityExecutionProbe{}
	c, w := capabilityDomainFixture(t, p)
	if err := c.finalizeIdentifierCapability(w); err != nil || p.finalize.state != nil {
		t.Fatal("non-identifier finalized a proof", err)
	}
	if err := c.finalizeIdentifierCapability(Work{}); err == nil {
		t.Fatal("zero Work finalized")
	}
	w.state.identifier = &identifierWorkResult{proofConsumed: true}
	foreign := *c
	if err := foreign.finalizeIdentifierCapability(w); err == nil || p.finalize.state != nil || w.usable() != nil {
		t.Fatal("foreign coordinator changed Work", err)
	}
}

// Bounded plan: admit only the exact provisional storage result; reject changed
// versions, record/action/digest and mixed domain arms. Finalization failure must
// poison the same Work, never leave an independently committed consumption.
func TestIdentifierResultMatchesOwnedMutationOnly(t *testing.T) {
	cmd := recordIdentifier(t, identity.IdentifierVerify, nil, nil)
	spec, _ := cmd.ChangeIdentifier()
	digest, _ := identity.IdentifierIntentDigest(spec.Change)
	receipt := identity.IdentifierReceipt{IdentifierID: spec.Change.ID, Action: spec.Change.Action, ExpectedAuthorityVersion: 1, AuthorityVersion: 2, IntentDigest: digest}
	user := identity.User{TenantID: spec.Binding.TenantID, ID: spec.Binding.UserID, Status: identity.StatusActive, Version: 2}
	result := identity.CommandResult{Binding: spec.Binding, Outcome: identity.CommitOutcomeCommitted, User: user, ExpectedVersion: 1, Identifier: &receipt, AuditEventID: "audit-a"}
	w := Work{state: &workState{binding: spec.Binding, identifier: &identifierWorkResult{user: user, receipt: receipt}}}
	if !matchesDomainResult(w, result) {
		t.Fatal("owned identifier receipt rejected")
	}
	for name, change := range map[string]func(*identity.CommandResult){
		"user version":       func(r *identity.CommandResult) { r.User.Version++ },
		"expected user":      func(r *identity.CommandResult) { r.ExpectedVersion++ },
		"missing receipt":    func(r *identity.CommandResult) { r.Identifier = nil },
		"record":             func(r *identity.CommandResult) { r.Identifier.IdentifierID = "other" },
		"action":             func(r *identity.CommandResult) { r.Identifier.Action = identity.IdentifierRemove },
		"authority":          func(r *identity.CommandResult) { r.Identifier.AuthorityVersion++ },
		"previous authority": func(r *identity.CommandResult) { r.Identifier.ExpectedAuthorityVersion++ },
		"digest":             func(r *identity.CommandResult) { r.Identifier.IntentDigest = [32]byte{9} },
	} {
		t.Run(name, func(t *testing.T) {
			r := result
			copy := receipt
			r.Identifier = &copy
			change(&r)
			if matchesDomainResult(w, r) {
				t.Fatal("caller substituted identifier receipt")
			}
		})
	}
	for name, change := range map[string]func(*workState){
		"creation": func(s *workState) { s.creation = &user },
		"profile":  func(s *workState) { s.profile = &identity.UserProfile{} },
		"update":   func(s *workState) { s.update = &user },
		"status":   func(s *workState) { s.status = &result },
		"feature":  func(s *workState) { s.feature = &FeatureRegistration{} },
	} {
		t.Run(name, func(t *testing.T) {
			s := *w.state
			change(&s)
			if matchesDomainResult(Work{state: &s}, result) {
				t.Fatal("mixed domain receipt accepted")
			}
		})
	}
}
