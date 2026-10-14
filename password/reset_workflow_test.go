package password_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-capability"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

func TestResetWorkflowInputPreservesOriginalCustody(t *testing.T) {
	base := signupInput(t)
	base.Caller.Request.Action = "identity.password.reset-request"
	id, _ := identity.NewCommandID()
	identifierInput, err := identifier.NewInput(" unnormalized@example.test ")
	if err != nil {
		t.Fatal(err)
	}
	r := password.ResetRequestRequest{TenantID: base.TenantID, CommandID: id, Identifier: identifierInput, CallbackURL: "https://identity.test/reset", IdempotencyKey: base.IdempotencyKey, Caller: base.Caller, Origin: base.Origin, Network: base.Network, Device: base.Device}
	if r.Validate() != nil || string(r.Identifier) != " unnormalized@example.test " {
		t.Fatal("request changed identifier or denied bounded input")
	}
	for _, mutate := range []func(*password.ResetRequestRequest){
		func(r *password.ResetRequestRequest) { r.CommandID = "" },
		func(r *password.ResetRequestRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *password.ResetRequestRequest) { r.CallbackURL = "https://identity.test/reset#" },
		func(r *password.ResetRequestRequest) { r.CallbackURL = "http://identity.test/reset" },
		func(r *password.ResetRequestRequest) { r.Identifier = identifier.Input(strings.Repeat("x", 4097)) },
		func(r *password.ResetRequestRequest) { r.Caller.Request.Action = "identity.password.signup" },
	} {
		changed := r
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid reset request accepted")
		}
	}
	c, original := resetProfileFixture(t)
	p, _ := password.NewResetProfile(c)
	payload, _ := p.Payload(original)
	payload.ID = "synthetic-reset-input"
	signer, _ := capability.NewHMACSHA256Signer("synthetic", bytes.Repeat([]byte{71}, 32))
	wire, err := capability.Issue(context.Background(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	base.Caller.Request.Action = "identity.password.reset-complete"
	complete := password.ResetCompleteRequest{TenantID: base.TenantID, CommandID: id, Token: proof, NewPassword: base.Password, Caller: base.Caller, Origin: base.Origin, Network: base.Network, Device: base.Device}
	if complete.Validate() != nil || proof.ValidateBounds(32, 4096) != nil {
		t.Fatal("completion structural check consumed proof")
	}
	if err := complete.NewPassword.Use(func(raw []byte) error {
		if !bytes.Equal(raw, []byte(" raw\x00synthetic-ä-password ")) {
			t.Fatal("password bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{r, complete} {
		if strings.Contains(fmt.Sprintf("%#v", value), "unnormalized") {
			t.Fatal("sensitive input formatted")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("input exported implicitly")
		}
	}
	if err := proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if complete.Validate() == nil {
		t.Fatal("terminal proof accepted")
	}
}

func TestResetWorkflowResultsDoNotReportEffectsBeforeCommit(t *testing.T) {
	id, _ := identity.NewCommandID()
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress, identity.CommitOutcomeConflict} {
		if (password.ResetCompleteResult{CommandID: id, Outcome: outcome, CredentialVersion: 8, SessionsRevoked: true}).Validate() == nil {
			t.Fatal("uncommitted successor exposed")
		}
		if (password.ResetRequestResult{CommandID: id, Outcome: outcome, Accepted: true}).Validate() == nil {
			t.Fatal("uncommitted delivery acknowledgement exposed")
		}
	}
	if (password.ResetCompleteResult{CommandID: id, Outcome: identity.CommitOutcomeCommitted, CredentialVersion: 8, SessionsRevoked: true}).Validate() != nil {
		t.Fatal("known committed reset denied")
	}
	if (password.ResetRequestResult{CommandID: id, Outcome: identity.CommitOutcomeCommitted, Accepted: true}).Validate() != nil {
		t.Fatal("neutral committed request denied")
	}
	if (password.ResetCompleteResult{}).Validate() == nil || (password.ResetRequestResult{}).Validate() == nil {
		t.Fatal("zero result became authoritative")
	}
}
