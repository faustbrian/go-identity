package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
)

func TestIdentifierServiceCarriesOriginalProofWithoutTransferringCustody(t *testing.T) {
	s, owner, request, caps := identifierCommandFixture(t)
	var retained Command
	s.uow = creationOwnerFunc{execute: func(ctx context.Context, command Command) (CommandResult, error) {
		proof, ok := command.IdentifierProof()
		if !ok {
			t.Fatal("native composition lost original proof")
		}
		spec, _ := command.ChangeIdentifier()
		verified, err := caps.Verify(ctx, proof, capability.Purpose(spec.Binding.OperationID), s.config.ProofAudience)
		if err != nil {
			t.Fatal("configured reverification failed", err)
		}
		expected, err := capability.CanonicalPayload(spec.Proof.Payload(), capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		actual, err := capability.CanonicalPayload(verified.Payload(), capability.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expected, actual) {
			t.Fatal("original signed command changed")
		}
		retained = command
		return owner.Execute(ctx, command)
	}, recover: owner.Recover}
	result, err := s.IdentifierChange(context.Background(), request)
	if err != nil || result.CommitOutcome != CommitOutcomeCommitted {
		t.Fatal("proof transport changed result", err)
	}
	if _, err := caps.Verify(context.Background(), request.Proof, "identity.identifier.attach", s.config.ProofAudience); err != nil {
		t.Fatal("service consumed request custody", err)
	}
	if data, err := json.Marshal(retained); err == nil || len(data) != 0 {
		t.Fatal("command serialized bearer custody")
	}
	if strings.Contains(fmt.Sprintf("%#v", retained), request.Change.CanonicalValue) {
		t.Fatal("command disclosed sensitive intent")
	}
	copy := retained
	original, ok := copy.IdentifierProof()
	if !ok {
		t.Fatal("command copy lost custody")
	}
	if err := original.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if len(raw) == 0 {
			t.Fatal("empty original bearer")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []capability.Proof{request.Proof, original} {
		if _, err := caps.Verify(context.Background(), alias, "identity.identifier.attach", s.config.ProofAudience); err == nil {
			t.Fatal("transfer cloned rather than shared original custody")
		}
	}
	proof, ok := retained.IdentifierProof()
	if !ok {
		t.Fatal("presence was mistaken for validity")
	}
	if proof.Transfer(context.Background(), func(context.Context, []byte) error { t.Fatal("second disclosure"); return nil }) == nil {
		t.Fatal("command alias retained disclosed proof")
	}
	spec, _ := retained.ChangeIdentifier()
	metadataOnly, err := NewIdentifierCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := metadataOnly.IdentifierProof(); ok {
		t.Fatal("structural constructor invented bearer custody")
	}
	for _, command := range []Command{{}, {create: &CreateUserCommand{}}} {
		if _, ok := command.IdentifierProof(); ok {
			t.Fatal("nonidentifier variant exposed proof")
		}
	}
}

func TestIdentifierServiceDoesNotForwardProofAfterDeniedAdmission(t *testing.T) {
	s, owner, request, _ := identifierCommandFixture(t)
	s.policy.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	})
	s.uow = creationOwnerFunc{execute: func(context.Context, Command) (CommandResult, error) {
		t.Fatal("denied proof crossed execution boundary")
		return CommandResult{}, nil
	}, recover: owner.Recover}
	result, err := s.IdentifierChange(context.Background(), request)
	if err == nil || result.CommitOutcome == CommitOutcomeCommitted || owner.writes != 0 {
		t.Fatal("denied request executed")
	}
}
