package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

// This isolates root admission from the native producer. The actual PostgreSQL
// consumer must restore its genuine issuer checkpoint and fresh password proof;
// this test owner establishes no cryptographic or persistence qualification.
type preparedUnlinkTestOwner struct {
	*unlinkOwner
	expected AccountUnlinkCommand
	deny     bool
}

func (o *preparedUnlinkTestOwner) VerifyPreparedAccountUnlink(ctx context.Context, command AccountUnlinkCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.deny || !reflect.DeepEqual(command, o.expected) {
		return ForbiddenError{}
	}
	return nil
}

func preparedUnlinkCommandFixture(t *testing.T) (*AccountUnlinkService, *preparedUnlinkTestOwner, PreparedAccountUnlinkRequest, *AccountUnlinkService, AccountUnlinkRequest) {
	t.Helper()
	legacy, owner, request, caps, _ := unlinkCommandFixture(t)
	grant, err := caps.Verify(t.Context(), request.Proof, "identity.account.unlink", legacy.config.ProofAudience)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the existing core's exact policy-bound logical request. No raw
	// token or exported restoration API is introduced by the prepared path.
	binding := CommandBinding{CommandID: request.CommandID, TenantID: request.Change.TenantID, UserID: request.Change.UserID,
		ActorID: ActorID(request.ActorScope.Request.Subject.ID), ActorKind: request.ActorScope.Request.Subject.Kind,
		OperationID: "identity.account.unlink", PolicyID: legacy.config.Query.PolicyID, PolicyVersion: legacy.config.Query.PolicyVersion,
		SchemaID: "identity-account", SchemaVersion: 1, CorrelationID: string(request.CommandID), RecordID: string(request.Change.AccountID)}
	spec := AccountUnlinkCommand{Binding: binding, Change: request.Change, Proof: grant,
		SessionID: request.SessionID, SessionVersion: request.SessionVersion, RevokeProvider: request.RevokeProvider}
	prepared := &preparedUnlinkTestOwner{unlinkOwner: owner, expected: spec}
	service, err := NewPreparedAccountUnlinkService(owner, prepared, legacy.policy.policy.authorize, queryRedact, legacy.config)
	if err != nil {
		t.Fatal(err)
	}
	return service, prepared, PreparedAccountUnlinkRequest{Command: spec, ActorScope: request.ActorScope}, legacy, request
}

func TestPreparedAccountUnlinkRetainsCorePolicyReplayAndRecovery(t *testing.T) {
	s, owner, request, _, _ := preparedUnlinkCommandFixture(t)
	first, err := s.AccountUnlinkPrepared(t.Context(), request)
	if err != nil || first.CommitOutcome != CommitOutcomeCommitted || first.Version != 3 || owner.writes != 1 {
		t.Fatal("prepared original did not complete core-owned unlink admission", first, err)
	}
	again, err := s.AccountUnlinkPrepared(t.Context(), request)
	if err != nil || again != first || owner.writes != 1 {
		t.Fatal("prepared retry changed the original receipt or mutated twice", err)
	}
	recovered, err := s.RecoverAccountUnlink(t.Context(), AccountUnlinkRecoveryRequest{CommandID: request.Command.Binding.CommandID,
		TenantID: request.Command.Binding.TenantID, UserID: request.Command.Binding.UserID, AccountID: request.Command.Change.AccountID, ActorScope: request.ActorScope})
	if err != nil || recovered != first || owner.writes != 1 {
		t.Fatal("prepared recovery did not retain existing scoped observation", err)
	}
}

func TestPreparedAccountUnlinkRejectsChangedIntentAndForeignAuthority(t *testing.T) {
	for _, mode := range []string{"producer-denied", "session", "actor", "policy", "correlation", "account", "issuer", "proof-age", "missing-grant", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, request, _, _ := preparedUnlinkCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "producer-denied":
				owner.deny = true
			case "session":
				request.Command.SessionVersion++
			case "actor":
				request.ActorScope.Request.Subject.ID = "foreign"
			case "policy":
				request.Command.Binding.PolicyVersion++
			case "correlation":
				request.Command.Binding.CorrelationID = "changed"
			case "account":
				request.Command.Change.AccountID = "foreign"
			case "issuer":
				s.config.ProofIssuer = "https://foreign.example"
			case "proof-age":
				s.config.MaximumProofAge = 30 * time.Second
			case "missing-grant":
				request.Command.Proof = capability.Grant{}
			case "cancelled":
				cancel()
			}
			out, err := s.AccountUnlinkPrepared(ctx, request)
			if err == nil || out.CommitOutcome == CommitOutcomeCommitted || owner.writes != 0 {
				t.Fatal("substituted or untrusted prepared input reached mutation", mode)
			}
		})
	}
}

func TestPreparedAccountUnlinkDoesNotReplaceRawProofAdmission(t *testing.T) {
	s, owner, request, legacy, raw := preparedUnlinkCommandFixture(t)
	if _, err := legacy.AccountUnlinkPrepared(t.Context(), request); err == nil || owner.writes != 0 {
		t.Fatal("ordinary proof service accepted an unconfigured prepared owner")
	}
	if _, err := s.AccountUnlink(t.Context(), raw); err == nil || owner.writes != 0 {
		t.Fatal("prepared service silently replaced configured raw-proof verification")
	}
	if out, err := legacy.AccountUnlink(t.Context(), raw); err != nil || out.CommitOutcome != CommitOutcomeCommitted {
		t.Fatal("existing raw-proof consumer regressed", err)
	}
}

func TestPreparedAccountUnlinkPreservesUnknownAfterLostCommitReply(t *testing.T) {
	s, owner, request, _, _ := preparedUnlinkCommandFixture(t)
	owner.lose = true
	out, err := s.AccountUnlinkPrepared(t.Context(), request)
	if !errors.As(err, new(UnknownCommitError)) || out.CommitOutcome != CommitOutcomeUnknown || out.Version != 0 || owner.writes != 1 {
		t.Fatal("prepared path invented rollback or disclosed uncertain output", err)
	}
}
