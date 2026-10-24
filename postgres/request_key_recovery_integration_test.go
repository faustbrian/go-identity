//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// A kernel owner seam, not an encryption/authentication interoperability claim.
// The organization consumer separately proves its genuine envelope decoder.
func testMappedFeatureRecovery(t *testing.T, ctx context.Context, c *Coordinator, owner *requestPreparationParticipant, input RequestKeyPreparationBinding, wire []byte, original identity.CommandBinding) {
	t.Helper()
	original.CommandID = input.Admission.CommandID
	original.TenantID, original.ActorID, original.ActorKind = input.Scope.TenantID, input.Scope.ActorID, input.Scope.ActorKind
	q, caller := queryInputs(original)
	allow, calls := true, 0
	c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		outcome := authorization.Deny
		if allow {
			outcome = authorization.Allow
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	owner.restore = func(callback context.Context, b RequestKeyPreparationBinding, got []byte) (identity.CommandBinding, error) {
		calls++
		if _, bounded := callback.Deadline(); !bounded || b != input || !bytes.Equal(got, wire) {
			t.Fatal("restore lost original custody or bound")
		}
		return original, nil
	}
	var unknown identity.UnknownCommitError
	for range 2 {
		got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, owner)
		if !errors.As(err, &unknown) || unknown.CommandID != q.CommandID || got.Binding != original || got.Outcome != identity.CommitOutcomeUnknown || got.Feature == nil || got.Feature.Operation != input.Feature.Operation || got.Validate() != nil {
			t.Fatal("mapped original lost explicit unknown correlation", got.Outcome, err)
		}
	}
	// Ordinary outcome queries retain their intentionally uniform denial shape.
	if got, err := c.RecoverFeatureCommand(ctx, q, caller); err == nil || got.Binding.CommandID != "" {
		t.Fatal("generic recovery disclosed mapped absence")
	}
	for _, alter := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.UserID = "foreign" },
		func(q *identity.RecoveryQuery) { q.RecordID = "foreign" },
		func(q *identity.RecoveryQuery) { q.TenantID = "foreign" },
		func(q *identity.RecoveryQuery) { q.ActorID = "foreign" },
	} {
		other := q
		alter(&other)
		got, err := c.RecoverPreparedFeatureCommand(ctx, other, callerForQuery(caller, other), input.Feature, owner)
		if err == nil || got.Binding.CommandID != "" || got.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("foreign mapped history disclosed")
		}
	}
	allow = false
	before := calls
	if got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, owner); err == nil || got.Binding.CommandID != "" || calls != before {
		t.Fatal("current policy denial reached decoder or disclosed correlation")
	}
	allow = true
	decode := owner.restore
	owner.restore = func(ctx context.Context, b RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
		original, err := decode(ctx, b, wire)
		allow = false // Current query policy must still fence the final read.
		return original, err
	}
	if got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, owner); err == nil || got.Binding.CommandID != "" {
		t.Fatal("changed current policy disclosed mapped outcome")
	}
	allow, owner.restore = true, decode
	foreign := &requestPreparationParticipant{scopeFeatureParticipant: owner.scopeFeatureParticipant, restore: owner.restore}
	if got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, foreign); err == nil || got.Binding.CommandID != "" {
		t.Fatal("descriptor alias acquired native recovery custody")
	}
	owner.restore = func(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, error) {
		return original, errors.New("private decoder diagnostic")
	}
	if got, err := c.RecoverPreparedFeatureCommand(ctx, q, caller, input.Feature, owner); err == nil || got.Binding.CommandID != "" || err.Error() == "private decoder diagnostic" {
		t.Fatal("failed native authentication disclosed original scope")
	}
	var claims, journals int
	raw, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	if err := c.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM identity.commands WHERE command_id=$1)`, raw).Scan(&claims, &journals); err != nil || claims != 0 || journals != 0 {
		t.Fatal("mapped observation created executable history", err)
	}
}
