//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This is a trusted test-owned native feature, not a session implementation.
// It proves the real coordinator's proof/effect/journal atomicity. The production
// session owner must still map complete session input and lock its full vector.
type authenticatedIntegrationOwner struct {
	finalFeatureOwner
	denyInitial, denyFinal, expireAfterApply bool
	checks                                   []bool
}

func (p *authenticatedIntegrationOwner) CheckAuthenticatedFeature(ctx context.Context, w Work, command identity.Command, s authentication.AuthenticatedProofSpec, final bool) error {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	p.checks = append(p.checks, final)
	if !final && p.denyInitial || final && p.denyFinal {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *authenticatedIntegrationOwner) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	b, operation, _, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	n, err := w.Exec(ctx, "INSERT INTO public.authenticated_feature(command_id,record_id) VALUES($1,$2)", string(b.CommandID), b.RecordID)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if p.expireAfterApply {
		// Primary-side waiting crosses the original exclusive proof expiry. No new
		// client clock, refreshed proof or renewed authority is substituted.
		if _, err := w.Exec(ctx, "SELECT pg_sleep(0.6)"); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: operation.Operation, AfterVersion: 1}, nil
}
func (p *authenticatedIntegrationOwner) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.authenticated_feature")
}

func testAuthenticatedCommandIntegration(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.authenticated_feature(command_id text PRIMARY KEY,record_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, _, base, unitOwner := finalFeatureFixture(t)
	owner := &authenticatedIntegrationOwner{finalFeatureOwner: *unitOwner}
	auditing, lifecycle := &recoveryAuditPhase{}, &recoveryLifecyclePhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, owner})
	if err != nil {
		t.Fatal(err)
	}
	binding := codecBinding()
	binding.OperationID, binding.SchemaID, binding.RecordID = "identity.session.issue", "session-issue", "new-session"
	authority, mint, original := finalProofFactory(t, binding)
	config := CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, FinalAuthentication: &FinalAuthenticationConfig{Authority: authority, Namespace: "original-authentication"}}
	config.QueryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	c, err := NewCoordinator(pool, registry, config)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(proof authentication.AuthenticatedProof) (identity.CommandBinding, identity.Command, CommandPlan) {
		t.Helper()
		b := binding
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		b.RecordID = string(id)
		command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: owner.operations[0], Fields: []identity.FeatureField{{Name: "value", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original"}}}})
		p := base
		p.Contributors = registry.Descriptors()
		p.Audits = append([]AuditPlan(nil), base.Audits...)
		p.Feature = &FeatureRegistration{Contributor: owner.Descriptor(), Operation: owner.operations[0]}
		record, err := securityMutationAudit(ctx, b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", b.RecordID, "protected", true)
		if err != nil {
			t.Fatal(err)
		}
		p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, owner.operations[0], "session", record)
		if err != nil {
			t.Fatal(err)
		}
		p, err = c.PrepareAuthenticatedCommandPlan(b, command, proof, p)
		if err != nil {
			t.Fatal("prepare", err)
		}
		return b, command, p
	}
	counts := func(b identity.CommandBinding, wantUse, wantDomain, wantAudit, wantLifecycle int) {
		t.Helper()
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		var use, domain, audit, event int
		err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.signin_proof_uses WHERE command_id=$1),(SELECT count(*) FROM public.authenticated_feature WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$2)`, id, string(b.CommandID)).Scan(&use, &domain, &audit, &event)
		if err != nil || use != wantUse || domain != wantDomain || audit != wantAudit || event != wantLifecycle {
			t.Fatalf("atomic state %d/%d/%d/%d: %v", use, domain, audit, event, err)
		}
	}
	execute := func(b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, p CommandPlan) (identity.CommandResult, error) {
		t.Helper()
		r, result, err := c.ReserveAuthenticatedCommand(ctx, b, command, proof, p)
		if err != nil || r.state == nil {
			return result, err
		}
		w, err := c.Begin(ctx, r)
		if err != nil {
			return result, err
		}
		defer c.Abort(w, identity.UnavailableError{})
		result, err = c.ApplyFeature(ctx, w, command)
		if err != nil {
			return c.Abort(w, err)
		}
		return c.Commit(w, result)
	}
	proof := mint(original)
	b, command, p := prepare(proof)
	result, err := execute(b, command, proof, p)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("commit", err)
	}
	counts(b, 1, 1, 1, 1)
	_, caller := queryInputs(b)
	observed, queryErr := c.QueryAuthenticatedCommand(ctx, b, command, proof, p, caller)
	if queryErr != nil || observed.AuditEventID != result.AuditEventID || observed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("exact primary receipt lookup", queryErr)
	}
	observed, queryErr = c.RecoverAuthenticatedCommand(ctx, b, command, proof, p, caller)
	if queryErr != nil || observed.AuditEventID != result.AuditEventID || observed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("exact primary receipt recovery", queryErr)
	}
	counts(b, 1, 1, 1, 1)
	if len(owner.checks) != 2 || owner.checks[0] || !owner.checks[1] {
		t.Fatal("initial/final checks missing")
	}
	r, replay, err := c.ReserveAuthenticatedCommand(ctx, b, command, proof, p)
	if err != nil || r.state != nil || replay.AuditEventID != result.AuditEventID {
		t.Fatal("exact replay changed", err)
	}
	counts(b, 1, 1, 1, 1)
	rotated := config
	rotated.CurrentFingerprintKeyVersion = 2
	rotated.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {2}}
	next, err := NewCoordinator(pool, registry, rotated)
	if err != nil {
		t.Fatal(err)
	}
	nextPlan, err := next.PrepareAuthenticatedCommandPlan(b, command, proof, p)
	if err != nil {
		t.Fatal(err)
	}
	r, replay, err = next.ReserveAuthenticatedCommand(ctx, b, command, proof, nextPlan)
	if err != nil || r.state != nil || replay.AuditEventID != result.AuditEventID {
		t.Fatal("retained-key replay changed", err)
	}
	observed, queryErr = next.QueryAuthenticatedCommand(ctx, b, command, proof, nextPlan, caller)
	if queryErr != nil || observed.AuditEventID != result.AuditEventID {
		t.Fatal("retained-key historical query changed", queryErr)
	}
	modified := original
	modified.ProofVersion--
	changedProof := mint(modified)
	changedPlan, err := c.PrepareAuthenticatedCommandPlan(b, command, changedProof, p)
	if err != nil {
		t.Fatal(err)
	}
	var conflict identity.ConflictError
	if queryResult, queryErr := c.QueryAuthenticatedCommand(ctx, b, command, changedProof, changedPlan, caller); !errors.As(queryErr, &conflict) || queryResult.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("changed proof disclosed original receipt", queryErr)
	}
	if _, result, err := c.ReserveAuthenticatedCommand(ctx, b, command, changedProof, changedPlan); !errors.As(err, &conflict) || result.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("changed proof reassigned command", err)
	}
	duplicate, duplicateCommand, duplicatePlan := prepare(proof)
	if _, err := execute(duplicate, duplicateCommand, proof, duplicatePlan); !errors.As(err, &conflict) {
		t.Fatal("proof reused by another command", err)
	}
	counts(duplicate, 0, 0, 1, 0)
	t.Run("recovery never reserves missing input", func(t *testing.T) {
		missing, missingCommand, missingPlan := prepare(proof)
		_, currentCaller := queryInputs(missing)
		if receipt, e := c.RecoverAuthenticatedCommand(ctx, missing, missingCommand, proof, missingPlan, currentCaller); e == nil || receipt.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("missing recovery gained outcome")
		}
		counts(missing, 0, 0, 0, 0)
		var claims int
		id, _ := base64.RawURLEncoding.DecodeString(string(missing.CommandID))
		if e := pool.Raw().QueryRow(ctx, "SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1", id).Scan(&claims); e != nil || claims != 0 {
			t.Fatal("recovery reserved missing command", e)
		}
	})
	t.Run("live pending recovery does not renew", func(t *testing.T) {
		candidate := original
		candidate.Proof.ID = "pendingpendingpendingxx"
		pendingProof := mint(candidate)
		pending, pendingCommand, pendingPlan := prepare(pendingProof)
		reservation, receipt, e := c.ReserveAuthenticatedCommand(ctx, pending, pendingCommand, pendingProof, pendingPlan)
		if e != nil || reservation.state == nil || receipt.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("pending reservation", e)
		}
		_, currentCaller := queryInputs(pending)
		receipt, e = c.RecoverAuthenticatedCommand(ctx, pending, pendingCommand, pendingProof, pendingPlan, currentCaller)
		if e != nil || receipt.Outcome != identity.CommitOutcomeInProgress {
			t.Fatal("live lease recovery", e)
		}
		counts(pending, 0, 0, 0, 0)
		id, _ := base64.RawURLEncoding.DecodeString(string(pending.CommandID))
		var generation string
		if e = pool.Raw().QueryRow(ctx, "SELECT generation::text FROM identity.commands WHERE command_id=$1", id).Scan(&generation); e != nil || generation != "1" {
			t.Fatal("recovery renewed live generation", e)
		}
	})
	t.Run("kernel recovery conserves proof use", func(t *testing.T) {
		for _, candidate := range []struct {
			binding identity.CommandBinding
			want    RecoveryStatus
		}{{b, RecoveryUnknown}, {duplicate, RecoveryNotCommitted}} {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			bounded, stop := context.WithTimeout(ctx, time.Second)
			w := Work{state: &workState{tx: tx, ctx: bounded, cancel: stop, binding: candidate.binding, generation: 1}}
			recovery := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{contributor: repo, descriptor: repo.Descriptor()}, plan: &admittedKernelPlan{feature: p.Feature}, active: true}}
			got, checkErr := repo.RecoverParticipant(bounded, recovery)
			invalidateWork(w)
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			rollbackErr := tx.Rollback(cleanup)
			done()
			if checkErr != nil || rollbackErr != nil || got != candidate.want {
				t.Fatalf("proof-use recovery %v, want %v: %v / %v", got, candidate.want, checkErr, rollbackErr)
			}
		}
	})
	for index, variant := range []string{"initial denial", "final denial", "audit failure", "expiry after apply"} {
		t.Run(variant, func(t *testing.T) {
			candidate := original
			candidate.Proof.ID = authentication.ProofID("zzzzzzzzzzzzzzzzzzzzzz" + string(rune('a'+index)))
			if variant == "expiry after apply" {
				candidate.Proof.ExpiresAt = time.Now().UTC().Add(300 * time.Millisecond)
			}
			token := mint(candidate)
			b, command, p := prepare(token)
			owner.denyInitial = variant == "initial denial"
			owner.denyFinal = variant == "final denial"
			owner.expireAfterApply = variant == "expiry after apply"
			auditing.fail = variant == "audit failure"
			result, err := execute(b, command, token, p)
			if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("failed admission committed")
			}
			// Audit failure cannot persist a terminal failure event either; it remains
			// pending/unknown rather than fabricating an audited rollback result.
			audit := 1
			if auditing.fail {
				audit = 0
			}
			counts(b, 0, 0, audit, 0)
			owner.denyInitial, owner.denyFinal, owner.expireAfterApply, auditing.fail = false, false, false, false
		})
	}
}
