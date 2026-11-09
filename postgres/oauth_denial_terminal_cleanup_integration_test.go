//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// The SQL owner represents native RP custody. This fixture proves coordinator
// rollback/recovery atomicity, not browser admission or provider cryptography.
type denialTerminalSQLPhase struct {
	cleanupFailure bool
	applyCalls     int
	cleanupHandle  Work
}

func (*denialTerminalSQLPhase) Descriptor() ContributorDescriptor {
	return oauthCallbackDenialDescriptor()
}

func (*denialTerminalSQLPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{oauthCallbackDenialOperation()}
}

func (p *denialTerminalSQLPhase) ValidateFeatureCommand(command identity.Command, plan CommandPlan) error {
	spec, ok := command.Feature()
	if !ok || spec.Operation != oauthCallbackDenialOperation() || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Capability == nil {
		return invalidPlan()
	}
	return nil
}

func (p *denialTerminalSQLPhase) ApplyFeature(ctx context.Context, w Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.applyCalls++
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	// A native erasure statement failed; no denial transition committed.
	return identity.FeatureReceipt{}, identity.UnavailableError{}
}

func (*denialTerminalSQLPhase) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return nil
}

func (p *denialTerminalSQLPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, feature, _, err := w.FeatureScope(p); err != nil || feature.Contributor != p.Descriptor() {
		return RecoveryUnknown, invalidWork()
	}
	return recoveryTestEvidence(ctx, w, "public.identity_test_lifecycle")
}

// This optional phase deliberately uses existing Work authority so the RED
// regression compiles before the coordinator gains its exact-owner dispatch.
func (p *denialTerminalSQLPhase) CleanupFeatureTerminal(ctx context.Context, w Work) error {
	p.cleanupHandle = w
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || feature.Operation != oauthCallbackDenialOperation() {
		return invalidWork()
	}
	state, err := w.OAuthCallbackDenialState(p)
	if err != nil || state.Purpose != "identity.oauth.callback" {
		return invalidWork()
	}
	if p.cleanupFailure {
		return identity.UnavailableError{}
	}
	n, err := w.Exec(ctx, `UPDATE public.denial_exchange_secrets SET ciphertext=NULL WHERE command_id=$1 AND ciphertext IS NOT NULL`, string(b.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

type denialWithoutCleanupPhase struct{ FeatureCommitContributor }

func (p *denialWithoutCleanupPhase) RecoverParticipant(_ context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return RecoveryUnknown, err
	}
	return RecoveryNotCommitted, nil
}

func TestOAuthDenialMissingCleanupKeepsOriginalCustody(t *testing.T) {
	ctx, pool, c, phase, command, plan := denialTerminalFixture(t)
	entries := make([]Contributor, len(c.registry.state.entries))
	for i, entry := range c.registry.state.entries {
		entries[i] = entry.contributor
		if entry.descriptor == phase.Descriptor() {
			entries[i] = &denialWithoutCleanupPhase{FeatureCommitContributor: phase}
		}
	}
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.Feature()
	if reservation, _, err := c.ReserveCommand(ctx, spec.Binding, command, plan); err != nil || reservation.state == nil {
		t.Fatal("reserve legacy denial owner", err)
	}
	expireDenialTerminalLease(t, ctx, pool, spec.Binding.CommandID)
	result, err := c.recoverCommandReceipt(ctx, creationRecoveryQuery(spec.Binding))
	if err == nil || result.Outcome == identity.CommitOutcomeNotCommitted {
		t.Fatal("missing exact-owner cleanup silently terminalized denial", err)
	}
	var intact, pending bool
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT ciphertext IS NOT NULL FROM public.denial_exchange_secrets),(SELECT state='pending' AND result IS NULL FROM identity.commands)`).Scan(&intact, &pending); err != nil || !intact || !pending {
		t.Fatal("missing cleanup lost recovery custody", err)
	}
}

func TestOAuthDenialHistoricalRecoveryUsesExactRegisteredOwnerWithoutCaller(t *testing.T) {
	ctx, pool, c, phase, command, plan := denialTerminalFixture(t)
	spec, _ := command.Feature()
	if reservation, _, err := c.ReserveCommand(ctx, spec.Binding, command, plan); err != nil || reservation.state == nil {
		t.Fatal(err)
	}
	expireDenialTerminalLease(t, ctx, pool, spec.Binding.CommandID)
	q := creationRecoveryQuery(spec.Binding)
	if _, err := c.RecoverOAuthCallbackDenial(ctx, q, &denialTerminalSQLPhase{}); err == nil {
		t.Fatal("descriptor-equivalent foreign owner obtained historical authority")
	}
	wrong := q
	wrong.UserID, wrong.ActorID = "other-user", "other-user"
	if _, err := c.RecoverOAuthCallbackDenial(ctx, wrong, phase); err == nil {
		t.Fatal("registered owner retargeted historical recovery")
	}
	result, err := c.RecoverOAuthCallbackDenial(ctx, q, phase)
	if err != nil || result.Outcome != identity.CommitOutcomeNotCommitted || result.Feature == nil || result.Feature.AfterVersion != 0 {
		t.Fatal("native metadata-only historical denial did not settle failure", err)
	}
	if _, err := phase.cleanupHandle.OAuthCallbackDenialState(phase); err == nil {
		t.Fatal("returned cleanup handle retained state disclosure authority")
	}
}

func denialTerminalFixture(t *testing.T) (context.Context, *database.Pool, *Coordinator, *denialTerminalSQLPhase, identity.Command, CommandPlan) {
	t.Helper()
	ctx, pool, repo := newAccountAuthorityStore(t)
	_, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE,no_change boolean,outcome smallint,reason text);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.link_capability_effect(command_id text NOT NULL,capability_id text NOT NULL,state text NOT NULL,PRIMARY KEY(command_id,capability_id));
CREATE TABLE public.denial_exchange_secrets(command_id text PRIMARY KEY,ciphertext bytea)`)
	if err != nil {
		t.Fatal(err)
	}
	phase := &denialTerminalSQLPhase{}
	registry, err := NewContributorRegistry([]Contributor{repo, &accountLinkSQLAudit{}, &recoveryLifecyclePhase{}, phase, &accountLinkErasureCapabilities{}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	b, plan := oauthDenialPlanFixture(t)
	b.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b.CorrelationID = string(b.CommandID)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: oauthCallbackDenialOperation(), Fields: []identity.FeatureField{{Name: "oauth.flow-digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 32)}}}})
	plan.Contributors = []ContributorDescriptor{repo.Descriptor(), (&accountLinkSQLAudit{}).Descriptor(), (&recoveryLifecyclePhase{}).Descriptor(), phase.Descriptor(), (&accountLinkErasureCapabilities{}).Descriptor()}
	seed, err := featureMutationAudits(ctx, &admittedKernelPlan{binding: b, feature: plan.Feature, lifecycle: plan.Lifecycle, audits: plan.Audits, subjectType: plan.SubjectType}, time.Now().UTC().Truncate(time.Microsecond), "committed")
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, oauthCallbackDenialOperation(), plan.SubjectType, seed[0])
	if err != nil {
		t.Fatal(err)
	}
	plan, err = c.PrepareCommandPlan(b, command, plan)
	if err != nil {
		t.Fatal("prepare original denial", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.denial_exchange_secrets(command_id,ciphertext) VALUES($1,$2)`, string(b.CommandID), []byte("synthetic-encrypted-rp-secrets")); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, c, phase, command, plan
}

func TestOAuthDenialTerminalCleanupIsAtomicWithFailureReceiptAndProofRelease(t *testing.T) {
	for _, route := range []string{"abort", "recovery"} {
		for _, cleanupFailure := range []bool{false, true} {
			name := route + "/erasure-available"
			if cleanupFailure {
				name = route + "/erasure-unavailable"
			}
			t.Run(name, func(t *testing.T) {
				ctx, pool, c, phase, command, plan := denialTerminalFixture(t)
				phase.cleanupFailure = cleanupFailure
				spec, _ := command.Feature()
				b := spec.Binding
				reservation, _, err := c.ReserveCommand(ctx, b, command, plan)
				if err != nil || reservation.state == nil {
					t.Fatal("reserve denial", err)
				}
				var result identity.CommandResult
				if route == "abort" {
					w, beginErr := c.Begin(ctx, reservation)
					if beginErr != nil {
						t.Fatal(beginErr)
					}
					defer c.Abort(w, identity.UnavailableError{})
					_, applyErr := c.ApplyFeature(ctx, w, command)
					if applyErr == nil || phase.applyCalls != 1 {
						t.Fatal("denial did not reach failed erasure", applyErr)
					}
					result, err = c.Abort(w, applyErr)
				} else {
					expireDenialTerminalLease(t, ctx, pool, b.CommandID)
					result, err = c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
				}
				var state, proof string
				var intact, receipt bool
				var audits, lifecycle int
				raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				read := func() {
					t.Helper()
					if e := pool.Raw().QueryRow(ctx, `SELECT j.state,j.result IS NOT NULL,s.ciphertext IS NOT NULL,c.state,(SELECT count(*) FROM public.identity_test_audits),(SELECT count(*) FROM public.identity_test_lifecycle) FROM identity.commands j JOIN public.denial_exchange_secrets s ON s.command_id=$2 JOIN public.link_capability_effect c ON c.command_id=$2 WHERE j.command_id=$1`, raw, string(b.CommandID)).Scan(&state, &receipt, &intact, &proof, &audits, &lifecycle); e != nil {
						t.Fatal(e)
					}
				}
				read()
				if cleanupFailure {
					if err == nil || state != "pending" || receipt || !intact || proof != "reserved" || audits != 0 || lifecycle != 0 || result.Outcome == identity.CommitOutcomeNotCommitted {
						t.Fatalf("failed denial erasure lost recoverable custody: state=%s receipt=%t intact=%t proof=%s audits=%d lifecycle=%d outcome=%v error=%T", state, receipt, intact, proof, audits, lifecycle, result.Outcome, err)
					}
					phase.cleanupFailure = false
					expireDenialTerminalLease(t, ctx, pool, b.CommandID)
					result, err = c.recoverCommandReceipt(ctx, creationRecoveryQuery(b))
					read()
				}
				if state != "aborted" || !receipt || intact || proof != "released" || audits != 1 || lifecycle != 0 || result.Outcome != identity.CommitOutcomeNotCommitted || result.Feature == nil || result.Feature.BeforeVersion != 0 || result.Feature.AfterVersion != 0 {
					t.Fatalf("failed denial terminalized with secrets or fabricated completion: state=%s receipt=%t intact=%t proof=%s audits=%d lifecycle=%d outcome=%v error=%T", state, receipt, intact, proof, audits, lifecycle, result.Outcome, err)
				}
				var noChange bool
				var outcome int16
				if e := pool.Raw().QueryRow(ctx, `SELECT no_change,outcome FROM public.identity_test_audits`).Scan(&noChange, &outcome); e != nil || !noChange || outcome != int16(audit.OutcomeFailed) {
					t.Fatal("failed cleanup was reported as committed provider denial", e)
				}
				_, replay, replayErr := c.ReserveCommand(ctx, b, command, plan)
				if replayErr != nil || !reflect.DeepEqual(replay, result) {
					t.Fatal("failed-terminal replay changed its original receipt", replayErr)
				}
			})
		}
	}
}

func expireDenialTerminalLease(t *testing.T, ctx context.Context, pool *database.Pool, command identity.CommandID) {
	t.Helper()
	raw, _ := base64.RawURLEncoding.DecodeString(string(command))
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
		t.Fatal(err)
	}
}
