//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This is session-owner composition proof, not ID-token hint authentication or
// an end-session protocol service. Genuine native issuance, current owner data
// and actual required audit/outbox are retained; the OAuth contributor here only
// exercises the explicitly closed effect boundary that the protocol will own.
type oidcEndSessionOwnerPhase struct {
	effect             *OIDCEndSessionEffect
	command            identity.Command
	source             session.Session
	applied            bool
	recovered          int
	vote               kernel.RecoveryStatus
	waitUntil          time.Time
	finalWindowReached bool
}

func (*oidcEndSessionOwnerPhase) Descriptor() kernel.ContributorDescriptor {
	return oidcEndSessionOwner()
}
func (*oidcEndSessionOwnerPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{oidcEndSessionOperation()}
}
func (p *oidcEndSessionOwnerPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return session.ErrInvalidSessionCommand
	}
	_, _, err := oidcEndSessionIntent(c)
	return err
}
func (p *oidcEndSessionOwnerPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, c)
	p.applied = err == nil
	return r, err
}
func (p *oidcEndSessionOwnerPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if !p.waitUntil.IsZero() {
		// A bounded test-only pause after required persistence crosses the
		// immutable command deadline, not the still-live source's lifetime.
		timer := time.NewTimer(time.Until(p.waitUntil) + 5*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		now, err := w.DatabaseTime(ctx)
		if err != nil || now.Before(p.waitUntil) {
			return identity.UnavailableError{}
		}
		if _, err := p.source.Lifetime(now); err != nil {
			return err
		}
		p.finalWindowReached = true
	}
	return p.effect.Check(ctx, w, p, c)
}
func (p *oidcEndSessionOwnerPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recovered++
	vote, err := p.effect.Recover(ctx, w, p, p.source)
	p.vote = vote
	return vote, err
}

func testOIDCEndSessionEffect(t *testing.T, ctx context.Context, pool *database.Pool, c IssueExecutorConfig, executor *IssueExecutor, issue func(*testing.T, string) session.Session) {
	t.Helper()
	history, err := (OIDCEndSessionMigrationSource{Schema: c.Repository.Schema, Version: 100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("populated session owner suffix", err)
		}
	}
	effect, err := NewOIDCEndSessionEffect(c.Repository, IdentifierAdmissionConfig(c.Profile))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("ordinary signout does not withdraw OAuth grant", func(t *testing.T) {
		testOIDCOrdinarySignoutFence(t, ctx, pool, c, executor, effect, issue(t, ""))
	})
	for _, mode := range []string{"commit", "required-outbox-rollback", "expired-before-apply", "oversized-window", "expired-final-window", "pending", "pending-missing-session-history", "pending-retained-row", "pending-mismatched-row"} {
		t.Run(mode, func(t *testing.T) {
			source := issue(t, "")
			s, _ := source.Bindings()
			sibling := issue(t, s.FamilyID)
			ss, _ := sibling.Bindings()
			until := time.Now().UTC().Add(19 * time.Second).Truncate(time.Microsecond)
			if mode == "expired-before-apply" || mode == "oversized-window" || mode == "expired-final-window" {
				if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&until); err != nil {
					t.Fatal(err)
				}
				until = until.UTC().Truncate(time.Microsecond)
				if mode == "oversized-window" {
					until = until.Add(21 * time.Second)
				}
				if mode == "expired-final-window" {
					until = until.Add(time.Second)
				}
			}
			fields, err := OIDCEndSessionFields(source, until)
			if err != nil {
				t.Fatal(err)
			}
			op := oidcEndSessionOperation()
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			p := &oidcEndSessionOwnerPhase{effect: effect, command: command, source: source}
			if mode == "expired-final-window" {
				p.waitUntil = until
			}
			domain, _ := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
			a, _ := auditpg.NewIdentityContributor(auditpg.Config{})
			l, _ := lifecyclepg.NewContributor()
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, a, l, p})
			if err != nil {
				t.Fatal(err)
			}
			configuration := c.Coordinator
			query := kernel.CommandQueryPolicy{Authorization: c.Authorization, Clock: c.Clock, PolicyVersion: c.PolicyVersion}
			configuration.QueryPolicy, configuration.AdmissionPolicy = &query, &query
			coordinator, err := kernel.NewCoordinator(pool, registry, configuration)
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "identity.oauth_server.end_session", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(s.Version, 10), "aggregate.after_version": strconv.FormatUint(s.Version+1, 10), "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.oauth_server.end_session", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "required-outbox-rollback" {
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_oidc_owner_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test required outbox rejection'; END $$; CREATE TRIGGER reject_oidc_owner_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_oidc_owner_outbox()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_oidc_owner_outbox ON public.outbox_messages;DROP FUNCTION public.reject_oidc_owner_outbox()`); err != nil {
						t.Error("owned trigger cleanup", err)
					}
				}()
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "pending") {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); err != nil {
					t.Fatal(err)
				}
				if mode == "pending-missing-session-history" {
					// Restore the same retained table after this isolated failure so
					// sibling controls continue with their real predecessor history.
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE session_store.session_revocations RENAME TO oidc_test_hidden_revocations`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						bounded, stop := context.WithTimeout(context.Background(), time.Second)
						defer stop()
						if _, err := pool.Raw().Exec(bounded, `ALTER TABLE session_store.oidc_test_hidden_revocations RENAME TO session_revocations`); err != nil {
							t.Error("owned history restoration", err)
						}
					}()
				}
				if mode == "pending-retained-row" || mode == "pending-mismatched-row" {
					// A deliberately inconsistent retained owner row, not a real
					// successful logout. No command/effect history is rewritten;
					// participant evidence must prevent a false rollback receipt.
					id, binding := revocationEvidence(b, kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1})
					wire, _, err := encodeRecord(source)
					if err != nil {
						t.Fatal(err)
					}
					record := sha256.Sum256(wire)
					if mode == "pending-mismatched-row" {
						record[0] ^= 1
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.session_revocations(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(s.Version, 10), strconv.FormatUint(s.Version+1, 10), binding[:], record[:]); err != nil {
						t.Fatal(err)
					}
				}
				queryScope := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
				result, recoveryErr := coordinator.RecoverFeatureCommand(ctx, queryScope, caller)
				if p.recovered != 1 || p.applied {
					t.Fatal("pending owner vote not reached", p.recovered, p.applied, recoveryErr)
				}
				if mode == "pending" && result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("unapplied logout did not reconcile", result.Outcome, recoveryErr)
				}
				if mode != "pending" && (recoveryErr == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Outcome == identity.CommitOutcomeNotCommitted) {
					t.Fatal("missing owner history proved a terminal outcome", result.Outcome, recoveryErr)
				}
				if mode == "pending-retained-row" && p.vote != kernel.RecoveryCommitted || mode == "pending-mismatched-row" && p.vote != kernel.RecoveryUnknown {
					t.Fatal("retained OIDC owner branch not exercised", p.vote)
				}
				native, err := NewRepository(pool, c.Repository)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := native.Get(ctx, s.TenantID, s.SessionID)
				if err != nil || stored.Revoked || stored.FamilyRevoked {
					t.Fatal("recovery replayed logout", err)
				}
				return
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			provisional, err := coordinator.ApplyFeature(ctx, work, command)
			var result identity.CommandResult
			if err != nil {
				result, err = coordinator.Abort(work, err)
			} else {
				result, err = coordinator.Commit(work, provisional)
			}
			if !p.applied && mode != "expired-before-apply" && mode != "oversized-window" {
				t.Fatal("actual session mutation not reached", err)
			}
			if mode == "expired-final-window" && !p.finalWindowReached {
				t.Fatal("original-deadline final fence not reached with live source", err)
			}
			native, ce := NewRepository(pool, c.Repository)
			if ce != nil {
				t.Fatal(ce)
			}
			stored, ce := native.Get(ctx, s.TenantID, s.SessionID)
			if ce != nil {
				t.Fatal(ce)
			}
			survivor, ce := native.Get(ctx, ss.TenantID, ss.SessionID)
			if ce != nil || survivor.Revoked || survivor.FamilyRevoked || survivor.CurrentFamilyVersion != ss.FamilyVersion {
				t.Fatal("sibling/family changed", ce)
			}
			var tombstones, audits, events int
			id := mustCommandBytes(t, b.CommandID)
			if ce := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id, int64(audit.OutcomeSucceeded)).Scan(&tombstones, &audits, &events); ce != nil {
				t.Fatal(ce)
			}
			if mode == "required-outbox-rollback" || mode == "expired-before-apply" || mode == "oversized-window" || mode == "expired-final-window" {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted || stored.Revoked || tombstones+audits+events != 0 {
					t.Fatal("required effect allowed partial logout", err, tombstones, audits, events)
				}
				return
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || !stored.Revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != s.FamilyVersion || tombstones != 1 || audits != 1 || events != 1 {
				t.Fatal("exact-session commit failed", err, tombstones, audits, events)
			}
			was, err := native.OIDCEndSessionRevoked(ctx, s.TenantID, s.UserID, s.SessionID)
			if err != nil || !was {
				t.Fatal("RP disposition lost", err)
			}
			was, err = native.OIDCEndSessionRevoked(ctx, ss.TenantID, ss.UserID, ss.SessionID)
			if err != nil || was {
				t.Fatal("RP disposition crossed session", err)
			}
			testOIDCTokenFence(t, ctx, pool, c, effect, source, true)
			testOIDCTokenFence(t, ctx, pool, c, effect, sibling, false)
			testOIDCTokenFence(t, ctx, pool, c, effect, sibling, true, "foreign-user")
			testOIDCTokenFence(t, ctx, pool, c, effect, sibling, true, "wrong-schema")
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2 AND state='revoked'`, string(s.TenantID), s.SessionID); err != nil {
				t.Fatal("prunable source payload", err)
			}
			queryScope := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			recovered, err := coordinator.RecoverFeatureCommand(ctx, queryScope, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original outcome required revoked credential", err, recovered.Outcome)
			}
			was, err = native.OIDCEndSessionRevoked(ctx, s.TenantID, s.UserID, s.SessionID)
			if err != nil || !was {
				t.Fatal("pruning lost RP disposition", err)
			}
			testOIDCTokenFence(t, ctx, pool, c, effect, source, true)
		})
	}
}
