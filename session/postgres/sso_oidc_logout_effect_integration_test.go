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
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Exercise the session-owned effect inside the actual coordinator. The
// separate provider service must still prove original provider pairing, sealed
// state persistence and the redirect/return journey.
type ssoOIDCLogoutEffectTestOwner struct {
	effect      *SSOOIDCLogoutEffect
	command     identity.Command
	csrf        session.CSRFToken
	key         session.CSRFKey
	source      session.Session
	dropsMember bool
	applied     bool
	recovered   int
	vote        kernel.RecoveryStatus
}

func (*ssoOIDCLogoutEffectTestOwner) Descriptor() kernel.ContributorDescriptor {
	return kernel.SSOOIDCLogoutDescriptor()
}

func (*ssoOIDCLogoutEffectTestOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.SSOOIDCLogoutOperation()}
}

func (p *ssoOIDCLogoutEffectTestOwner) ValidateFeatureCommand(command identity.Command, _ kernel.CommandPlan) error {
	if command != p.command {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (p *ssoOIDCLogoutEffectTestOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, command, p.csrf, p.key)
	p.applied = err == nil
	return r, err
}

func (p *ssoOIDCLogoutEffectTestOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p.dropsMember {
		s, _ := p.source.Bindings()
		if n, err := w.Exec(ctx, `UPDATE public.sso_session_membership SET active=false WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil || n != 1 {
			return identity.UnavailableError{}
		}
	}
	return p.effect.Check(ctx, w, p, command)
}

func (p *ssoOIDCLogoutEffectTestOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recovered++
	vote, err := p.effect.Recover(ctx, w, p, p.source)
	p.vote = vote
	return vote, err
}

func TestSSOOIDCLogoutEffectRevokesOnlyCurrentSessionWithCSRF(t *testing.T) {
	for _, mode := range []string{"wrong-csrf", "late-membership-loss", "commit", "commit-with-issuer-predecessor", "recover-absent", "recover-matching", "recover-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newSSOSessionAccessFixture(t, "sso-oidc")
			predecessor := "session_revocations_purpose_check"
			if mode == "commit-with-issuer-predecessor" {
				issuerHistory, err := (OIDCEndSessionMigrationSource{Schema: f.repository.Schema, Version: 99}).Load(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(f.ctx, issuerHistory[0].UpSQL()); err != nil {
					t.Fatal("install previous issuer logout purpose", err)
				}
				predecessor = "session_revocations_purpose_oidc_v1"
			}
			history, err := (SSOOIDCLogoutMigrationSource{Schema: f.repository.Schema, Version: 100, ValidationVersion: 101, PreviousConstraint: predecessor}).Load(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range history {
				if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
					t.Fatal("install logout-specific journal purpose", err)
				}
			}
			observed, err := f.reader.Get(f.ctx, f.request)
			if err != nil || !observed.Authenticated {
				t.Fatal("admit actual original session", err)
			}
			s, _ := observed.Session.Bindings()
			fields, err := SSOOIDCLogoutFields(observed.Session, observed.ValidUntil().Truncate(time.Microsecond))
			if err != nil {
				t.Fatal("freeze original provider session and cutoff", err)
			}
			op := kernel.SSOOIDCLogoutOperation()
			b := revokeBinding()
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
			b.ActorKind, b.OperationID, b.SchemaID, b.SchemaVersion = authorization.SubjectUser, op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			effect, err := NewSSOOIDCLogoutEffect(f.repository, f.selection)
			if err != nil {
				t.Fatal(err)
			}
			p := &ssoOIDCLogoutEffectTestOwner{effect: effect, command: command, csrf: f.csrf, key: f.csrfKey, source: observed.Session, dropsMember: mode == "late-membership-loss"}
			if mode == "wrong-csrf" {
				p.csrf, err = session.NewCSRFToken()
				if err != nil {
					t.Fatal(err)
				}
			}
			coordinator, plan := prepareSSOOIDCLogoutEffectTest(t, f, p, b, op, s.Version)
			reservation, _, err := coordinator.ReserveCommand(f.ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "recover-") {
				assertSSOOIDCLogoutEffectRecovery(t, f, p, coordinator, b, s.Version, mode)
				return
			}
			w, err := coordinator.Begin(f.ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			candidate, applyErr := coordinator.ApplyFeature(f.ctx, w, command)
			var terminal identity.CommandResult
			if applyErr != nil {
				terminal, err = coordinator.Abort(w, applyErr)
			} else {
				terminal, err = coordinator.Commit(w, candidate)
			}
			committed := mode == "commit" || mode == "commit-with-issuer-predecessor"
			if p.applied != (mode != "wrong-csrf") || (terminal.Outcome == identity.CommitOutcomeCommitted) != committed || committed && err != nil {
				t.Fatal("logout accepted wrong authority or lost the original effect", terminal.Outcome, applyErr, err)
			}
			observed, err = f.reader.Get(f.ctx, f.request)
			if committed && observed.Authenticated || !committed && (err != nil || !observed.Authenticated) {
				t.Fatal("cookie validity does not match durable outcome", err)
			}
			var revocations, audits, lifecycleEvents int
			var familyState string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
			 (SELECT count(*) FROM session_store.session_revocations WHERE tenant_id=$1 AND session_id=$2 AND purpose=$3),
			 (SELECT state FROM session_store.families WHERE tenant_id=$1 AND family_id=$4),
			 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$5 AND r.outcome=$6),
			 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$5)`, string(s.TenantID), s.SessionID, op.OperationID, s.FamilyID,
				mustCommandBytes(t, b.CommandID), int64(audit.OutcomeSucceeded)).Scan(&revocations, &familyState, &audits, &lifecycleEvents); err != nil {
				t.Fatal(err)
			}
			want := 0
			if committed {
				want = 1
			}
			if familyState != "active" || revocations != want || audits != want || lifecycleEvents != want {
				t.Fatal("unexpected revocation scope or non-atomic evidence", familyState, revocations, audits, lifecycleEvents)
			}
		})
	}
}

func assertSSOOIDCLogoutEffectRecovery(t *testing.T, f ssoSessionAccessFixture, p *ssoOIDCLogoutEffectTestOwner, coordinator *kernel.Coordinator, b identity.CommandBinding, version uint64, mode string) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); err != nil {
		t.Fatal(err)
	}
	wantVote := kernel.RecoveryNotCommitted
	if mode != "recover-absent" {
		// Simulate a surviving native journal without matching audit/outbox
		// votes. Neither a local match nor a mismatch may settle the command.
		l := kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: version, AfterVersion: version + 1}
		id, binding := revocationEvidence(b, l)
		payload, _, err := encodeRecord(p.source)
		if err != nil {
			t.Fatal(err)
		}
		record := sha256.Sum256(payload)
		wantVote = kernel.RecoveryCommitted
		if mode == "recover-mismatch" {
			record[0] ^= 1
			wantVote = kernel.RecoveryUnknown
		}
		if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.session_revocations(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,record_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(version, 10), strconv.FormatUint(version+1, 10), binding[:], record[:]); err != nil {
			t.Fatal(err)
		}
	}
	q, caller := revokeRecoveryInput(b)
	result, err := coordinator.RecoverFeatureCommand(f.ctx, q, caller)
	if p.recovered != 1 || p.applied || p.vote != wantVote {
		t.Fatal("logout recovery replayed mutation or cast an incorrect vote", p.recovered, p.applied, p.vote, err)
	}
	if mode == "recover-absent" {
		if result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("known missing native effect did not reconcile", result.Outcome, err)
		}
	} else if err == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Outcome == identity.CommitOutcomeNotCommitted {
		t.Fatal("partial evidence incorrectly settled the whole command", result.Outcome, err)
	}
	stillActive, err := f.reader.Get(f.ctx, f.request)
	if err != nil || !stillActive.Authenticated {
		t.Fatal("recovery replayed the session mutation", err)
	}
}

func prepareSSOOIDCLogoutEffectTest(t *testing.T, f ssoSessionAccessFixture, p *ssoOIDCLogoutEffectTestOwner, b identity.CommandBinding, op identity.FeatureOperation, version uint64) (*kernel.Coordinator, kernel.CommandPlan) {
	t.Helper()
	domain, _ := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	a, _ := auditpg.NewIdentityContributor(auditpg.Config{})
	l, _ := lifecyclepg.NewContributor()
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, a, l, p})
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyVersion: b.PolicyVersion}
	c, err := kernel.NewCoordinator(f.pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {73}}, QueryPolicy: &query})
	if err != nil {
		t.Fatal(err)
	}
	bldr, _ := audit.NewBuilder(audit.BuilderConfig{})
	const action = "identity.sso.logout_oidc"
	seed, err := bldr.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: action, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(version, 10), "aggregate.after_version": strconv.FormatUint(version+1, 10), "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.PrepareCommandPlan(b, p.command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: version, AfterVersion: version + 1}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
	if err != nil {
		t.Fatal(err)
	}
	return c, plan
}
