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
	migrations "github.com/faustbrian/go-migrations/v3"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Exercise the session-owned effect inside the actual coordinator. The
// separate provider service must still prove original provider pairing, sealed
// state persistence and the redirect/return journey.
type enterpriseLogoutSessionEffect interface {
	Apply(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command, session.CSRFToken, session.CSRFKey) (identity.FeatureReceipt, error)
	Check(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error
	Recover(context.Context, kernel.RecoveryWork, kernel.FeatureExecutionContributor, session.Session) (kernel.RecoveryStatus, error)
}

type enterpriseLogoutEffectTestOwner struct {
	effect      enterpriseLogoutSessionEffect
	profile     enterpriseLogoutSessionTestProfile
	command     identity.Command
	csrf        session.CSRFToken
	key         session.CSRFKey
	source      session.Session
	dropsMember bool
	advanceMFA  bool
	applied     bool
	recovered   int
	vote        kernel.RecoveryStatus
}

func (p *enterpriseLogoutEffectTestOwner) Descriptor() kernel.ContributorDescriptor {
	return p.profile.descriptor
}

func (p *enterpriseLogoutEffectTestOwner) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.profile.operation}
}

func (p *enterpriseLogoutEffectTestOwner) ValidateFeatureCommand(command identity.Command, _ kernel.CommandPlan) error {
	if command != p.command {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (p *enterpriseLogoutEffectTestOwner) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, command, p.csrf, p.key)
	p.applied = err == nil
	return r, err
}

func (p *enterpriseLogoutEffectTestOwner) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	s, _ := p.source.Bindings()
	if p.dropsMember {
		if n, err := w.Exec(ctx, `UPDATE public.sso_session_membership SET active=false WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil || n != 1 {
			return identity.UnavailableError{}
		}
	}
	if p.advanceMFA {
		// A later generation can still be empty. It cannot replace the one
		// originally authenticated by the session.
		if n, err := w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND active_factors=0`, string(s.TenantID), string(s.UserID)); err != nil || n != 1 {
			return identity.UnavailableError{}
		}
	}
	return p.effect.Check(ctx, w, p, command)
}

func (p *enterpriseLogoutEffectTestOwner) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recovered++
	vote, err := p.effect.Recover(ctx, w, p, p.source)
	p.vote = vote
	return vote, err
}

type enterpriseLogoutSessionTestProfile struct {
	method      string
	auditAction string
	operation   identity.FeatureOperation
	descriptor  kernel.ContributorDescriptor
	fields      func(session.Session, time.Time) ([]identity.FeatureField, error)
	effect      func(ssoSessionAccessFixture) (enterpriseLogoutSessionEffect, error)
	history     func(context.Context, string, string) ([]migrations.Migration, error)
}

func TestSSOOIDCLogoutEffectRevokesOnlyCurrentSessionWithCSRF(t *testing.T) {
	assertEnterpriseLogoutEffect(t, enterpriseLogoutSessionTestProfile{
		method: "sso-oidc", auditAction: "identity.sso.logout_oidc", operation: kernel.SSOOIDCLogoutOperation(), descriptor: kernel.SSOOIDCLogoutDescriptor(), fields: SSOOIDCLogoutFields,
		effect: func(f ssoSessionAccessFixture) (enterpriseLogoutSessionEffect, error) {
			return NewSSOOIDCLogoutEffect(f.repository, f.selection)
		},
		history: func(ctx context.Context, schema, previous string) ([]migrations.Migration, error) {
			return (SSOOIDCLogoutMigrationSource{Schema: schema, Version: 100, ValidationVersion: 101, PreviousConstraint: previous}).Load(ctx)
		},
	})
}

func TestSSOSAMLLogoutStartEffectRevokesOriginalWithoutProviderReply(t *testing.T) {
	assertEnterpriseLogoutEffect(t, enterpriseLogoutSessionTestProfile{
		method: "sso-saml", auditAction: "identity.sso.logout_saml", operation: kernel.SSOSAMLLogoutStartOperation(), descriptor: kernel.SSOSAMLLogoutStartDescriptor(), fields: SSOSAMLLogoutStartFields,
		effect: func(f ssoSessionAccessFixture) (enterpriseLogoutSessionEffect, error) {
			return NewSSOSAMLLogoutStartEffect(f.repository, f.saml)
		},
		history: func(ctx context.Context, schema, previous string) ([]migrations.Migration, error) {
			return (SSOSAMLLogoutStartMigrationSource{Schema: schema, Version: 100, ValidationVersion: 101, PreviousConstraint: previous}).Load(ctx)
		},
	})
}

func assertEnterpriseLogoutEffect(t *testing.T, profile enterpriseLogoutSessionTestProfile) {
	t.Helper()
	modes := []string{"wrong-csrf", "late-membership-loss", "late-factor-generation", "commit", "commit-with-issuer-predecessor", "recover-absent", "recover-matching", "recover-mismatch"}
	if profile.method == "sso-saml" {
		modes = append(modes, "commit-with-enterprise-oidc-predecessor")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f := newSSOSessionAccessFixture(t, profile.method)
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
			if mode == "commit-with-enterprise-oidc-predecessor" {
				prior, err := (SSOOIDCLogoutMigrationSource{Schema: f.repository.Schema, Version: 98, ValidationVersion: 99, PreviousConstraint: predecessor}).Load(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range prior {
					if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
						t.Fatal("install previous enterprise OIDC logout journal purpose", err)
					}
				}
				predecessor = "session_revocations_purpose_sso_oidc_v1"
			}
			var priorJournalPurpose string
			if profile.method == "sso-saml" && strings.HasPrefix(mode, "commit") {
				priorJournalPurpose = "identity.session.revoke-one"
				if mode == "commit-with-issuer-predecessor" {
					priorJournalPurpose = "identity.oauth-server.end-session"
				} else if mode == "commit-with-enterprise-oidc-predecessor" {
					priorJournalPurpose = "identity.sso.oidc-logout"
				}
				seedPredecessorLogoutJournal(t, f, priorJournalPurpose)
			}
			history, err := profile.history(f.ctx, f.repository.Schema, predecessor)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range history {
				if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
					t.Fatal("install logout-specific journal purpose", err)
				}
			}
			if priorJournalPurpose != "" {
				var original bool
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT purpose=$1 AND before_version=5 AND after_version=6
				 AND binding_digest=decode(repeat('02',32),'hex') AND record_digest=decode(repeat('03',32),'hex')
				 FROM session_store.session_revocations WHERE tenant_id='guest-tenant' AND session_id='earlier-session'`, priorJournalPurpose).Scan(&original); err != nil || !original {
					t.Fatal("upgrading retained history changed the original revocation", err)
				}
			}
			observed, err := f.reader.Get(f.ctx, f.request)
			if err != nil || !observed.Authenticated {
				t.Fatal("admit actual original session", err)
			}
			s, _ := observed.Session.Bindings()
			fields, err := profile.fields(observed.Session, observed.ValidUntil().Truncate(time.Microsecond))
			if err != nil {
				t.Fatal("freeze original provider session and cutoff", err)
			}
			op := profile.operation
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
			effect, err := profile.effect(f)
			if err != nil {
				t.Fatal(err)
			}
			p := &enterpriseLogoutEffectTestOwner{effect: effect, profile: profile, command: command, csrf: f.csrf, key: f.csrfKey, source: observed.Session,
				dropsMember: mode == "late-membership-loss", advanceMFA: mode == "late-factor-generation"}
			if mode == "wrong-csrf" {
				p.csrf, err = session.NewCSRFToken()
				if err != nil {
					t.Fatal(err)
				}
			}
			coordinator, plan := prepareEnterpriseLogoutEffectTest(t, f, p, b, op, s.Version)
			reservation, _, err := coordinator.ReserveCommand(f.ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "recover-") {
				assertEnterpriseLogoutEffectRecovery(t, f, p, coordinator, b, s.Version, mode)
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
			committed := strings.HasPrefix(mode, "commit")
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

func seedPredecessorLogoutJournal(t *testing.T, f ssoSessionAccessFixture, purpose string) {
	t.Helper()
	for _, query := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('03',16),'hex'),'guest-tenant',$1,decode(repeat('01',32),'hex'),1,decode('01','hex'))`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('03',16),'hex'),'guest-tenant',$1)`,
		`INSERT INTO session_store.session_revocations(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,record_digest) VALUES('guest-tenant',decode(repeat('03',16),'hex'),$1,'enterprise-user','earlier-session',5,6,decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'))`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, query, purpose); err != nil {
			t.Fatal("seed a retained native revocation before migration", err)
		}
	}
}

func assertEnterpriseLogoutEffectRecovery(t *testing.T, f ssoSessionAccessFixture, p *enterpriseLogoutEffectTestOwner, coordinator *kernel.Coordinator, b identity.CommandBinding, version uint64, mode string) {
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

func prepareEnterpriseLogoutEffectTest(t *testing.T, f ssoSessionAccessFixture, p *enterpriseLogoutEffectTestOwner, b identity.CommandBinding, op identity.FeatureOperation, version uint64) (*kernel.Coordinator, kernel.CommandPlan) {
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
	action := p.profile.auditAction
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
