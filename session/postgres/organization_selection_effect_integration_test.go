//go:build integration

package postgres

import (
	"bytes"
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

// This tests the session-owned effect through a real foreign-participant Work,
// native password issuance, SQL CAS and audit/outbox. The test participant and
// organization port are only the declared owner seam, not a proof of actual
// organization policy, membership or a complete backend selection workflow.
type organizationSelectionOwnerPhase struct {
	effect      *OrganizationSelectionEffect
	command     identity.Command
	finalDenied bool
	applied     bool
	recovered   bool
	vote        kernel.RecoveryStatus
	recoveryErr error
}

func (*organizationSelectionOwnerPhase) Descriptor() kernel.ContributorDescriptor {
	// Match the actual go-organization/postgres Contributor contract at f278236.
	// Keep this independent of the effect's accepted-owner implementation so a
	// guessed contract ID cannot make a fake owner pass its own declaration.
	return kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
}
func (*organizationSelectionOwnerPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{session.OrganizationSelectionOperation()}
}
func (p *organizationSelectionOwnerPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
func (p *organizationSelectionOwnerPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, c)
	p.applied = err == nil
	return r, err
}
func (p *organizationSelectionOwnerPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.finalDenied {
		return identity.ForbiddenError{}
	}
	return p.effect.Check(ctx, w, p, c)
}
func (p *organizationSelectionOwnerPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recovered = true
	p.vote, p.recoveryErr = p.effect.Recover(ctx, w, p)
	return p.vote, p.recoveryErr
}

type selectedOrganizationOwnerSeam struct{}

func (selectedOrganizationOwnerSeam) ObserveOrganizationSession(context.Context, session.Session) (OrganizationSessionAuthorityObservation, error) {
	return OrganizationSessionAuthorityObservation{}, session.ErrUnauthenticated
}
func (selectedOrganizationOwnerSeam) RequireOrganizationSession(_ context.Context, _ kernel.Work, _ kernel.FeatureExecutionContributor, s session.Session) error {
	x, err := s.Bindings()
	if err != nil {
		return err
	}
	v, _ := x.Authority.Bindings()
	validA := v.ActiveOrganizationID == "selected-a" && v.Organization.Binding == (session.AuthorityBinding{ScopeKey: "organization:owner-seam-a", Version: 9})
	validB := v.ActiveOrganizationID == "selected-b" && v.Organization.Binding == (session.AuthorityBinding{ScopeKey: "organization:owner-seam-b", Version: 11})
	if !v.Organization.Present || !validA && !validB {
		return identity.ForbiddenError{}
	}
	return nil
}

func testOrganizationSelectionEffect(t *testing.T, ctx context.Context, pool *database.Pool, c IssueExecutorConfig, issue func(*testing.T, string) session.Session) {
	t.Helper()
	history, err := (OrganizationSelectionMigrationSource{Schema: c.Repository.Schema, Version: 101}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	effect, err := NewOrganizationSelectionEffect(c.Repository, OrganizationPasswordSessionAdmission{Profile: IdentifierAdmissionConfig(c.Profile), Authority: selectedOrganizationOwnerSeam{}})
	if err != nil {
		t.Fatal(err)
	}
	native, err := NewRepository(pool, c.Repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"select", "switch", "clear", "stale-cas", "wrong-target", "required-outbox-rollback", "final-denial", "expired", "pending", "pending-retained", "pending-mismatched"} {
		t.Run(mode, func(t *testing.T) {
			source := issue(t, "")
			if mode == "clear" || mode == "switch" {
				spec, _ := source.Bindings()
				v, _ := spec.Authority.Bindings()
				v.ActiveOrganizationID, v.Organization = "selected-a", session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:owner-seam-a", Version: 9}}
				spec.Authority, _ = session.NewAuthoritySnapshot(v)
				source, err = session.NewSession(spec)
				if err != nil {
					t.Fatal(err)
				}
				payload, _, _ := encodeRecord(source)
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1 WHERE tenant_id=$2 AND session_id=$3`, payload, string(spec.TenantID), spec.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			s, _ := source.Bindings()
			originalStored := source
			sibling := issue(t, s.FamilyID)
			ss, _ := sibling.Bindings()
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
			op := session.OrganizationSelectionOperation()
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			selection := session.ActiveOrganizationSelection{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: session.SessionVersion(s.Version), OrganizationID: "selected-a", Authority: session.AuthorityBinding{ScopeKey: "organization:owner-seam-a", Version: 9}}
			if mode == "clear" {
				selection.OrganizationID, selection.Authority = "", session.AuthorityBinding{}
			}
			if mode == "switch" {
				selection.OrganizationID, selection.Authority = "selected-b", session.AuthorityBinding{ScopeKey: "organization:owner-seam-b", Version: 11}
			}
			if mode == "wrong-target" {
				selection.OrganizationID = "foreign"
			}
			transition, err := session.NewOrganizationSelectionCommand(b, source, selection)
			if err != nil {
				t.Fatal(err)
			}
			until := time.Now().UTC().Add(19 * time.Second).Truncate(time.Microsecond)
			if mode == "expired" {
				until = s.LastActivityAt.Add(time.Microsecond)
			}
			fields, err := OrganizationSelectionFields(transition, until)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			p := &organizationSelectionOwnerPhase{effect: effect, command: command, finalDenied: mode == "final-denial"}
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
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "identity.organization.change_active", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(s.Version, 10), "aggregate.after_version": strconv.FormatUint(s.Version+1, 10), "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.organization_changed.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.organization.change_active", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "required-outbox-rollback" {
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_selection_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test selection outbox rejection'; END $$; CREATE TRIGGER reject_selection_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_selection_outbox()`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_selection_outbox ON public.outbox_messages;DROP FUNCTION public.reject_selection_outbox()`); err != nil {
						t.Error("owned trigger cleanup", err)
					}
				}()
			}
			if mode == "stale-cas" {
				newSpec := s
				v, _ := s.Authority.Bindings()
				newSpec.Version++
				v.Session.Version = newSpec.Version
				newSpec.Authority, _ = session.NewAuthoritySnapshot(v)
				originalStored, err = session.NewSession(newSpec)
				if err != nil {
					t.Fatal(err)
				}
				payload, _, _ := encodeRecord(originalStored)
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET version=$1::numeric,record=$2 WHERE tenant_id=$3 AND session_id=$4`, strconv.FormatUint(newSpec.Version, 10), payload, string(s.TenantID), s.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "pending") {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); err != nil {
					t.Fatal(err)
				}
				caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
				if mode != "pending" {
					// Deliberately inconsistent participant evidence beside a
					// pending journal must remain unknown, never reconstruct success.
					transitionSpec, _ := transition.Bindings()
					before, _, _ := encodeRecord(transitionSpec.Source)
					after, _, _ := encodeRecord(transitionSpec.Successor)
					id, binding := organizationSelectionEvidence(b, *plan.Lifecycle)
					sh, nh := sha256.Sum256(before), sha256.Sum256(after)
					if mode == "pending-mismatched" {
						nh[0] ^= 1
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.organization_selections(tenant_id,command_id,purpose,user_id,session_id,before_version,after_version,binding_digest,source_digest,successor_digest,source_record,successor_record) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8,$9,$10,$11::jsonb,$12::jsonb)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(s.Version, 10), strconv.FormatUint(s.Version+1, 10), binding[:], sh[:], nh[:], string(before), string(after)); err != nil {
						t.Fatal(err)
					}
				}
				result, err := coordinator.RecoverFeatureCommand(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}, caller)
				if mode != "pending" {
					wantVote := kernel.RecoveryCommitted
					if mode == "pending-mismatched" {
						wantVote = kernel.RecoveryUnknown
					}
					if err == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Outcome == identity.CommitOutcomeNotCommitted || p.vote != wantVote || p.applied {
						t.Fatal("conflicting selection evidence terminalized pending work", err, p.vote)
					}
					return
				}
				// The coordinator terminalizes abandoned work as a dependency
				// failure: a proved NotCommitted receipt accompanies its error.
				// A non-nil error alone must not hide that terminal outcome.
				if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted || p.applied || !p.recovered || p.vote != kernel.RecoveryNotCommitted || p.recoveryErr != nil {
					t.Fatal("unapplied selection did not reconcile", err, result.Outcome, "owner reached", p.recovered, "vote", p.vote, "owner error", p.recoveryErr)
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
			stored, readErr := native.Get(ctx, s.TenantID, s.SessionID)
			if readErr != nil {
				t.Fatal(readErr)
			}
			survivor, readErr := native.Get(ctx, ss.TenantID, ss.SessionID)
			survivorBytes, _, _ := encodeRecord(survivor.Session)
			wantSibling, _, _ := encodeRecord(sibling)
			if readErr != nil || survivor.Revoked || survivor.FamilyRevoked || survivor.CurrentFamilyVersion != ss.FamilyVersion || !bytes.Equal(survivorBytes, wantSibling) {
				t.Fatal("selection changed sibling/family", readErr)
			}
			var histories, audits, events int
			if readErr := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.organization_selections WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, b.CommandID), int64(audit.OutcomeSucceeded)).Scan(&histories, &audits, &events); readErr != nil {
				t.Fatal(readErr)
			}
			got, _, _ := encodeRecord(stored.Session)
			if mode != "select" && mode != "switch" && mode != "clear" {
				want, _, _ := encodeRecord(originalStored)
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted || !bytes.Equal(got, want) || histories+audits+events != 0 {
					t.Fatal("selection failure leaked partial state", err, histories, audits, events)
				}
				return
			}
			transitionSpec, _ := transition.Bindings()
			want, _, _ := encodeRecord(transitionSpec.Successor)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || !p.applied || !bytes.Equal(got, want) || histories != 1 || audits != 1 || events != 1 {
				t.Fatal("exact selected-session CAS did not commit", err, histories, audits, events)
			}
			if mode == "select" {
				testSelectedOrganizationNativeRevocation(t, ctx, pool, c, transitionSpec.Successor, sibling)
			}
		})
	}
}

func testSelectedOrganizationNativeRevocation(t *testing.T, ctx context.Context, pool *database.Pool, c IssueExecutorConfig, target, sibling session.Session) {
	t.Helper()
	executor, err := newOwnedSessionExecution(pool, c, false)
	if err != nil {
		t.Fatal(err)
	}
	executor.native.revokeOrganizationPassword = &OrganizationPasswordSessionAdmission{Profile: IdentifierAdmissionConfig(c.Profile), Authority: selectedOrganizationOwnerSeam{}}
	s, _ := target.Bindings()
	b := revokeBinding()
	op := session.RevokeOneOperation()
	b.CommandID, _ = identity.NewCommandID()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = s.TenantID, s.UserID, identity.ActorID(s.UserID), s.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	native, err := session.NewRevokeOneCommand(b, target)
	if err != nil {
		t.Fatal(err)
	}
	command, err := MapCommand(native)
	if err != nil {
		t.Fatal(err)
	}
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: s.SessionID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": s.SessionID, "aggregate.before_version": strconv.FormatUint(s.Version, 10), "aggregate.after_version": strconv.FormatUint(s.Version+1, 10), "retention.class": "standard"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: executor.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: executor.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard", RetentionPolicyVersion: 1, BindingDigest: digest, MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}})
	if err != nil {
		t.Fatal(err)
	}
	reservation, _, err := executor.coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	w, err := executor.coordinator.Begin(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.coordinator.Abort(w, identity.UnavailableError{})
	provisional, err := executor.coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		t.Fatal("selected native revocation admission", err)
	}
	result, err := executor.coordinator.Commit(w, provisional)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("selected native revocation commit", err)
	}
	stored, err := executor.native.Get(ctx, s.TenantID, s.SessionID)
	if err != nil || !stored.Revoked || stored.FamilyRevoked {
		t.Fatal("selected native revocation did not invalidate only target", err)
	}
	ss, _ := sibling.Bindings()
	survivor, err := executor.native.Get(ctx, ss.TenantID, ss.SessionID)
	if err != nil || survivor.Revoked || survivor.FamilyRevoked {
		t.Fatal("selected native revocation invalidated sibling", err)
	}
}
