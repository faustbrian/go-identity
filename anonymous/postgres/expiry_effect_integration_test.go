//go:build integration

package anonymouspostgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// Owner-component proof, not a public cleanup-service or reference journey.
// Historical fixture aging changes the primary lifecycle/session projections;
// it does not claim that constructing metadata issued a historical credential.
type expiryOwnerPhase struct {
	repository  *anonymouspg.Repository
	domain      *kernel.AnonymousDisposalDomain
	effect      *sessionpg.AnonymousDisposalEffect
	command     identity.Command
	intent      kernel.AnonymousDisposalIntent
	until       time.Time
	applied     bool
	fail        bool
	recovered   int
	nativeVote  kernel.RecoveryStatus
	sessionVote kernel.RecoveryStatus
}

func (*expiryOwnerPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}
func (p *expiryOwnerPhase) FeatureOperations() []identity.FeatureOperation {
	f, _ := p.command.Feature()
	return []identity.FeatureOperation{f.Operation}
}
func (p *expiryOwnerPhase) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	_, err := anonymouspg.ExpirySubject(c)
	return err
}
func (p *expiryOwnerPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, err := p.domain.ApplyExpired(ctx, w, p, c, p.intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.repository.StageExpiredDisposal(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	receipt, err := p.effect.ApplyExpired(ctx, w, p, c)
	p.applied = err == nil
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return receipt, err
}
func (p *expiryOwnerPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if err := p.domain.CheckExpired(ctx, w, p, c, p.intent); err != nil {
		return err
	}
	if err := p.repository.RequireExpiredDisposal(ctx, w, p, c); err != nil {
		return err
	}
	return p.effect.CheckExpired(ctx, w, p, c, p.until)
}
func (p *expiryOwnerPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	p.recovered++
	a, err := p.repository.RecoverExpiredDisposal(ctx, w, p)
	p.nativeVote = a
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.effect.RecoverExpired(ctx, w, p)
	p.sessionVote = b
	if err != nil || a != b {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return a, nil
}

func TestExpiredGuestOwnersCommitOrRollbackTogether(t *testing.T) {
	for _, mode := range []string{"delete", "anonymize", "retain", "pruned", "rollback", "outbox-rollback", "future", "hold-race", "pending", "pending-missing-session-history", "pending-native-row", "pending-session-row", "pending-session-row-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublicAnonymousFixture(t)
			ctx := f.ctx
			policy := anonymous.CleanupAnonymize
			if mode == "delete" {
				policy = anonymous.CleanupDelete
			}
			if mode == "retain" {
				policy = anonymous.CleanupRetain
			}
			c := f.config
			pc, _ := c.Policy.Config()
			pc.Cleanup = policy
			c.Policy, _ = anonymous.NewPolicy(pc)
			issuer, err := anonymouspg.NewSigninService(f.pool, c, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := issuer.Signin(ctx, f.fresh())
			if err != nil {
				t.Fatal("genuine guest prerequisite", err)
			}
			s, _ := issued.Session.Session.Bindings()
			seedAnonymousDisposalSiblings(t, f, issued.Session.Session)
			shiftHours := int64(48)
			if mode == "future" {
				shiftHours = 0
			}
			shift := time.Duration(shiftHours) * time.Hour
			// Age all authoritative session timestamps together; no clock bypass
			// or expired credential is used to authorize the maintenance command.
			rows, err := f.pool.Raw().Query(ctx, `SELECT session_id,record::text FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID))
			if err != nil {
				t.Fatal(err)
			}
			type aged struct {
				id   string
				wire []byte
			}
			var records []aged
			for rows.Next() {
				var id string
				var wire []byte
				if err := rows.Scan(&id, &wire); err != nil {
					t.Fatal(err)
				}
				var data map[string]json.RawMessage
				if err := json.Unmarshal(wire, &data); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"IssuedAt", "LastActivityAt"} {
					var at time.Time
					if err := json.Unmarshal(data[field], &at); err != nil {
						t.Fatal(err)
					}
					data[field], _ = json.Marshal(at.Add(-shift))
				}
				var auth map[string]json.RawMessage
				if err := json.Unmarshal(data["Authentication"], &auth); err != nil {
					t.Fatal(err)
				}
				var at time.Time
				if err := json.Unmarshal(auth["AnonymousAt"], &at); err != nil {
					t.Fatal(err)
				}
				auth["AnonymousAt"], _ = json.Marshal(at.Add(-shift))
				data["Authentication"], _ = json.Marshal(auth)
				wire, _ = json.Marshal(data)
				records = append(records, aged{id: id, wire: wire})
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			for _, r := range records {
				if _, err := f.pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3::jsonb,expires_at=to_char((expires_at::timestamptz-$4::bigint*interval '1 hour') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US')||'000Z' WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), r.id, r.wire, shiftHours); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.pool.Raw().Exec(ctx, `UPDATE session_store.families SET issued_at=to_char((issued_at::timestamptz-$3::bigint*interval '1 hour') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US')||'000Z' WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID), shiftHours); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Raw().Exec(ctx, `UPDATE anonymous_store.subjects SET created_at=created_at-$3::bigint*interval '1 hour',expires_at=expires_at-$3::bigint*interval '1 hour' WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID), shiftHours); err != nil {
				t.Fatal(err)
			}
			storedSessions, _ := sessionpg.NewRepository(f.pool, c.Sessions)
			for _, r := range records {
				if _, err := storedSessions.Get(ctx, s.TenantID, r.id); err != nil {
					t.Fatal("historical session fixture violates its actual owner", err)
				}
			}
			if mode == "pruned" {
				if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Raw().Exec(ctx, `UPDATE session_store.families SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			base := kernel.AnonymousDisposalMigrationSource{Base: kernel.DirectoryAuthorityMigrationSource{Base: kernel.AnonymousIdentityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14}, Version: 15, GlobalAuthorityID: "anonymous-deployment", TenantIDs: []identity.TenantID{"tenant-a", "AAAAAAAAAAAAAAAAAAAAAQ"}}, Version: 16}
			for _, source := range []migrations.Source{kernel.AnonymousExpiryDisposalMigrationSource{Base: base, Version: 62}, sessionpg.AnonymousExpiryMigrationSource{Schema: "session_store", Version: 63}, anonymouspg.ExpiryMigrationSource{Schema: "anonymous_store", Version: 64}} {
				history, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range history {
					if step.Version() >= 62 {
						if _, err := f.pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
							t.Fatal("populated forward expiry history", err)
						}
					}
				}
			}
			directory, _ := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: 3 * time.Second})
			domain, _ := kernel.NewAnonymousDisposalDomain(directory)
			repository, _ := anonymouspg.NewRepository(f.pool, c.Repository)
			subject, err := repository.Read(ctx, anonymous.SubjectQuery{TenantID: s.TenantID, UserID: s.UserID})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := directory.GetAnonymousDisposal(ctx, identity.UserStatusQuery{TenantID: s.TenantID, UserID: s.UserID})
			if err != nil {
				t.Fatal(err)
			}
			action := kernel.AnonymousDisposeAnonymize
			if mode == "delete" {
				action = kernel.AnonymousDisposeDelete
			}
			if mode == "retain" {
				action = kernel.AnonymousDisposeRetain
			}
			intent := kernel.AnonymousDisposalIntent{Snapshot: snapshot, Action: action, RetentionPolicyVersion: 1}
			fields, _ := anonymouspg.ExpiryFields(subject)
			owned, _ := kernel.AnonymousDisposalFields(intent)
			fields = append(fields, owned...)
			id, _ := identity.NewCommandID()
			b := identity.CommandBinding{CommandID: id, TenantID: s.TenantID, UserID: s.UserID, RecordID: string(s.UserID), ActorID: "guest-maintenance", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.anonymous.expire", SchemaID: "identity.anonymous.expire.native-v1", SchemaVersion: 1, PolicyID: "guest-maintenance", PolicyVersion: 1, CorrelationID: string(id)}
			op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			effect, _ := sessionpg.NewAnonymousDisposalEffect(c.Sessions)
			phase := &expiryOwnerPhase{repository: repository, domain: domain, effect: effect, command: command, intent: intent, until: time.Now().UTC().Add(19 * time.Second), fail: mode == "rollback"}
			a, _ := auditpg.NewIdentityContributor(auditpg.Config{})
			l, _ := lifecyclepg.NewContributor()
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, a, l, phase})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(f.pool, registry, c.Coordinator)
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "anonymous", ID: string(b.UserID)}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "anonymous", "aggregate.id": string(b.UserID), "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := kernel.FeatureAuditBindingDigest(b, op, "anonymous", seed)
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "anonymous", Feature: &kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "anonymous.expired.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "hold-race" {
				if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET legal_hold=true,legal_hold_version=legal_hold_version+1 WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "outbox-rollback" {
				if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_expiry_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test required outbox rejection'; END $$; CREATE TRIGGER reject_expiry_outbox BEFORE INSERT ON public.outbox_messages FOR EACH ROW EXECUTE FUNCTION public.reject_expiry_outbox()`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					bounded, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER reject_expiry_outbox ON public.outbox_messages;DROP FUNCTION public.reject_expiry_outbox()`); err != nil {
						t.Error("owned expiry trigger cleanup", err)
					}
				})
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "pending") {
				// A genuine unapplied reservation expires in this isolated fixture.
				// No committed receipt or effects are rewritten into pending state.
				if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustExpiryCommandBytes(t, id)); err != nil {
					t.Fatal(err)
				}
				if mode == "pending-missing-session-history" {
					if _, err := f.pool.Raw().Exec(ctx, `DROP TABLE session_store.anonymous_disposals`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "pending-native-row" {
					// Deliberately inconsistent retained evidence, not a committed
					// disposal: kernel/session/audit/outbox effects remain absent.
					before, _ := subject.Record()
					if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO anonymous_store.disposals(tenant_id,purpose,command_id,user_id,before_version,after_version,terminal_state,cleanup,created_at,expires_at) VALUES($1,$2,$3,$4,1,2,5,2,$5,$6)`, string(b.TenantID), b.OperationID, mustExpiryCommandBytes(t, id), string(b.UserID), before.CreatedAt, before.ExpiresAt); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "pending-session-row" || mode == "pending-session-row-mismatch" {
					binding, chain, result := expiryZeroSessionEvidence(t, b)
					if mode == "pending-session-row-mismatch" {
						result[0] ^= 1
					}
					if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO session_store.anonymous_disposals(tenant_id,command_id,purpose,user_id,source_id,before_version,after_version,revoked_count,family_count,effects_digest,binding_digest,result_digest) VALUES($1,$2,$3,$4,NULL,1,2,0,0,$5,$6,$7)`, string(b.TenantID), mustExpiryCommandBytes(t, id), b.OperationID, string(b.UserID), chain[:], binding[:], result[:]); err != nil {
						t.Fatal(err)
					}
				}
				query := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
				caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
				result, recoveryErr := coordinator.RecoverFeatureCommand(ctx, query, caller)
				if phase.recovered != 1 || phase.applied {
					t.Fatal("pending recovery did not invoke owner evidence only", phase.recovered, phase.applied, recoveryErr)
				}
				if mode == "pending" && result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("unapplied reservation did not reconcile", result.Outcome, recoveryErr)
				}
				if mode != "pending" && (recoveryErr == nil || result.Outcome == identity.CommitOutcomeCommitted || result.Outcome == identity.CommitOutcomeNotCommitted) {
					t.Fatal("missing owner history proved a terminal outcome", result.Outcome, recoveryErr)
				}
				if mode == "pending-native-row" && (phase.nativeVote != kernel.RecoveryCommitted || phase.sessionVote != kernel.RecoveryNotCommitted) || mode == "pending-session-row" && (phase.nativeVote != kernel.RecoveryNotCommitted || phase.sessionVote != kernel.RecoveryCommitted) || mode == "pending-session-row-mismatch" && phase.sessionVote != kernel.RecoveryUnknown {
					t.Fatal("retained-row owner branch not exercised", phase.nativeVote, phase.sessionVote)
				}
				var status string
				var state, active, effects int
				wantEffects := 0
				if mode == "pending-native-row" {
					wantEffects = 1
				}
				if err := f.pool.Raw().QueryRow(ctx, `SELECT u.status,a.state,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND state='active'),(SELECT count(*) FROM identity.anonymous_disposals WHERE command_id=$3)+(SELECT count(*) FROM anonymous_store.disposals WHERE command_id=$3) FROM identity.users u JOIN anonymous_store.subjects a USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID), mustExpiryCommandBytes(t, id)).Scan(&status, &state, &active, &effects); err != nil || status != "active" || state != 1 || active != 18 || effects != wantEffects {
					t.Fatal("recovery executed protected disposal", err, status, state, active, effects)
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
			if !phase.applied && mode != "future" && mode != "hold-race" {
				t.Fatal("actual owner effects not reached", err)
			}
			var status string
			var state int16
			var active, native, ownedCount, sessionCount, attrs int
			if e := f.pool.Raw().QueryRow(ctx, `SELECT u.status,a.state,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=u.tenant_id AND user_id=u.user_id AND state='active'),(SELECT count(*) FROM identity.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM anonymous_store.disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM session_store.anonymous_disposals WHERE tenant_id=u.tenant_id AND user_id=u.user_id),(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=u.tenant_id AND user_id=u.user_id) FROM identity.users u JOIN anonymous_store.subjects a USING(tenant_id,user_id) WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)).Scan(&status, &state, &active, &native, &ownedCount, &sessionCount, &attrs); e != nil {
				t.Fatal(e)
			}
			if mode == "rollback" || mode == "outbox-rollback" || mode == "future" || mode == "hold-race" {
				if err == nil || result.Outcome == identity.CommitOutcomeCommitted || status != "active" || state != 1 || active != 18 || native+ownedCount+sessionCount != 0 || attrs == 0 {
					t.Fatal("partial expiry escaped rollback", err, status, state, active, native, ownedCount, sessionCount, attrs)
				}
				var audits, events int
				commandID, _ := base64.RawURLEncoding.Strict().DecodeString(string(id))
				if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, commandID, int64(audit.OutcomeSucceeded)).Scan(&audits, &events); err != nil || audits != 0 || events != 0 {
					t.Fatal("denied expiry retained successful required effects", err, audits, events)
				}
				return
			}
			wantStatus, wantState := "anonymized", anonymous.StateAnonymized
			if mode == "delete" {
				wantStatus, wantState = "deleted", anonymous.StateExpired
			}
			if mode == "retain" {
				wantStatus, wantState = "deleted", anonymous.StateRetained
			}
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || status != wantStatus || state != int16(wantState) || active != 0 || native != 1 || ownedCount != 1 || sessionCount != 1 || (mode == "retain") != (attrs > 0) {
				t.Fatal("protected owners disagree", err, status, state, active, native, ownedCount, sessionCount, attrs)
			}
			var sourceID *string
			var revoked, families int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT source_id,revoked_count,family_count FROM session_store.anonymous_disposals WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)).Scan(&sourceID, &revoked, &families); err != nil {
				t.Fatal(err)
			}
			wantCount, wantFamilies := 18, 19
			if mode == "pruned" {
				wantCount, wantFamilies = 0, 0
			}
			if sourceID != nil || revoked != wantCount || families != wantFamilies {
				t.Fatal("invented source or incomplete set", revoked, families)
			}
			_, temporalErr := f.pool.Raw().Exec(ctx, `UPDATE anonymous_store.disposals SET expires_at=created_at WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID))
			var constraint *pgconn.PgError
			if !errors.As(temporalErr, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "disposals_check" {
				t.Fatal("expiry suffix removed the retained temporal-integrity guard")
			}
			query := identity.RecoveryQuery{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			recovered, err := coordinator.RecoverFeatureCommand(ctx, query, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original expiry recovery", err, recovered.Outcome)
			}
		})
	}
}

// Independent serialized fixture for the session owner's published retained
// checksum format (revocationEvidence/anonymousDisposalSessionDigest). Only a
// zero-count, source-free row is seeded, intentionally without any actual owner
// mutation. The coordinator must reject the resulting participant disagreement.
func expiryZeroSessionEvidence(t *testing.T, b identity.CommandBinding) ([32]byte, [32]byte, [32]byte) {
	t.Helper()
	encode := func(v any) []byte {
		wire, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	binding := sha256.Sum256(append([]byte("identity-session-family-revocation-v1\x00"), encode(struct {
		Binding       identity.CommandBinding
		Before, After uint64
	}{b, 1, 2})...))
	chain := [32]byte{1}
	base := sha256.Sum256(append([]byte("identity-password-reset-session-effect-v1\x00"), encode(struct {
		Binding                     [32]byte
		User, Authority, Credential uint64
		Count                       uint32
		Chain                       [32]byte
	}{binding, 0, 0, 0, 0, chain})...))
	result := sha256.Sum256(append([]byte("identity-password-reset-session-chain-v1\x00"), encode(struct {
		Previous [32]byte
		ID       string
		Version  uint64
	}{base, "", 0})...))
	return binding, chain, result
}

func mustExpiryCommandBytes(t *testing.T, id identity.CommandID) []byte {
	t.Helper()
	wire, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err != nil || len(wire) != 16 {
		t.Fatal("invalid command fixture")
	}
	return wire
}
