//go:build integration

package passwordpostgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

// Same-Work SQL seams prove real material/kernel/audit/outbox atomicity. They
// are not substitutes for production audit/outbox interoperability qualification.
type passwordAudit struct{ fail bool }

func (*passwordAudit) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "audit/postgres", ContractID: "identity.security_audit", Version: 1}
}
func (p *passwordAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err = w.Exec(ctx, `INSERT INTO public.password_test_audit(event_id,command_id,outcome) VALUES($1,$2,$3)`, r.Record.ID(), r.Record.Attributes()["command.id"], int64(r.Record.Outcome())); err != nil {
			return err
		}
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func (*passwordAudit) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return passwordTestEvidence(ctx, w, "public.password_test_audit")
}

type passwordOutbox struct{ fail bool }

func (*passwordOutbox) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}
}
func (*passwordOutbox) PersistLifecycle(ctx context.Context, w kernel.Work) error {
	records, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err = w.Exec(ctx, `INSERT INTO public.password_test_outbox(command_id,event_type) VALUES($1,$2)`, string(r.CommandID), r.EventType); err != nil {
			return err
		}
	}
	return nil
}
func (p *passwordOutbox) PersistCredentialReplacement(ctx context.Context, w kernel.Work) error {
	r, err := w.StagedCredentialReplacement()
	if err != nil {
		return err
	}
	if err = p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	_, err = w.Exec(ctx, `INSERT INTO public.password_test_epochs(command_id,user_before,user_after,epoch_before,epoch_after,record_before,record_after) SELECT command_id,$1::numeric,$2::numeric,$3::numeric,$4::numeric,$5::numeric,$6::numeric FROM public.password_test_outbox WHERE command_id=$7`, strconv.FormatUint(r.BeforeUserVersion, 10), strconv.FormatUint(r.AfterUserVersion, 10), strconv.FormatUint(r.BeforeAuthorityVersion, 10), strconv.FormatUint(r.AfterAuthorityVersion, 10), strconv.FormatUint(r.BeforeCredentialVersion, 10), strconv.FormatUint(r.Credential.Version, 10), string(recordsCommandID(w)))
	if err != nil {
		return err
	}
	if p.fail {
		return identity.UnavailableError{}
	}
	return nil
}
func recordsCommandID(w kernel.Work) identity.CommandID { b, _ := w.Scope(); return b.CommandID }
func (*passwordOutbox) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return passwordTestEvidence(ctx, w, "public.password_test_outbox")
}
func passwordTestEvidence(ctx context.Context, w kernel.RecoveryWork, table string) (kernel.RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE command_id=$1)`, string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}

type passwordQueryPolicy struct{}

func (passwordQueryPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
}

func testNativePasswordReplacement(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, original primitive.EncodedHash) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.password_test_audit(event_id text PRIMARY KEY,command_id text,outcome bigint);CREATE TABLE public.password_test_outbox(command_id text PRIMARY KEY,event_type text);CREATE TABLE public.password_test_epochs(command_id text PRIMARY KEY,user_before numeric,user_after numeric,epoch_before numeric,epoch_after numeric,record_before numeric,record_after numeric)`); err != nil {
		t.Fatal("native effect fixture failed")
	}
	repo, err := passworddb.NewRepository(pool, passworddb.Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	auditing, outbox := &passwordAudit{}, &passwordOutbox{}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditing, outbox, repo})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: passwordQueryPolicy{}}})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(policy)
	if err != nil {
		t.Fatal("test crypto invalid")
	}
	next, err := crypto.Hash(ctx, []byte("synthetic-replacement-password"))
	if err != nil {
		t.Fatal("replacement fixture unavailable")
	}
	op := repo.FeatureOperations()[0]
	prepare := func(t *testing.T, user identity.UserID, uv, av, cv uint64, hash primitive.EncodedHash) (identity.CommandBinding, identity.Command, kernel.CommandPlan) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		b := identity.CommandBinding{CommandID: id, TenantID: "writer-tenant", UserID: user, ActorID: "actor", ActorKind: authorization.SubjectUser, RecordID: "password", OperationID: op.OperationID, PolicyID: "password-policy", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "replacement-test"}
		fields, err := kernel.CredentialReplacementFields(kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{TenantID: b.TenantID, UserID: user, ID: "password", Owner: "identity/password", Kind: identity.CredentialPassword, Version: cv}, ExpectedUserVersion: uv, ExpectedAuthorityVersion: av})
		if err != nil {
			t.Fatal(err)
		}
		c, err := identity.NewFeaturePasswordHashCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, hash.String())
		if err != nil {
			t.Fatal("native command invalid")
		}
		builder, err := audit.NewBuilder(audit.BuilderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: op.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: "actor"}, Subject: audit.SubjectInput{Type: "credential", ID: "password"}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": "password", "aggregate.before_version": strconv.FormatUint(cv, 10), "aggregate.after_version": strconv.FormatUint(cv+1, 10), "retention.class": "protected"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := kernel.FeatureAuditBindingDigest(b, op, "credential", seed)
		if err != nil {
			t.Fatal(err)
		}
		p, err := coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: op}, SubjectType: "credential", Lifecycle: &kernel.LifecyclePlan{EventType: "password.changed.v1", BeforeVersion: cv, AfterVersion: cv + 1}, Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native preparation failed", err)
		}
		return b, c, p
	}
	seed := func(t *testing.T) identity.UserID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		user := identity.UserID(id)
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,credential_version) VALUES('writer-tenant',$1,'active',3,5);`, string(user)); err != nil {
			t.Fatal("user fixture failed")
		}
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('writer-tenant',$1,'password',1,'identity/password',7,true)`, string(user)); err != nil {
			t.Fatal("reference fixture failed")
		}
		if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('writer-tenant',$1,'password',7,'argon2id',$2)`, string(user), original.String()); err != nil {
			t.Fatal("material fixture failed")
		}
		return user
	}
	execute := func(call context.Context, b identity.CommandBinding, c identity.Command, p kernel.CommandPlan) (identity.CommandResult, error) {
		r, result, err := coordinator.ReserveCommand(call, b, c, p)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			return result, err
		}
		w, err := coordinator.Begin(call, r)
		if err != nil {
			return identity.CommandResult{}, err
		}
		defer coordinator.Abort(w, identity.UnavailableError{})
		result, err = coordinator.ApplyFeature(call, w, c)
		if err != nil {
			return coordinator.Abort(w, err)
		}
		return coordinator.Commit(w, result)
	}
	assertMaterial := func(t *testing.T, user identity.UserID, want primitive.EncodedHash, uv, av, cv uint64) {
		t.Helper()
		got, err := repo.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: "writer-tenant", SubjectID: user})
		if err != nil || got.EncodedHash().String() != want.String() || got.Authority().User.Version != uv || got.Authority().AuthorityVersion != av || got.Authority().Credential.Version != cv {
			t.Fatal("material/reference/user transition not atomic")
		}
	}
	for _, scenario := range []string{"commit", "legacy-predecessor", "material-cas", "corrupt-material", "missing-material", "audit-failure", "outbox-failure", "effect-failure", "cancelled"} {
		t.Run("native password "+scenario, func(t *testing.T) {
			user := seed(t)
			b, c, p := prepare(t, user, 3, 5, 7, next)
			auditing.fail, outbox.fail = scenario == "audit-failure", scenario == "outbox-failure"
			if scenario == "legacy-predecessor" {
				legacyPolicy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Bcrypt, BcryptCost: 4, Limits: policy.Limits()})
				if err != nil {
					t.Fatal(err)
				}
				legacyEngine, err := primitive.New(legacyPolicy)
				if err != nil {
					t.Fatal(err)
				}
				legacy, err := legacyEngine.Hash(ctx, []byte("synthetic-legacy-password"))
				if err != nil {
					t.Fatal("legacy fixture unavailable")
				}
				if _, err = pool.Raw().Exec(ctx, `UPDATE identity_password.credentials SET algorithm='bcrypt',encoded_hash=$2 WHERE tenant_id='writer-tenant' AND user_id=$1`, string(user), legacy.String()); err != nil {
					t.Fatal("legacy fixture failed")
				}
			}
			if scenario == "material-cas" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_password.credentials SET version=8 WHERE tenant_id='writer-tenant' AND user_id=$1`, string(user)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "corrupt-material" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_password.credentials SET encoded_hash='malformed' WHERE tenant_id='writer-tenant' AND user_id=$1`, string(user)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "missing-material" {
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_password.credentials WHERE tenant_id='writer-tenant' AND user_id=$1`, string(user)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "effect-failure" {
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity_password.replacements ADD CONSTRAINT test_reject_effect CHECK(false) NOT VALID`); err != nil {
					t.Fatal("effect failure setup failed")
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity_password.replacements DROP CONSTRAINT test_reject_effect`); err != nil {
						t.Error("effect fixture restore failed")
					}
				}()
			}
			call := ctx
			if scenario == "cancelled" {
				var stop context.CancelFunc
				call, stop = context.WithCancel(ctx)
				stop()
			}
			result, err := execute(call, b, c, p)
			if scenario == "commit" || scenario == "legacy-predecessor" {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("native material commit failed", err)
				}
				assertMaterial(t, user, next, 4, 6, 8)
				// A later replacement must not erase original receipt/effect evidence.
				b2, c2, p2 := prepare(t, user, 4, 6, 8, original)
				r2, err := execute(ctx, b2, c2, p2)
				if err != nil || r2.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("later material replacement failed", err)
				}
				assertMaterial(t, user, original, 5, 7, 9)
				_, replay, err := coordinator.ReserveCommand(ctx, b, c, p)
				if err != nil || replay.Feature == nil || replay.Feature.AfterVersion != 8 || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original receipt lost after overwrite", err)
				}
				var effects, epochs int
				if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.replacements WHERE tenant_id='writer-tenant' AND user_id=$1),(SELECT count(*) FROM public.password_test_epochs WHERE command_id IN ($2,$3))`, string(user), string(b.CommandID), string(b2.CommandID)).Scan(&effects, &epochs); err != nil || effects != 2 || epochs != 2 {
					t.Fatal("retained effects/outbox not committed together")
				}
				return
			}
			if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("unsafe native material committed")
			}
			var uv, av, cv string
			if err := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,c.version::text FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) WHERE u.tenant_id='writer-tenant' AND u.user_id=$1`, string(user)).Scan(&uv, &av, &cv); err != nil || uv != "3" || av != "5" || cv != "7" {
				t.Fatal("native failure advanced kernel authority")
			}
			if scenario == "audit-failure" || scenario == "outbox-failure" || scenario == "effect-failure" || scenario == "cancelled" {
				assertMaterial(t, user, original, 3, 5, 7)
			}
			var out int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.password_test_outbox WHERE command_id=$1`, string(b.CommandID)).Scan(&out); err != nil || out != 0 {
				t.Fatal("rollback left outbox effect")
			}
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_password.replacements WHERE tenant_id='writer-tenant' AND command_id=$1`, key).Scan(&out); err != nil || out != 0 {
				t.Fatal("rollback left material effect evidence")
			}
		})
	}
	auditing.fail, outbox.fail = false, false
	t.Run("native password concurrent one winner", func(t *testing.T) {
		user := seed(t)
		b1, c1, p1 := prepare(t, user, 3, 5, 7, next)
		b2, c2, p2 := prepare(t, user, 3, 5, 7, original)
		var group sync.WaitGroup
		results := make(chan identity.CommandResult, 2)
		errs := make(chan error, 2)
		for _, v := range []struct {
			b identity.CommandBinding
			c identity.Command
			p kernel.CommandPlan
		}{{b1, c1, p1}, {b2, c2, p2}} {
			group.Add(1)
			go func() { defer group.Done(); r, err := execute(ctx, v.b, v.c, v.p); results <- r; errs <- err }()
		}
		group.Wait()
		close(results)
		close(errs)
		wins, failures := 0, 0
		for r := range results {
			if r.Outcome == identity.CommitOutcomeCommitted {
				wins++
			}
		}
		for err := range errs {
			if err != nil {
				failures++
			}
		}
		if wins != 1 || failures != 1 {
			t.Fatal("concurrent material changes did not have one winner")
		}
		got, err := repo.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: "writer-tenant", SubjectID: user})
		if err != nil || got.Authority().Credential.Version != 8 || got.Authority().AuthorityVersion != 6 || got.Authority().User.Version != 4 {
			t.Fatal("concurrent successors inconsistent")
		}
	})
	for _, scenario := range []string{"negative", "retained", "retained-exact", "missing-schema"} {
		t.Run("native password pending recovery "+scenario, func(t *testing.T) {
			user := seed(t)
			b, c, p := prepare(t, user, 3, 5, 7, next)
			_, _, err := coordinator.ReserveCommand(ctx, b, c, p)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			if _, err = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, key); err != nil {
				t.Fatal(err)
			}
			if scenario == "retained" || scenario == "retained-exact" {
				stored := make([]byte, 32)
				if scenario == "retained-exact" {
					data, e := json.Marshal(struct {
						Binding       identity.CommandBinding
						Before, After uint64
					}{b, 7, 8})
					if e != nil {
						t.Fatal(e)
					}
					digest := sha256.Sum256(append([]byte("identity-password-replacement-v1\x00"), data...))
					stored = digest[:]
				}
				if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.replacements VALUES('writer-tenant',$1,$2,$3,'password',7,8,$4)`, key, b.OperationID, string(user), stored); err != nil {
					t.Fatal("retained evidence fixture failed")
				}
			}
			if scenario == "missing-schema" {
				if _, err = pool.Raw().Exec(ctx, `ALTER TABLE identity_password.replacements RENAME TO replacements_hidden`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity_password.replacements_hidden RENAME TO replacements`); err != nil {
						t.Error("recovery fixture restore failed")
					}
				}()
			}
			q := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
			caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}}}
			observed, err := coordinator.RecoverCommand(ctx, q, caller)
			var unavailable identity.UnavailableError
			want := identity.CommitOutcomeInProgress
			if scenario == "negative" {
				want = identity.CommitOutcomeNotCommitted
			}
			if !errors.As(err, &unavailable) || observed.Outcome != want {
				t.Fatal("unsafe material recovery conclusion", err)
			}
		})
	}
}
