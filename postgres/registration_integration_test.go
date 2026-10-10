//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This native material seam proves kernel ownership and transactional composition,
// not a password workflow, HIBP implementation or audit-provider interoperability.
type registrationTestPhase struct {
	domain                         *PasswordRegistrationDomain
	expected                       identity.Command
	intent                         PasswordRegistrationIntent
	fail, foreign, skip, duplicate bool
}

func (*registrationTestPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *registrationTestPhase) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.expected.PasswordSignupFeature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *registrationTestPhase) ValidateFeatureCommand(c identity.Command, plan CommandPlan) error {
	if c != p.expected {
		return invalidPlan()
	}
	return nil
}
func (p *registrationTestPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if !p.skip {
		if p.foreign {
			s, _ := c.PasswordSignupFeature()
			hash, cookie, _ := c.PasswordSignupCustody()
			c, _ = identity.NewFeaturePasswordSignupCommand(s, hash, cookie)
		}
		if _, err := p.domain.Apply(ctx, w, p, c, p.intent); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if p.duplicate {
			_, _ = p.domain.Apply(ctx, w, p, c, p.intent)
		}
		b, _, _, err := w.FeatureScope(p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_registration_material(command_id,user_id) VALUES($1,$2)`, string(b.CommandID), string(p.intent.Creation.Binding.UserID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	s, _ := c.PasswordSignupFeature()
	return identity.FeatureReceipt{Operation: s.Operation}, nil
}
func (*registrationTestPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_registration_material")
}

func TestPasswordRegistrationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test database required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("isolated cluster unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if admin.Close(cleanup) != nil {
			t.Error("admin cleanup failed")
		}
	}()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_registration_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	source := PasswordRegistrationMigrationSource{Base: CredentialMigrationSource{Base: IdentifierMutationMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("registration history installation", err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("registration history replay", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	repo, err := NewRepository(pool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := NewPasswordRegistrationDomain(repo, PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE); CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE); CREATE TABLE public.identity_test_registration_material(command_id text PRIMARY KEY,user_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "native-failure", "audit-failure", "outbox-failure", "foreign-command", "missing-domain", "duplicate-domain", "changed-intent", "changed-attributes", "changed-actor", "changed-actor-kind", "changed-command-id", "retired-identifier", "canonical-duplicate", "foreign-tenant-value", "concurrent", "disconnect-before", "disconnect-after"} {
		t.Run(mode, func(t *testing.T) {
			selectedPool, selectedRepo, selectedDomain := pool, repo, domain
			var fault *registrationCommitFault
			if strings.HasPrefix(mode, "disconnect-") {
				fault = &registrationCommitFault{before: mode == "disconnect-before"}
				var err error
				selectedPool, err = database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 3, Configure: func(c *database.PoolConfig) error {
					// ConnString preserves the parsed DSN, not the database selected
					// later by Configure. Both pools must target this owned fixture.
					c.ConnConfig.Database = name
					c.ConnConfig.DialFunc = fault.dial
					return nil
				}})
				if err != nil {
					t.Fatal("fault pool unavailable")
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
					defer stop()
					if selectedPool.Close(cleanup) != nil {
						t.Error("fault pool cleanup")
					}
				}()
				selectedRepo, err = NewRepository(selectedPool, Config{MaximumDuration: time.Second, AttributeSchemas: []identity.AttributeSchema{storageSchema()}})
				if err != nil {
					t.Fatal(err)
				}
				selectedDomain, err = NewPasswordRegistrationDomain(selectedRepo, PasswordRegistrationDomainConfig{ComparisonProfile: "email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: {1}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			b := codecBinding()
			b.CommandID, _ = identity.NewCommandID()
			u, _ := identity.NewSubjectID()
			b.UserID = identity.UserID(u)
			b.SchemaID = "fields"
			creation := identity.CreateUserCommand{Binding: b, Status: identity.StatusActive, Attributes: storageValues()}
			intent := PasswordRegistrationIntent{Creation: creation, Identifier: identity.Identifier{ID: identity.IdentifierID(u), UserID: identity.UserID(u), Kind: identity.IdentifierEmail, CanonicalValue: string(u) + "@example.test", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: identity.UserID(u), Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
			fields, err := PasswordRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
			b.UserID, b.AnonymousFlowID = "", string(b.CommandID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			cookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
			hash := "$synthetic$prepared-registration-verifier"
			command, err := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, hash, cookie)
			if err != nil {
				t.Fatal(err)
			}
			phase := &registrationTestPhase{domain: selectedDomain, expected: command, intent: intent, fail: mode == "native-failure", foreign: mode == "foreign-command", skip: mode == "missing-domain", duplicate: mode == "duplicate-domain"}
			if mode == "changed-intent" {
				phase.intent.Identifier.CanonicalValue = "other@example.test"
			}
			if mode == "changed-attributes" {
				phase.intent.Creation.Attributes = storageValues()
				phase.intent.Creation.Attributes[0].Name = "unknown"
			}
			// Keep the original feature command intact. These otherwise valid
			// creation bindings must independently match its frozen custody.
			switch mode {
			case "changed-actor":
				phase.intent.Creation.Binding.ActorID = "different-actor"
			case "changed-actor-kind":
				phase.intent.Creation.Binding.ActorKind = "api-key"
			case "changed-command-id":
				phase.intent.Creation.Binding.CommandID, _ = identity.NewCommandID()
			}
			if strings.HasPrefix(mode, "changed-actor") || mode == "changed-command-id" {
				if _, e := PasswordRegistrationFields(phase.intent); e != nil {
					t.Fatal("binding substitution must remain structurally valid", e)
				}
			}
			if mode == "canonical-duplicate" || mode == "foreign-tenant-value" {
				tenant := b.TenantID
				if mode == "foreign-tenant-value" {
					tenant = "another-tenant"
				}
				old := "existing-" + string(u)
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1);`, string(tenant), old); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,version,verification_state,verification_version) VALUES($1,$2,$2,'email',$3,1,1,1)`, string(tenant), old, intent.Identifier.CanonicalValue); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "retired-identifier" {
				digest := identifierReuseDigest([32]byte{1}, b.TenantID, intent.Identifier.Kind, intent.Identifier.CanonicalValue)
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'deleted',1)`, string(b.TenantID), "retired-"+string(u)); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifier_retirements(tenant_id,user_id,identifier_id,kind,record_version,verification_version,removed,command_id,key_version,value_digest,retired_at,reuse_until) VALUES($1,$2,$3,'email',1,1,true,$4,1,$5,clock_timestamp(),clock_timestamp()+interval '1 day')`, string(b.TenantID), "retired-"+string(u), "retired-"+string(u), string(b.CommandID), digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			audits, outbox := &recoveryAuditPhase{}, &recoveryLifecyclePhase{}
			audits.fail, outbox.fail = mode == "audit-failure", mode == "outbox-failure"
			registry, err := NewContributorRegistry([]Contributor{selectedRepo, audits, outbox, phase})
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(selectedPool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 500 * time.Millisecond, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.SubjectType, plan.Feature = registry.Descriptors(), "user", &FeatureRegistration{Contributor: phase.Descriptor(), Operation: op}
			plan.Lifecycle = &LifecyclePlan{EventType: "user.created.v1"}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = op.OperationID, "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, "user", b.AnonymousFlowID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, "user", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = c.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			execute := func(c *Coordinator, b identity.CommandBinding, command identity.Command, plan CommandPlan) (identity.CommandResult, error) {
				r, history, err := c.ReserveCommand(ctx, b, command, plan)
				if err != nil || r.state == nil {
					return history, err
				}
				w, err := c.Begin(ctx, r)
				if err != nil {
					return identity.CommandResult{}, err
				}
				result, err := c.ApplyFeature(ctx, w, command)
				if err == nil {
					return c.Commit(w, result)
				}
				result, _ = c.Abort(w, err)
				return result, err
			}
			var result identity.CommandResult
			if mode == "concurrent" {
				otherIntent := intent
				otherUser, _ := identity.NewSubjectID()
				otherBinding := b
				otherBinding.CommandID, _ = identity.NewCommandID()
				otherBinding.AnonymousFlowID = string(otherBinding.CommandID)
				otherIntent.Creation.Binding.CommandID = otherBinding.CommandID
				otherIntent.Creation.Binding.UserID = identity.UserID(otherUser)
				otherIntent.Identifier.ID, otherIntent.Identifier.UserID = identity.IdentifierID(otherUser), identity.UserID(otherUser)
				otherIntent.Credential.UserID = identity.UserID(otherUser)
				otherFields, e := PasswordRegistrationFields(otherIntent)
				if e != nil {
					t.Fatal(e)
				}
				otherCommand, e := identity.NewFeaturePasswordSignupCommand(identity.FeatureCommandSpec{Binding: otherBinding, Operation: op, Fields: otherFields}, hash, cookie)
				if e != nil {
					t.Fatal(e)
				}
				otherPhase := &registrationTestPhase{domain: domain, expected: otherCommand, intent: otherIntent}
				otherRegistry, e := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, otherPhase})
				if e != nil {
					t.Fatal(e)
				}
				otherCoordinator, e := NewCoordinator(pool, otherRegistry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
				if e != nil {
					t.Fatal(e)
				}
				otherPlan := plan
				otherPlan.Audits = append([]AuditPlan(nil), plan.Audits...)
				otherSeed, e := securityMutationAudit(ctx, otherBinding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", op.OperationID, "user", otherBinding.AnonymousFlowID, "protected", true)
				if e != nil {
					t.Fatal(e)
				}
				otherPlan.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(otherBinding, op, "user", otherSeed)
				if e != nil {
					t.Fatal(e)
				}
				otherPlan, e = otherCoordinator.PrepareCommandPlan(otherBinding, otherCommand, otherPlan)
				if e != nil {
					t.Fatal(e)
				}
				type observed struct {
					result   identity.CommandResult
					err      error
					original bool
				}
				done, start := make(chan observed, 2), make(chan struct{})
				go func() { <-start; r, e := execute(c, b, command, plan); done <- observed{r, e, true} }()
				go func() {
					<-start
					r, e := execute(otherCoordinator, otherBinding, otherCommand, otherPlan)
					done <- observed{r, e, false}
				}()
				close(start)
				winners := 0
				for range 2 {
					observation := <-done
					if observation.original {
						result, err = observation.result, observation.err
					}
					if observation.err == nil && observation.result.Outcome == identity.CommitOutcomeCommitted {
						winners++
					}
				}
				if winners != 1 {
					t.Fatal("canonical registration race did not have one winner")
				}
				var accounts int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users u JOIN identity.identifiers i USING(tenant_id,user_id) JOIN identity.credential_references c USING(tenant_id,user_id) JOIN public.identity_test_registration_material m ON m.user_id=u.user_id WHERE u.tenant_id=$1 AND i.canonical_value=$2`, string(b.TenantID), intent.Identifier.CanonicalValue).Scan(&accounts); e != nil || accounts != 1 {
					t.Fatal("canonical race left partial or duplicate accounts", e)
				}
				var losingOrphans int
				if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.users u WHERE u.tenant_id=$1 AND u.user_id IN($2,$3) AND NOT EXISTS(SELECT 1 FROM identity.identifiers i WHERE i.tenant_id=u.tenant_id AND i.user_id=u.user_id)`, string(b.TenantID), string(u), string(otherUser)).Scan(&losingOrphans); e != nil || losingOrphans != 0 {
					t.Fatal("losing signup left an orphan", e)
				}
			} else {
				result, err = execute(c, b, command, plan)
			}
			want := 0
			if mode == "commit" || mode == "disconnect-after" || mode == "foreign-tenant-value" || mode == "concurrent" && result.Outcome == identity.CommitOutcomeCommitted && err == nil {
				want = 1
			}
			if fault == nil && want == 1 && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Binding.OperationID != op.OperationID || result.Binding.AnonymousFlowID != b.AnonymousFlowID) {
				t.Fatal("signup lost its original operation or durable creation", err)
			}
			if want == 0 && err == nil {
				t.Fatal("denied registration succeeded")
			}
			if fault != nil {
				if err == nil || !fault.hit.Load() || result.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("registration transport ambiguity fabricated outcome", "fault", fault.hit.Load(), "outcome", result.Outcome, err)
				}
				query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
				deadline, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				outcome := identity.CommitOutcomeNotCommitted
				if want == 1 {
					outcome = identity.CommitOutcomeCommitted
				}
				for {
					history, e := c.recoverCommandReceipt(deadline, query)
					if history.Outcome == outcome {
						if want == 1 && e != nil {
							t.Fatal("committed registration history lost", e)
						}
						break
					}
					select {
					case <-deadline.Done():
						t.Fatal("original registration ambiguity unresolved", e)
					case <-ticker.C:
					}
				}
			}
			var users, identifiers, references, material, bindings, emitted int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND NOT verified AND NOT is_primary AND version=1 AND verification_state=1),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND enabled AND version=1),(SELECT count(*) FROM public.identity_test_registration_material WHERE command_id=$3),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3)`, string(b.TenantID), string(u), string(b.CommandID)).Scan(&users, &identifiers, &references, &material, &bindings, &emitted); err != nil || users != want || identifiers != want || references != want || material != want || bindings != want || emitted != want {
				t.Fatal("signup creation and required effects were not atomic", err)
			}
			if want == 1 {
				var attributes int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2 AND schema_id='fields' AND schema_version=1`, string(b.TenantID), string(u)).Scan(&attributes); err != nil || attributes != 1 {
					t.Fatal("prepared registration attributes lost", err)
				}
				replay, history, err := c.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.state != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != b {
					t.Fatal("original signup replay lost", err)
				}
				for _, changed := range []struct {
					hash   string
					cookie auth.BearerCredential
				}{{hash + "x", cookie}, {hash, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))}} {
					spec, _ := command.PasswordSignupFeature()
					substitute, e := identity.NewFeaturePasswordSignupCommand(spec, changed.hash, changed.cookie)
					if e != nil {
						t.Fatal(e)
					}
					// Admit the substitute through its own otherwise valid participant
					// and freshly computed plan, so only durable intent can reject it.
					changedPhase := *phase
					changedPhase.expected = substitute
					changedRegistry, e := NewContributorRegistry([]Contributor{selectedRepo, audits, outbox, &changedPhase})
					if e != nil {
						t.Fatal(e)
					}
					changedCoordinator, e := NewCoordinator(selectedPool, changedRegistry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 500 * time.Millisecond, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
					if e != nil {
						t.Fatal(e)
					}
					changedPlan, e := changedCoordinator.PrepareCommandPlan(b, substitute, plan)
					if e != nil {
						t.Fatal("changed custody must reach durable claim comparison", e)
					}
					reservation, conflictResult, e := changedCoordinator.ReserveCommand(ctx, b, substitute, changedPlan)
					var conflict identity.ConflictError
					if !errors.As(e, &conflict) || reservation.state != nil || conflictResult.Outcome != identity.CommitOutcomeConflict {
						t.Fatal("changed signup custody did not conflict with durable intent", e)
					}
				}
				history, err = c.recoverCommandReceipt(ctx, identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID})
				if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Binding != b {
					t.Fatal("password-free original registration recovery lost", err)
				}
			}
		})
	}
}
