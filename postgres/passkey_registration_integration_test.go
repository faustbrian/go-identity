//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// This real coordinator fixture proves kernel creation and its required effects,
// not WebAuthn verification, signup authorization or session issuance.
type passkeyRegistrationPhase struct {
	domain  *PasskeyRegistrationDomain
	command identity.Command
	intent  PasskeyRegistrationIntent
	mode    string
	created bool
}

func (*passkeyRegistrationPhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeyRegistrationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}}
}
func (p *passkeyRegistrationPhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.command {
		return invalidWork()
	}
	return nil
}
func (p *passkeyRegistrationPhase) PasskeyRegistration(c identity.Command) (PasskeyRegistrationIntent, error) {
	if c != p.command {
		return PasskeyRegistrationIntent{}, invalidWork()
	}
	return p.intent, nil
}
func (p *passkeyRegistrationPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode == "premature-read" {
		_, _ = w.PasskeyRegistrationUser(ctx, p, c)
	}
	if p.mode != "missing-creation" {
		owner, command := PasskeyRegistrationContributor(p), c
		if p.mode == "foreign-owner" {
			owner = &passkeyRegistrationPhase{}
		}
		if p.mode == "reconstructed-command" {
			spec, _ := c.Feature()
			command, _ = identity.NewFeatureCommand(spec)
		}
		user, err := p.domain.Apply(ctx, w, owner, command)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.created = true
		observed, err := w.PasskeyRegistrationUser(ctx, p, c)
		if err != nil || observed != user || user.ID != p.intent.Creation.Binding.UserID {
			return identity.FeatureReceipt{}, invalidWork()
		}
		if p.mode == "duplicate" {
			_, _ = p.domain.Apply(ctx, w, p, c)
		}
		if strings.HasPrefix(p.mode, "session") {
			id := "new-session-" + string(user.ID)
			if p.mode == "session-mismatch" {
				id = "different-session"
			}
			err := w.StagePasskeyRegistrationSession(ctx, p, c, id)
			if err != nil && !strings.Contains(p.mode, "overflow") {
				return identity.FeatureReceipt{}, err
			}
			if p.mode == "session-duplicate" {
				_ = w.StagePasskeyRegistrationSession(ctx, p, c, id)
			}
		}
	}
	if p.mode == "native-failure" {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.FeatureOperations()[0], AfterVersion: 1}, nil
}
func (p *passkeyRegistrationPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if p.mode == "final-check-failure" || p.mode == "session-final-check-failure" {
		return identity.ForbiddenError{}
	}
	if p.mode == "late-user-block" {
		if _, err := w.Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID)); err != nil {
			return err
		}
	}
	if p.mode == "late-credential-disable" {
		if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID), string(p.intent.Credential.ID)); err != nil {
			return err
		}
	}
	if p.mode == "late-reference-expiry" {
		if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(p.intent.Credential.TenantID), string(p.intent.Credential.UserID), string(p.intent.Credential.ID)); err != nil {
			return err
		}
	}
	_, err := w.PasskeyRegistrationUser(ctx, p, c)
	return err
}
func (*passkeyRegistrationPhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

type passkeyRegistrationOutbox struct {
	recoveryLifecyclePhase
	expectedSessionIndex uint16
	failAfterSession     bool
	sessionWritten       bool
}

func (p *passkeyRegistrationOutbox) PersistPasskeySignupSession(ctx context.Context, w Work) error {
	return p.PersistPasskeyRegistration(ctx, w)
}

type legacyPasskeyRegistrationOutbox struct {
	recoveryLifecyclePhase
	base *passkeyRegistrationOutbox
}

func (p *legacyPasskeyRegistrationOutbox) PersistPasskeyRegistration(ctx context.Context, w Work) error {
	return p.base.PersistPasskeyRegistration(ctx, w)
}

func (p *passkeyRegistrationOutbox) PersistPasskeyRegistration(ctx context.Context, w Work) error {
	if err := p.PersistLifecycle(ctx, w); err != nil {
		return err
	}
	created, err := w.StagedPasskeyRegistrationLifecycle()
	if err != nil {
		return err
	}
	if _, err = w.Exec(ctx, `INSERT INTO public.identity_test_passkey_created(event_id,command_id,user_id,event_type,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6)`, created.ID, string(created.CommandID), created.SubjectID, created.EventType, created.BeforeVersion, created.AfterVersion); err != nil {
		return err
	}
	session, present, err := w.StagedPasskeyRegistrationSessionLifecycle()
	if err != nil || !present {
		return err
	}
	if session.EventType != "session.created.v1" || session.SubjectType != "session" || session.SubjectID != "new-session-"+string(created.UserID) || session.EventIndex != p.expectedSessionIndex || session.ID == created.ID || session.ID == w.state.lifecycle.record.ID || !session.OccurredAt.Equal(created.OccurredAt) {
		return invalidLifecycle()
	}
	_, err = w.Exec(ctx, `INSERT INTO public.identity_test_passkey_created(event_id,command_id,user_id,event_type,before_version,after_version) VALUES($1,$2,$3,$4,$5,$6)`, session.ID, string(session.CommandID), string(session.UserID), session.EventType, session.BeforeVersion, session.AfterVersion)
	if err == nil {
		p.sessionWritten = true
		if p.failAfterSession {
			return identity.ForbiddenError{}
		}
	}
	return err
}

func TestPasskeyRegistrationCreationPostgres(t *testing.T) {
	ctx, pool, repo := anonymousKernelDatabase(t)
	history, err := (PasskeyRegistrationMigrationSource{Base: PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 16}, Version: 17}, Version: 18}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() > 15 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("passkey registration history", err)
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_passkey_created(event_id text PRIMARY KEY,command_id text NOT NULL,user_id text NOT NULL,event_type text NOT NULL,before_version numeric NOT NULL,after_version numeric NOT NULL,UNIQUE(command_id,event_type))`); err != nil {
		t.Fatal(err)
	}
	domain, err := NewPasskeyRegistrationDomain(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "session", "session-slots", "session-reversed-slots", "session-primary-overflow", "session-account-overflow", "session-outbox-after-failure", "session-final-check-failure", "session-old-outbox", "session-mismatch", "session-duplicate", "missing-creation", "premature-read", "foreign-owner", "reconstructed-command", "changed-intent", "unknown-field", "duplicate", "existing-user", "disabled-reference", "native-failure", "audit-failure", "outbox-failure", "final-check-failure", "late-user-block", "late-credential-disable", "late-reference-expiry"} {
		t.Run(mode, func(t *testing.T) {
			intent := passkeyRegistrationIntentFixture()
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			intent.Creation.Binding.CommandID = id
			intent.Creation.Binding.UserID = identity.UserID("passkey-created-" + mode)
			intent.Credential.UserID = intent.Creation.Binding.UserID
			intent.Credential.ID = identity.CredentialID("passkey-ref-" + mode)
			p := &passkeyRegistrationPhase{domain: domain, intent: intent, mode: mode}
			op := p.FeatureOperations()[0]
			b := intent.Creation.Binding
			b.UserID, b.AnonymousFlowID, b.RecordID = "", "signup-flow-"+mode, string(intent.Credential.ID)
			b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			fields, err := PasskeyRegistrationFields(intent)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "unknown-field" {
				fields = append(fields, identity.FeatureField{Name: "registration.unselected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
			}
			if strings.HasPrefix(mode, "session") {
				fields = append(fields, identity.FeatureField{Name: "session.result.session.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "new-session-" + string(intent.Credential.UserID)}})
			}
			p.command = featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
			digest, err := PasskeyRegistrationDigest(intent)
			if err != nil {
				t.Fatal(err)
			}
			auditing := &anonymousCreationAuditPhase{recoveryAuditPhase: recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}}
			outbox := &passkeyRegistrationOutbox{recoveryLifecyclePhase: recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}}
			outbox.failAfterSession = mode == "session-outbox-after-failure"
			lifecycle := Contributor(outbox)
			if mode == "session-old-outbox" {
				lifecycle = &legacyPasskeyRegistrationOutbox{base: outbox}
			}
			registry, err := NewContributorRegistry([]Contributor{repo, auditing, lifecycle, p})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			_, _, plan := featurePlanFixture(t)
			plan.Contributors, plan.Feature, plan.SubjectType = registry.Descriptors(), &FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, "credential"
			plan.Lifecycle = &LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}
			plan.PasskeyRegistration = &PasskeyRegistrationPlan{UserID: intent.Credential.UserID, CredentialID: intent.Credential.ID, CreationDigest: digest, CreationEventIndex: 1}
			outbox.expectedSessionIndex = 2
			switch mode {
			case "session-slots":
				plan.Lifecycle.EventIndex, plan.PasskeyRegistration.CreationEventIndex = 3, 7
				outbox.expectedSessionIndex = 8
			case "session-reversed-slots":
				plan.Lifecycle.EventIndex, plan.PasskeyRegistration.CreationEventIndex = 7, 3
				outbox.expectedSessionIndex = 8
			case "session-primary-overflow":
				plan.Lifecycle.EventIndex = ^uint16(0)
			case "session-account-overflow":
				plan.PasskeyRegistration.CreationEventIndex = ^uint16(0)
			}
			plan.Audits[0].EventType, plan.Audits[0].RetentionClass = "identity.passkey.create_credential", "protected"
			seed, err := securityMutationAudit(ctx, b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", plan.Audits[0].EventType, plan.SubjectType, b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, op, plan.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err = coordinator.PrepareCommandPlan(b, p.command, plan)
			if err != nil {
				t.Fatal("prepare signup", err)
			}
			if mode == "existing-user" || mode == "disabled-reference" {
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'banned',7)`, string(b.TenantID), string(intent.Credential.UserID)); err != nil {
					t.Fatal(err)
				}
				if mode == "disabled-reference" {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,false)`, string(b.TenantID), string(intent.Credential.UserID), string(intent.Credential.ID)); err != nil {
						t.Fatal(err)
					}
				}
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "changed-intent" {
				p.intent.Creation.Attributes[0].Value.Scalar.String = "changed after admission"
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, p.command)
			if applyErr != nil {
				result, err = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			sessionSuccess := mode == "session" || mode == "session-slots" || mode == "session-reversed-slots"
			success := mode == "commit" || sessionSuccess
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("prospective account did not commit", err, applyErr)
			}
			if !success && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid signup committed")
			}
			if (mode == "native-failure" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-check-failure" || mode == "duplicate") && !p.created {
				t.Fatal("rollback control did not reach creation", applyErr)
			}
			if (mode == "session-outbox-after-failure" || mode == "session-final-check-failure") && !outbox.sessionWritten {
				t.Fatal("late failure control did not write the third event", applyErr)
			}
			if strings.Contains(mode, "overflow") && !p.created {
				t.Fatal("overflow control did not reach session staging", applyErr)
			}
			var users, credentials, bindings, audits, primaryEvents, creationEvents, attributes, identifiers int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.registration_bindings WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$3 AND succeeded),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$3),(SELECT count(*) FROM public.identity_test_passkey_created WHERE command_id=$3 AND user_id=$2 AND event_type='user.created.v1' AND before_version=0 AND after_version=1),(SELECT count(*) FROM identity.user_attributes WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(intent.Credential.UserID), string(b.CommandID)).Scan(&users, &credentials, &bindings, &audits, &primaryEvents, &creationEvents, &attributes, &identifiers); err != nil {
				t.Fatal(err)
			}
			want, oldUser, oldCredential := 0, 0, 0
			if success {
				want = 1
			}
			if mode == "existing-user" || mode == "disabled-reference" {
				oldUser = 1
			}
			if mode == "disabled-reference" {
				oldCredential = 1
			}
			if users != want+oldUser || credentials != want+oldCredential || bindings != want || audits != want || primaryEvents != want || creationEvents != want || attributes != want || identifiers != 0 {
				t.Fatal("creation/effects not atomic or unwanted identity method created", users, credentials, bindings, audits, primaryEvents, creationEvents, attributes, identifiers)
			}
			var sessionEvents int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_test_passkey_created WHERE command_id=$1 AND event_type='session.created.v1' AND user_id=$2 AND before_version=0 AND after_version=1`, string(b.CommandID), string(intent.Credential.UserID)).Scan(&sessionEvents); err != nil {
				t.Fatal(err)
			}
			if (sessionEvents == 1) != sessionSuccess {
				t.Fatal("session lifecycle absent, duplicated or survived rollback", sessionEvents)
			}
			if success {
				current, err := repo.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: intent.Credential.UserID, CredentialID: intent.Credential.ID})
				if err != nil || !current.Enabled || current.Credential != intent.Credential || current.User.Version != 1 || current.AuthorityVersion != 1 {
					t.Fatal("initial passkey authority missing", err)
				}
				_, retry, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
				if err != nil || retry.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original retry lost committed creation metadata", err)
				}
				for _, recoveryCase := range []struct {
					name     string
					expected RecoveryStatus
				}{{"exact", RecoveryCommitted}, {"different-credential", RecoveryUnknown}, {"other-command-same-user", RecoveryNotCommitted}} {
					// Exercise only the kernel's real primary evidence reader, not
					// the full native ambiguous-commit/session recovery journey.
					frozen := *reservation.state.plan
					frozen.passkeyRegistration = clonePasskeyRegistrationPlan(frozen.passkeyRegistration)
					if recoveryCase.name == "different-credential" {
						frozen.passkeyRegistration.CredentialID = "other-original-reference"
					}
					if recoveryCase.name == "other-command-same-user" {
						frozen.binding.CommandID, err = identity.NewCommandID()
						if err != nil {
							t.Fatal(err)
						}
					}
					tx, err := pool.Raw().Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					work := Work{state: &workState{ctx: ctx, tx: tx, binding: frozen.binding}}
					recovery := RecoveryWork{state: &recoveryWorkState{work: work, entry: registeredContributor{descriptor: repo.Descriptor(), contributor: repo}, plan: &frozen, active: true}}
					status, evidenceErr := repo.RecoverParticipant(ctx, recovery)
					recovery.state.active = false
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					if evidenceErr != nil || status != recoveryCase.expected {
						t.Fatal("creation recovery lost original correlation", recoveryCase.name, status, evidenceErr)
					}
				}
			}
		})
	}
}

func TestPasskeyRegistrationPopulatedMigration(t *testing.T) {
	ctx, pool, _ := anonymousKernelDatabase(t)
	base := MagicLinkRegistrationMigrationSource{Base: PasswordSignupAcceptanceMigrationSource{Base: PasswordRegistrationMigrationSource{Base: MigrationSource{}, Version: 16}, Version: 17}, Version: 18}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() > 15 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	purposes := []string{"identity.password.signup", "identity.password.signup", "identity.magic-link.consume", "identity.passkey.register-verify", "identity.passkey.register-verify", "identity.passkey.register-verify", "identity.password.signup", "identity.magic-link.consume", "identity.username.signup"}
	for i, purpose := range purposes {
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(lpad(to_hex($1::int),32,'0'),'hex'),'tenant',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'))`, i+1, purpose); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(lpad(to_hex($1::int),32,'0'),'hex'),'tenant',$2)`, i+1, purpose); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(id int, user, identifier, credential any, accepted bool) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id,accepted_only) VALUES('tenant',$1,decode(lpad(to_hex($2::int),32,'0'),'hex'),$3,$4,$5,$6)`, purposes[id-1], id, user, identifier, credential, accepted)
		return err
	}
	for _, seed := range []struct {
		id                           int
		user, identifier, credential any
		accepted                     bool
	}{{1, "old-user", "old-email", "old-password", false}, {2, nil, nil, nil, true}, {3, "old-magic-user", "old-magic-email", nil, false}} {
		if err := insert(seed.id, seed.user, seed.identifier, seed.credential, seed.accepted); err != nil {
			t.Fatal(err)
		}
	}
	constraint := func(err error) {
		t.Helper()
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23514" {
			t.Fatal("expected actual disposition constraint rejection", err)
		}
	}
	constraint(insert(4, "new-user", nil, "new-passkey", false))
	snapshot := func() string {
		t.Helper()
		var result string
		if err := pool.Raw().QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(r) ORDER BY command_id)::text FROM identity.registration_bindings r`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	extended, err := (PasskeyRegistrationMigrationSource{Base: base, Version: 19}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range history {
		if history[i].UpSQL() != extended[i].UpSQL() {
			t.Fatal("predecessor migration rewritten")
		}
	}
	if _, err := pool.Raw().Exec(ctx, extended[len(history)].UpSQL()); err != nil {
		t.Fatal("populated forward suffix", err)
	}
	if snapshot() != before {
		t.Fatal("populated registration history changed")
	}
	if err := insert(4, "new-user", nil, "new-passkey", false); err != nil {
		t.Fatal("passkey-only disposition rejected", err)
	}
	constraint(insert(5, "bad-passkey-user", "invented-email", "passkey", false))
	constraint(insert(6, nil, nil, nil, true))
	constraint(insert(7, "bad-password-user", nil, "password", false))
	constraint(insert(8, "bad-magic-user", nil, "passkey", false))
	if err := insert(9, "username-user", "username-email", "username-password", false); err != nil {
		t.Fatal("username predecessor arm lost", err)
	}
}
