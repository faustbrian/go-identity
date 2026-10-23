//go:build integration

package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// This controlled protocol-owner seam tests real session/kernel SQL and atomic
// effects, not WebAuthn authentication or real RP/mapping/MFA authority. The
// complete passkey consumer must supply those genuine owners before acceptance.
type passkeySessionFeature struct {
	effect   *PasskeySigninEffect
	original identity.Command
	mode     string
	applied  bool
}

func (*passkeySessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (*passkeySessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passkeySessionOperation()}
}
func (p *passkeySessionFeature) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.original || plan.SubjectType != "session" {
		return identity.ForbiddenError{}
	}
	_, err := PasskeySigninSession(c)
	return err
}
func (p *passkeySessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	scope := policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(b.UserID)}
	if _, err := policy.InitializeAuthority(ctx, w, scope, time.Second); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "reconstructed-command" {
		spec, _ := c.Feature()
		c, _ = identity.NewFeatureCommand(spec)
	}
	result, err := p.effect.Apply(ctx, w, p, c)
	p.applied = err == nil
	if err == nil && p.mode == "rollback" {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return result, err
}
func (p *passkeySessionFeature) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mode == "final-denial" {
		return identity.ForbiddenError{}
	}
	return p.effect.Check(ctx, w, p, c)
}
func (p *passkeySessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

type passkeySessionComponentAuthority struct {
	passkeyVersion, factorVersion uint64
}

func (a *passkeySessionComponentAuthority) ObservePasskeySession(ctx context.Context, namespace string, _ session.Session) (PasskeySessionAuthorityObservation, error) {
	if namespace != "rp-a" || ctx.Err() != nil {
		return PasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	now := time.Now().UTC()
	return PasskeySessionAuthorityObservation{PasskeyVersion: a.passkeyVersion, FactorVersion: a.factorVersion, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, nil
}
func (a *passkeySessionComponentAuthority) RequirePasskeySession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, namespace string, record session.Session) error {
	b, _, _, err := w.FeatureScope(owner)
	spec, e := record.Bindings()
	if err != nil || e != nil || namespace != "rp-a" || b.TenantID != spec.TenantID || b.UserID != spec.UserID {
		return identity.ForbiddenError{}
	}
	v, _ := spec.Authority.Bindings()
	if v.Passkey.Binding.Version != a.passkeyVersion || v.Factor.Binding.Version != a.factorVersion {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func TestPasskeySessionAtomicNativePersistence(t *testing.T) {
	ctx, pool, repository := anonymousSessionDatabase(t)
	steps, err := (PasskeySigninMigrationSource{Schema: "session_store", Version: 25, PreviousConstraint: "session_issuances_purpose_anonymous_v1"}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, steps[0].UpSQL()); err != nil {
		t.Fatal("passkey issuance forward history", err)
	}
	authority := &passkeySessionComponentAuthority{passkeyVersion: 1, factorVersion: 1}
	profile := PasskeyAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", RPNamespace: "rp-a"}
	effect, err := NewPasskeySigninEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile, authority)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "reconstructed-command", "banned", "disabled", "rollback", "audit-failure", "outbox-failure", "final-denial"} {
		t.Run(mode, func(t *testing.T) {
			original, b, _ := passkeySessionFixture(t)
			b.CommandID, _ = identity.NewCommandID()
			user, _ := identity.NewSubjectID()
			b.TenantID, b.UserID, b.ActorID = "guest-tenant", identity.UserID(user), identity.ActorID(user)
			spec, _ := original.Bindings()
			spec.TenantID, spec.UserID = b.TenantID, b.UserID
			spec.SessionID, spec.FamilyID = "passkey-session-"+mode, "passkey-family-"+mode
			b.RecordID = spec.SessionID
			now := time.Now().UTC().Truncate(time.Microsecond)
			spec.IssuedAt, spec.LastActivityAt = now, now
			spec.Authentication.CredentialVersion = 1
			spec.Authentication.Proof.Tenant, spec.Authentication.Proof.Subject = string(b.TenantID), string(b.UserID)
			spec.Authentication.Proof.IssuedAt, spec.Authentication.Proof.ExpiresAt = now, now.Add(time.Minute)
			key, _ := session.NewDigestKey(1, make([]byte, 32))
			token, err := session.NewToken(32)
			if err != nil {
				t.Fatal(err)
			}
			spec.Lookup, err = token.Digest(key, string(b.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "guest-deployment", TenantID: b.TenantID}, b.UserID)
			sk, _ := SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
			pk, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(b.UserID)}).Key()
			factorKey, _ := mfapg.FactorAuthorityKey(b.TenantID, b.UserID)
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			spec.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), Session: a(sk.Session), SessionFamily: a(sk.Family), Authorization: a(pk), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(factorKey)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: a("passkey:rp-a:" + string(user))}})
			if err != nil {
				t.Fatal(err)
			}
			status := "active"
			if mode == "banned" {
				status = "banned"
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,$3,1,1,1,1);`, string(b.TenantID), string(b.UserID), status); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'passkey-a',2,'passkey',1,$3)`, string(b.TenantID), string(b.UserID), mode != "disabled"); err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSession(spec)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := PasskeySigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: passkeySessionOperation(), Fields: fields})
			if err != nil {
				t.Fatal(err)
			}
			feature := &passkeySessionFeature{effect: effect, original: command, mode: mode}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &revokeAudit{fail: mode == "audit-failure"}, &revokeOutbox{fail: mode == "outbox-failure"}, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, passkeySessionOperation(), "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: passkeySessionOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			work, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			result, applyErr := coordinator.ApplyFeature(ctx, work, command)
			if applyErr != nil {
				result, _ = coordinator.Abort(work, applyErr)
			} else {
				result, err = coordinator.Commit(work, result)
			}
			if mode == "commit" && (applyErr != nil || err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("native passkey session failed", applyErr, err, result.Outcome)
			}
			if mode != "commit" && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid passkey session committed")
			}
			if (mode == "rollback" || mode == "audit-failure" || mode == "outbox-failure" || mode == "final-denial") && !feature.applied {
				t.Fatal("rollback control never reached staged passkey session")
			}
			var sessions, families, issuances int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1 AND user_id=$2)`, string(b.TenantID), string(b.UserID)).Scan(&sessions, &families, &issuances); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == "commit" {
				want = 1
			}
			if sessions != want || families != want || issuances != want {
				t.Fatal("passkey session effects not atomic", sessions, families, issuances)
			}
			if mode == "commit" {
				_, replay, err := coordinator.ReserveCommand(ctx, b, command, plan)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("retained command replay failed", err)
				}
				got, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}, passkeyIssuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted || got.SessionID != b.RecordID {
					t.Fatal("retained passkey issuance identity lost", err)
				}
				validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: sessionReadClock(time.Now), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}
				service, err := NewPasskeySessionService(pool, PasskeySessionServiceConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: validation, Authority: authority})
				if err != nil {
					t.Fatal(err)
				}
				credential, _ := session.NewCredential(session.CredentialBearer, token)
				request := session.GetRequest{TenantID: b.TenantID, Credential: credential}
				accepted, err := service.Get(ctx, request)
				if err != nil || !accepted.Authenticated || accepted.ValidateAt(time.Now()) != nil {
					t.Fatal("current native passkey record denied", err)
				}
				// Modeled external passkey/MFA epochs must be compared, never
				// copied into the stored original as refreshed positive authority.
				for _, dimension := range []string{"passkey", "factor"} {
					if dimension == "passkey" {
						authority.passkeyVersion = 2
					} else {
						authority.factorVersion = 2
					}
					if got, err := service.Get(ctx, request); err != nil || got.Authenticated {
						t.Fatal("changed owner epoch refreshed original record", err)
					}
					authority.passkeyVersion, authority.factorVersion = 1, 1
				}
				legacy := profile.credentialProfile()
				legacy.AuthenticationMethod, legacy.CredentialKind, legacy.CredentialOwner = "password", identity.CredentialPassword, "identity/password"
				passwordReader, err := NewSessionService(pool, SessionServiceConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: legacy, Validation: validation})
				if err != nil {
					t.Fatal(err)
				}
				if got, err := passwordReader.Get(ctx, request); err != nil || got.Authenticated {
					t.Fatal("passkey authority downgraded to password", err)
				}
				testPasskeySessionOwnedLogout(t, ctx, pool, service, request, accepted, profile, authority)
			}
		})
	}
}

// Use the actual revocation executor and its audit/outbox owners. This remains
// a session-owner component test, not proof of WebAuthn authentication.
func testPasskeySessionOwnedLogout(t *testing.T, ctx context.Context, pool *database.Pool, reader *session.SessionService, input session.GetRequest, accepted session.GetResult, profile PasskeyAdmissionConfig, authority *passkeySessionComponentAuthority) {
	t.Helper()
	history, err := (RevokeOneMigrationSource{Base: RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 20}, Version: 21}, Version: 26}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("revocation history", err)
	}
	install, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer install.Rollback(ctx)
	if _, err := install.Exec(ctx, `SET LOCAL search_path = public, pg_catalog`); err != nil {
		t.Fatal(err)
	}
	if _, err := install.Exec(ctx, auditpostgres.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, files := range []fs.FS{auditpostgres.Migrations(), outboxpostgres.Migrations(), identityoutbox.Migrations()} {
		entries, err := fs.ReadDir(files, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := fs.ReadFile(files, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := install.Exec(ctx, strings.Split(string(data), "-- +migrations Down")[0]); err != nil {
				t.Fatal("logout dependency history", entry.Name(), err)
			}
		}
	}
	if err := install.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Roles are cluster-wide, unlike the disposable database. Remove only the
	// three roles this successful fresh-install transaction just reserved.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(cleanup, `DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention`); err != nil {
			t.Error("logout audit-role cleanup", err)
		}
	}()
	config := RevokeOneExecutorConfig{
		Execution: IssueExecutorConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: IssueAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyID: "session-policy", PolicyVersion: 1, AuditRetentionVersion: 1},
		Sessions:  reader, Passkey: &PasskeySessionAdmission{Profile: profile, Authority: authority},
	}
	executor, err := NewRevokeOneExecutor(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := accepted.Session.Bindings()
	prepare := func() (session.RevokeOneRequest, identity.CommandID) {
		t.Helper()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID)
		b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := session.NewRevokeOneCommand(b, accepted.Session)
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRevokeOne(accepted, command)
		if err != nil {
			t.Fatal(err)
		}
		return request, b.CommandID
	}
	assertState := func(command identity.CommandID, revoked bool, effects int) {
		t.Helper()
		stored, err := executor.owned.native.Get(ctx, spec.TenantID, spec.SessionID)
		if err != nil || stored.Revoked != revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != spec.FamilyVersion {
			t.Fatal("logout changed wrong session/family state", err)
		}
		original, _, _ := encodeRecord(accepted.Session)
		current, _, _ := encodeRecord(stored.Session)
		if string(original) != string(current) {
			t.Fatal("logout rewrote original authority")
		}
		var revocations, audits, events int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, command), int64(audit.OutcomeSucceeded)).Scan(&revocations, &audits, &events); err != nil || revocations != effects || audits != effects || events != effects {
			t.Fatal("logout required effects not atomic", err, revocations, audits, events)
		}
	}
	for _, dimension := range []string{"passkey", "factor", "unselected"} {
		request, command := prepare()
		selected := executor
		switch dimension {
		case "passkey":
			authority.passkeyVersion = 2
		case "factor":
			authority.factorVersion = 2
		case "unselected":
			closed := config
			closed.Passkey = nil
			selected, err = NewRevokeOneExecutor(pool, closed)
			if err != nil {
				t.Fatal(err)
			}
		}
		result, err := selected.ExecuteRevokeOne(ctx, request)
		authority.passkeyVersion, authority.factorVersion = 1, 1
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logout omitted current " + dimension + " authority")
		}
		assertState(command, false, 0)
		if current, err := reader.Get(ctx, input); err != nil || !current.Authenticated {
			t.Fatal("denied logout mutated active session", err)
		}
	}
	request, command := prepare()
	result, err := executor.ExecuteRevokeOne(ctx, request)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owned passkey logout failed", err, result.Outcome)
	}
	assertState(command, true, 1)
	if current, err := reader.Get(ctx, input); err != nil || current.Authenticated {
		t.Fatal("logged-out passkey session authenticated", err)
	}
}
