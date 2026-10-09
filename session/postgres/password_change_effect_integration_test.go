//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	policy "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This test-only native feature isolates the real sealed same-Work session and
// kernel effects. It does not verify a password, bearer, reauthentication proof
// or public workflow; those remain mandatory in the consuming password owner.
type passwordSessionFeature struct {
	effect  *PasswordChangeEffect
	intent  kernel.CredentialReplacementIntent
	fail    bool
	foreign bool
}

func (*passwordSessionFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (*passwordSessionFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{passwordChangeOperation()}
}
func (p *passwordSessionFeature) CredentialReplacement(identity.Command) (kernel.CredentialReplacementIntent, error) {
	return p.intent, nil
}
func (*passwordSessionFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	_, err := passwordChangeSessions(c)
	return err
}
func (p *passwordSessionFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.foreign {
		copy := *p
		return p.effect.Apply(ctx, w, &copy, c)
	}
	r, err := p.effect.Apply(ctx, w, p, c)
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *passwordSessionFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

type passwordSessionOutbox struct{ revokeOutbox }

func (p *passwordSessionOutbox) PersistCredentialReplacement(ctx context.Context, w kernel.Work) error {
	if _, err := w.StagedCredentialReplacement(); err != nil {
		return err
	}
	return p.PersistLifecycle(ctx, w)
}

func testNativePasswordSessionEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	const tenant = "password-session-effect"
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES($1,1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: 2 * time.Second}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewPasswordChangeEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"preserve", "other", "all", "over-limit", "rollback", "audit-failure", "outbox-failure", "stale-other", "expired-other", "stale-family", "revoked-other", "stale-source", "foreign-invocation", "foreign-participant", "negative-recovery", "wait-expiry", "mixed-preserve"} {
		t.Run(scenario, func(t *testing.T) {
			user := identity.UserID(scenario)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1);`, tenant, string(user)); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, tenant, string(user)); err != nil {
				t.Fatal(err)
			}
			policyScope := policy.AuthorityScope{TenantID: tenant, PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(user)}
			if _, err := policy.InitializeAuthority(ctx, pool.Raw(), policyScope, time.Second); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			var records []session.Session
			for i := 0; i < 18; i++ {
				s, _ := testSession(t).Bindings()
				s.TenantID, s.UserID, s.SessionID, s.FamilyID = tenant, user, fmt.Sprintf("%s-s-%02d", scenario, i), fmt.Sprintf("%s-f-%02d", scenario, i)
				s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
				s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, CredentialID: "password", CredentialVersion: 1, ProofVersion: 1, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: tenant, Subject: string(user), Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}}
				if scenario == "wait-expiry" {
					remember, _ := s.Remember.Bindings()
					s.IssuedAt, s.LastActivityAt = now.Add(-remember.IdleTTL).Add(700*time.Millisecond), now.Add(-remember.IdleTTL).Add(700*time.Millisecond)
					s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = s.IssuedAt.Add(-time.Minute), s.IssuedAt.Add(time.Minute)
				}
				s.Lookup = session.TokenDigest{KeyVersion: 1, Sum: sha256.Sum256([]byte(string(user) + "/" + s.SessionID))}
				keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: tenant}, user)
				sk, _ := SessionAuthorityKeys(tenant, user, s.FamilyID, s.SessionID)
				pk, _ := policyScope.Key()
				a := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
				s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)})
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 && scenario == "expired-other" {
					s.IssuedAt, s.LastActivityAt = now.Add(-2*time.Hour), now.Add(-2*time.Hour)
					s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = s.IssuedAt.Add(-time.Minute), s.IssuedAt.Add(time.Minute)
				}
				if i == 0 && scenario == "stale-other" {
					v, _ := s.Authority.Bindings()
					v.Identifier.Version = 2
					s.Authority, _ = session.NewAuthoritySnapshot(v)
				}
				if i == 0 && (scenario == "mixed-preserve" || scenario == "other" || scenario == "all") {
					v, _ := s.Authority.Bindings()
					v.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:unsupported-profile", Version: 1}}
					s.Authority, err = session.NewAuthoritySnapshot(v)
					if err != nil {
						t.Fatal(err)
					}
				}
				record, err := session.NewSession(s)
				if err != nil {
					t.Fatal(err)
				}
				record = withCSRFState(t, record, 1)
				payload, expiry, err := encodeRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				state, fv := "active", 1
				if i == 0 && scenario == "stale-family" {
					fv = 2
				}
				if i == 0 && scenario == "revoked-other" {
					state = "revoked"
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,$4,'active',$5)`, tenant, string(user), s.FamilyID, fv, s.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,digest_version,digest,state,expires_at,record) VALUES($1,$2,$3,$4,1,1,1,$5,$6,$7,$8::jsonb)`, tenant, string(user), s.SessionID, s.FamilyID, s.Lookup.Sum[:], state, expiry, string(payload)); err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			original := records[17] // Source deliberately occurs on the second keyset page.
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.ActorID = tenant, user, identity.ActorID(user)
			b.OperationID, b.SchemaID, b.RecordID = "identity.password.change", "password-change", "password"
			intent := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: "password", TenantID: tenant, UserID: user, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1}
			mode, maximum := PasswordChangePreserveSessions, uint32(18)
			if scenario == "other" {
				mode = PasswordChangeRevokeOtherSessions
			}
			if scenario == "all" {
				mode = PasswordChangeRevokeAllSessions
			}
			if scenario == "over-limit" {
				maximum = 16
			}
			fields, _ := kernel.CredentialReplacementFields(intent)
			selection, err := PasswordChangeSessionFields(original, mode, maximum)
			if err != nil {
				t.Fatal(err)
			}
			fields = append(fields, selection...)
			command, err := identity.NewFeaturePasswordHashCommand(identity.FeatureCommandSpec{Binding: b, Operation: passwordChangeOperation(), Fields: fields}, "$argon2id$synthetic-command-custody")
			if err != nil {
				t.Fatal(err)
			}
			feature := &passwordSessionFeature{effect: effect, intent: intent, fail: scenario == "rollback", foreign: scenario == "foreign-participant"}
			auditing, outbox := &revokeAudit{fail: scenario == "audit-failure"}, &passwordSessionOutbox{revokeOutbox{fail: scenario == "outbox-failure"}}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditing, outbox, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: revokeQueryPolicy{}}})
			if err != nil {
				t.Fatal(err)
			}
			plan := passwordEffectPlan(t, b, registry, feature, now)
			plan, err = coordinator.PrepareCommandPlan(b, command, plan)
			if err != nil {
				t.Fatal("prepare", err)
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal("reserve", err)
			}
			if scenario == "negative-recovery" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)); err != nil {
					t.Fatal(err)
				}
				q, caller := revokeRecoveryInput(b)
				result, err := coordinator.RecoverCommand(ctx, q, caller)
				var unavailable identity.UnavailableError
				if !errors.As(err, &unavailable) || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("original negative recovery", result.Outcome, err)
				}
				var count int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.password_changes WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&count); err != nil || count != 0 {
					t.Fatal("recovery created session effects", err)
				}
				return
			}
			if scenario == "stale-source" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id=$1 AND subject_id=$2`, tenant, string(user)); err != nil {
					t.Fatal(err)
				}
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			if scenario == "foreign-invocation" {
				if _, err := effect.Apply(ctx, w, feature, command); err == nil {
					t.Fatal("pre-invocation Work admitted")
				}
			}
			var result identity.CommandResult
			if scenario == "wait-expiry" {
				s, _ := original.Bindings()
				life, _ := original.Lifetime(now)
				result, err = applyPasswordAfterFamilyWait(t, ctx, pool, coordinator, w, command, s, life.ExpiresAt)
			} else {
				result, err = coordinator.ApplyFeature(ctx, w, command)
			}
			success := scenario != "over-limit" && scenario != "rollback" && scenario != "audit-failure" && scenario != "outbox-failure" && scenario != "stale-source" && scenario != "foreign-participant" && scenario != "wait-expiry" && scenario != "mixed-preserve"
			if err == nil {
				result, err = coordinator.Commit(w, result)
			} else {
				coordinator.Abort(w, err)
			}
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("commit", err)
			}
			if !success && err == nil {
				t.Fatal("denied effect committed")
			}
			native, _ := NewRepository(pool, config)
			for i, record := range records {
				s, _ := record.Bindings()
				stored, err := native.Get(ctx, tenant, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				wantRevoked := scenario == "revoked-other" && i == 0
				continued := false
				if success {
					wantRevoked = wantRevoked || mode == PasswordChangeRevokeAllSessions || mode == PasswordChangeRevokeOtherSessions && i != 17 || i == 0 && (scenario == "stale-other" || scenario == "expired-other" || scenario == "stale-family")
					continued = !wantRevoked
				}
				if stored.Revoked != wantRevoked {
					t.Fatal("wrong revocation", i)
				}
				want := record
				if continued {
					want, err = session.ContinuePasswordSession(record, session.CredentialContinuationSpec{CommandID: b.CommandID, BeforeAuthorityVersion: 1, BeforeCredentialVersion: 1})
					if err != nil {
						t.Fatal(err)
					}
				}
				before, _, _ := encodeRecord(want)
				after, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(before, after) {
					t.Fatal("session history changed or continuation lost", i)
				}
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.password_changes WHERE tenant_id=$1 AND command_id=$2`, tenant, mustCommandBytes(t, b.CommandID)).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if (count == 1) != success {
				t.Fatal("effect evidence not atomic")
			}
			current, err := domain.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: tenant, UserID: user, CredentialID: "password"})
			if err != nil {
				t.Fatal(err)
			}
			delta := uint64(0)
			if success {
				delta = 1
			}
			if current.User.Version != 1+delta || current.AuthorityVersion != 1+delta || current.Credential.Version != 1+delta {
				t.Fatal("kernel epochs not atomic")
			}
			if success {
				_, replay, e := coordinator.ReserveCommand(ctx, b, command, plan)
				if e != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Feature == nil || *replay.Feature != *result.Feature {
					t.Fatal("original replay changed", e)
				}
				projection, _ := command.PasswordHashFeature()
				for j := range projection.Fields {
					if projection.Fields[j].Name == "password-sessions.maximum" {
						projection.Fields[j].Value.Uint64++
					}
				}
				changed, e := identity.NewFeaturePasswordHashCommand(projection, "$argon2id$synthetic-command-custody")
				if e != nil {
					t.Fatal(e)
				}
				changedPlan, e := coordinator.PrepareCommandPlan(b, changed, plan)
				if e != nil {
					t.Fatal(e)
				}
				_, changedReplay, e := coordinator.ReserveCommand(ctx, b, changed, changedPlan)
				var conflict identity.ConflictError
				if !errors.As(e, &conflict) || changedReplay.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("changed selection replay admitted", e)
				}
				transition := *plan.Lifecycle
				status, err := recoverPasswordSessionEffect(ctx, pool.Raw(), `"session_store"`, b, transition)
				if err != nil || status != kernel.RecoveryCommitted {
					t.Fatal("retained committed evidence", err)
				}
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2`, tenant, string(user)); err != nil {
					t.Fatal(err)
				}
				status, err = recoverPasswordSessionEffect(ctx, pool.Raw(), `"session_store"`, b, transition)
				if err != nil || status != kernel.RecoveryCommitted {
					t.Fatal("payload pruning erased original effect", err)
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.password_changes SET result_digest=decode(repeat('00',32),'hex') WHERE tenant_id=$1 AND command_id=$2`, tenant, mustCommandBytes(t, b.CommandID)); err != nil {
					t.Fatal(err)
				}
				status, err = recoverPasswordSessionEffect(ctx, pool.Raw(), `"session_store"`, b, transition)
				if err != nil || status != kernel.RecoveryUnknown {
					t.Fatal("corrupt commitment admitted", err)
				}
			}
		})
	}
}

func applyPasswordAfterFamilyWait(t *testing.T, ctx context.Context, pool *database.Pool, coordinator *kernel.Coordinator, w kernel.Work, command identity.Command, s session.SessionSpec, deadline time.Time) (identity.CommandResult, error) {
	t.Helper()
	lock, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = lock.Rollback(cleanup)
	}()
	if _, err := lock.Exec(ctx, `UPDATE session_store.families SET version=version WHERE tenant_id=$1 AND family_id=$2`, string(s.TenantID), s.FamilyID); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	type applied struct {
		result identity.CommandResult
		err    error
	}
	completed := make(chan applied, 1)
	go func() { r, e := coordinator.ApplyFeature(bounded, w, command); completed <- applied{r, e} }()
	joined := false
	defer func() {
		if !joined {
			stop()
			<-completed
		}
	}()
	for blocked, expired := false, false; !blocked || !expired; {
		var waiting bool
		if err := pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%session_store%.families%'),clock_timestamp()>$1`, deadline).Scan(&waiting, &expired); err != nil {
			t.Fatal("session lock/deadline barrier", err)
		}
		blocked = blocked || waiting
		if !blocked || !expired {
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-timer.C:
			case <-bounded.Done():
			}
			timer.Stop()
		}
	}
	if err := lock.Commit(bounded); err != nil {
		t.Fatal(err)
	}
	got := <-completed
	joined = true
	return got.result, got.err
}

func passwordEffectPlan(t *testing.T, b identity.CommandBinding, registry *kernel.ContributorRegistry, feature *passwordSessionFeature, now time.Time) kernel.CommandPlan {
	t.Helper()
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, passwordChangeOperation(), "credential", seed)
	if err != nil {
		t.Fatal(err)
	}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "credential", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: passwordChangeOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "password.changed.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}}
}
