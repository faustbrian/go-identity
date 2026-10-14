//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This native test seam proves session-owned atomic effects, not password
// comparison, cookie possession, proof signatures or a complete login journey.
type passwordSigninFeature struct {
	effect            *PasswordSigninEffect
	op                identity.FeatureOperation
	recipient         kernel.RecipientRecord
	flow              session.PreAuthTransaction
	fail              bool
	upgrade           *kernel.PasswordHashUpgradeIntent
	unapplied         bool
	unprepared        bool
	foreign           bool
	foreignAccepted   bool
	substituteApply   bool
	alterLookup       bool
	directApply       bool
	ignoreApplyDenial bool
}

func (*passwordSigninFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *passwordSigninFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*passwordSigninFeature) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	_, err := PasswordSigninSession(c)
	return err
}
func (p *passwordSigninFeature) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	var r identity.FeatureReceipt
	var err error
	if p.upgrade != nil {
		if p.unprepared {
			return p.effect.ApplyHashUpgrade(ctx, w, p, c, p.flow)
		}
		if p.foreign {
			s, _ := c.PasswordSigninFeature()
			secret, cookie, _ := c.PasswordSigninCustody()
			other, e := identity.NewFeaturePasswordSigninCommand(s, secret, cookie)
			if e != nil {
				return r, e
			}
			err = p.effect.PrepareHashUpgrade(ctx, w, p, other, p.recipient)
			p.foreignAccepted = err == nil
			return r, err
		}
		if err = p.effect.PrepareHashUpgrade(ctx, w, p, c, p.recipient); err != nil {
			return r, err
		}
		// Kernel/session contract seam only: native password material CAS and
		// signature provenance belong to the consuming password owner's tests.
		if !p.unapplied {
			if _, err = w.ApplyPasswordHashUpgrade(ctx, p, c); err != nil {
				return r, err
			}
			got, _, e := w.PasswordHashUpgradeSuccessor(p)
			if e != nil || got.ObservedAt != p.recipient.ObservedAt || got.User.Version != p.recipient.User.Version+1 {
				return r, identity.ForbiddenError{}
			}
		}
		if p.substituteApply {
			s, _ := c.PasswordSigninFeature()
			if p.alterLookup {
				record, e := PasswordSigninSession(c)
				if e != nil {
					return r, e
				}
				bindings, _ := record.Bindings()
				bindings.Lookup.Sum[0] ^= 1
				record, e = session.NewSession(bindings)
				if e != nil {
					return r, e
				}
				fields, e := PasswordSigninSessionFields(record)
				if e != nil {
					return r, e
				}
				for _, field := range s.Fields {
					if !strings.HasPrefix(field.Name, passwordSessionPrefix) {
						fields = append(fields, field)
					}
				}
				s.Fields = fields
			}
			secret, cookie, _ := c.PasswordSigninCustody()
			other, e := identity.NewFeaturePasswordSigninCommand(s, secret, cookie)
			if e != nil {
				return r, e
			}
			if p.directApply {
				recipient, _, e := w.PasswordHashUpgradeSuccessor(p)
				if e != nil {
					return r, e
				}
				r, err = p.effect.Apply(ctx, w, p, other, recipient, p.flow)
			} else {
				r, err = p.effect.ApplyHashUpgrade(ctx, w, p, other, p.flow)
			}
			p.foreignAccepted = err == nil
			if p.ignoreApplyDenial {
				return identity.FeatureReceipt{Operation: s.Operation}, nil
			}
		} else {
			r, err = p.effect.ApplyHashUpgrade(ctx, w, p, c, p.flow)
		}
	} else {
		r, err = p.effect.Apply(ctx, w, p, c, p.recipient, p.flow)
	}
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return r, err
}
func (p *passwordSigninFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func testNativePasswordSigninEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('password-effect',1,true);
INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('password-effect','recipient','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('password-effect','recipient','password-a',1,'identity/password',9,true);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('password-effect','recipient','password-email','email','password-effect@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	scope := policy.AuthorityScope{TenantID: "password-effect", PolicyNamespace: "users", SubjectID: "recipient"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := NewPasswordSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"known", "anonymous", "csrf", "rollback", "audit-failure", "outbox-failure", "stale-credential", "stale-authorization", "consumed-flow", "wait-expiry", "credential-wait", "upgrade-known", "upgrade-anonymous", "upgrade-csrf", "upgrade-rollback", "upgrade-audit-failure", "upgrade-outbox-failure", "upgrade-unapplied", "upgrade-unprepared", "upgrade-foreign-command", "upgrade-apply-custody", "upgrade-apply-lookup", "upgrade-apply-lookup-known", "upgrade-apply-direct", "upgrade-apply-ignored", "upgrade-predecessor", "upgrade-wrong-successor", "upgrade-stale-authorization", "upgrade-wait-expiry", "upgrade-credential-wait"} {
		t.Run(mode, func(t *testing.T) {
			upgrading := strings.HasPrefix(mode, "upgrade-")
			baseMode := strings.TrimPrefix(mode, "upgrade-")
			if upgrading {
				for _, sql := range []string{`UPDATE identity.users SET version=11,authority_version=19,identifier_version=17,credential_version=13 WHERE tenant_id='password-effect'`, `UPDATE identity.credential_references SET version=7 WHERE tenant_id='password-effect'`} {
					if _, err := pool.Raw().Exec(ctx, sql); err != nil {
						t.Fatal(err)
					}
				}
				defer func() {
					for _, sql := range []string{`UPDATE identity.users SET version=1,authority_version=1,identifier_version=1,credential_version=1 WHERE tenant_id='password-effect'`, `UPDATE identity.credential_references SET version=9 WHERE tenant_id='password-effect'`} {
						if _, err := pool.Raw().Exec(ctx, sql); err != nil {
							t.Error(err)
						}
					}
				}()
			}
			known := baseMode == "known" || strings.HasSuffix(baseMode, "-known")
			f, original, secret, cookie := passwordSigninMappingFixture(t, !known, false)
			b := f.Binding
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.ActorID = "password-effect", "recipient"
			if known {
				b.UserID = "recipient"
			}
			f.Binding = b
			recipient, err := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "password-effect@example.test", Eligibility: kernel.RecipientVerified})
			if err != nil || recipient.Suppressed {
				t.Fatal("recipient unavailable", err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			s, _ := original.Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, "recipient", "password-session-"+mode, "password-family-"+mode
			s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
			s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject, s.Authentication.Proof.Audience = string(s.TenantID), string(s.UserID), profile.Audience
			s.Authentication.Proof.IssuedAt, s.Authentication.Proof.ExpiresAt = now, now.Add(time.Minute)
			if baseMode == "wait-expiry" {
				s.Authentication.Proof.ExpiresAt = now.Add(250 * time.Millisecond)
			}
			s.Audience = profile.Audience
			token, _ := session.NewToken(32)
			key, _ := session.NewDigestKey(1, bytes.Repeat([]byte{1}, 32))
			s.Lookup, err = token.Digest(key, string(s.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := scope.Key()
			a := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
			vector := session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)}
			if upgrading {
				vector.User.Version, vector.Identifier.Version, vector.Credential.Version = 19, 17, 14
				if baseMode == "predecessor" {
					vector.Credential.Version = 13
				}
				s.Authentication.CredentialVersion = 8
				if baseMode == "wrong-successor" {
					s.Authentication.CredentialVersion = 9
				}
			}
			s.Authority, err = session.NewAuthoritySnapshot(vector)
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSession(s)
			if err != nil {
				t.Fatal(err)
			}
			if baseMode == "csrf" {
				record = withCSRFState(t, record, 1)
			}
			f.Fields, err = PasswordSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			var upgrade *kernel.PasswordHashUpgradeIntent
			if upgrading {
				upgrade = &kernel.PasswordHashUpgradeIntent{Admission: kernel.CredentialAdmission{Credential: identity.CredentialRef{ID: "password-a", TenantID: b.TenantID, UserID: recipient.User.ID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 7}, UserAuthorityVersion: 19, IdentifierAuthorityVersion: 17, CredentialAuthorityVersion: 13}, ExpectedUserVersion: 11}
				fields, e := kernel.PasswordHashUpgradeFields(*upgrade)
				if e != nil {
					t.Fatal(e)
				}
				f.Fields = append(f.Fields, fields...)
			}
			command, err := identity.NewFeaturePasswordSigninCommand(f, secret, cookie)
			if err != nil {
				t.Fatal(err)
			}
			flowID, _ := identity.NewPreAuthTransactionID()
			var cookieDigest [32]byte
			copy(cookieDigest[:], []byte(flowID))
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: "https://app.example.test", CallbackURL: "https://app.example.test/callback", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 1, Sum: cookieDigest}, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertPreAuth(ctx, preAuthTestTx{tx}, config, flow); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
			if mode == "consumed-flow" {
				use := PreAuthUse{Command: b, Fingerprint: [32]byte{9}, Generation: 1}
				if err := ReservePreAuth(ctx, preAuthTestTx{tx}, config, flow, use); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				if err := FinalizePreAuth(ctx, preAuthTestTx{tx}, config, flow, use); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			feature := &passwordSigninFeature{effect: effect, op: f.Operation, recipient: recipient, flow: flow, fail: baseMode == "rollback", upgrade: upgrade, unapplied: baseMode == "unapplied", unprepared: baseMode == "unprepared", foreign: baseMode == "foreign-command"}
			feature.substituteApply = strings.HasPrefix(baseMode, "apply-")
			feature.alterLookup = feature.substituteApply && baseMode != "apply-custody"
			feature.directApply = baseMode == "apply-direct"
			feature.ignoreApplyDenial = baseMode == "apply-ignored"
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, &revokeAudit{fail: baseMode == "audit-failure"}, &revokeOutbox{fail: baseMode == "outbox-failure"}, feature})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			target := string(b.UserID)
			if target == "" {
				target = b.AnonymousFlowID
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, f.Operation, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: f.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if baseMode == "stale-credential" || baseMode == "stale-authorization" {
				table := "identity.credential_references"
				if baseMode == "stale-authorization" {
					table = "authorization_subject_authorities"
				}
				if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET version=version+1 WHERE tenant_id='password-effect'"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET version=version-1 WHERE tenant_id='password-effect'"); err != nil {
						t.Error(err)
					}
				}()
			}
			reservation, _, err := coordinator.ReserveCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			waitUntil := s.Authentication.Proof.ExpiresAt
			if baseMode == "credential-wait" {
				if err := pool.Raw().QueryRow(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '250 milliseconds' WHERE tenant_id='password-effect' RETURNING expires_at`).Scan(&waitUntil); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=NULL WHERE tenant_id='password-effect'`); err != nil {
						t.Error(err)
					}
				}()
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			var result identity.CommandResult
			if baseMode == "wait-expiry" || baseMode == "credential-wait" {
				result, err = applyOTPAfterFamilyWait(t, ctx, pool, coordinator, w, command, s, waitUntil)
			} else {
				result, err = coordinator.ApplyFeature(ctx, w, command)
			}
			if feature.foreignAccepted {
				t.Fatal("foreign paired command admitted during original invocation")
			}
			want := 0
			if baseMode == "known" || baseMode == "anonymous" || baseMode == "csrf" {
				if err != nil {
					t.Fatal("valid password session effect denied", err)
				}
				result, err = coordinator.Commit(w, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("effect commit failed", err)
				}
				want = 1
			} else {
				if err == nil {
					result, err = coordinator.Commit(w, result)
				} else {
					result, err = coordinator.Abort(w, err)
				}
				wantOutcome := identity.CommitOutcomeNotCommitted
				if baseMode == "audit-failure" {
					// Persistent audit failure also prevents the detached failure
					// receipt. Domain rollback does not prove terminal noncommit.
					wantOutcome = identity.CommitOutcomeUnknown
				}
				if result.Outcome != wantOutcome || err == nil {
					t.Fatal("denied effects escaped rollback", err)
				}
			}
			var sessions, families, issuances int
			wantFamilies := want
			if baseMode == "wait-expiry" || baseMode == "credential-wait" {
				wantFamilies = 1 // The locked pre-existing family survives rollback.
			}
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND family_id=$3),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$4),(SELECT state FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$5)`, string(s.TenantID), s.SessionID, s.FamilyID, mustCommandBytes(t, b.CommandID), string(flowID)).Scan(&sessions, &families, &issuances, &state); err != nil || sessions != want || families != wantFamilies || issuances != want {
				t.Fatalf("atomic effects %d/%d/%d: %v", sessions, families, issuances, err)
			}
			wantState := "issued"
			if want == 1 || mode == "consumed-flow" {
				wantState = "consumed"
			}
			if state != wantState {
				t.Fatal("pre-auth state not conserved")
			}
			if upgrading {
				var userVersion, authorityVersion, credentialVersion string
				if e := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,c.version::text FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) WHERE u.tenant_id='password-effect' AND u.user_id='recipient'`).Scan(&userVersion, &authorityVersion, &credentialVersion); e != nil || userVersion != strconv.Itoa(11+want) || authorityVersion != strconv.Itoa(13+want) || credentialVersion != strconv.Itoa(7+want) {
					t.Fatal("upgrade/session effects not atomic", e)
				}
			}
			if want == 1 {
				native, _ := NewRepository(pool, config)
				stored, err := native.Get(ctx, s.TenantID, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				a, _, _ := encodeRecord(record)
				got, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(a, got) {
					t.Fatal("original session changed")
				}
				retained, e := native.ReadPasswordSigninIdentity(ctx, b)
				if e != nil || retained.UserID != s.UserID || retained.SessionID != s.SessionID || retained.FamilyID != s.FamilyID {
					t.Fatal("primary password identity inspection lost original issuance", e)
				}
				if _, e := native.ReadOTPSigninIdentity(ctx, b); e == nil {
					t.Fatal("OTP inspection admitted password issuance")
				}
				_, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
				if err != nil || status != kernel.RecoveryCommitted {
					t.Fatal("retained recovery lost original issuance", err)
				}
				if mode == "anonymous" || mode == "known" {
					testRetainedPasswordIssuance(t, ctx, pool, b, s)
				}
			}
		})
	}
}

func testRetainedPasswordIssuance(t *testing.T, ctx context.Context, pool *database.Pool, b identity.CommandBinding, s session.SessionSpec) {
	t.Helper()
	read := func(want kernel.RecoveryStatus) {
		t.Helper()
		got, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
		if err != nil || status != want {
			t.Fatalf("retained password status=%v want=%v: %v", status, want, err)
		}
		if want == kernel.RecoveryCommitted {
			if got.UserID != s.UserID || got.SessionID != s.SessionID || got.FamilyID != s.FamilyID {
				t.Fatal("retained password identity changed")
			}
		} else if got != (OTPSigninIdentity{}) {
			t.Fatal("unproven retained identity disclosed")
		}
		native, e := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
		if e != nil {
			t.Fatal(e)
		}
		retained, e := native.ReadPasswordSigninIdentity(ctx, b)
		if want == kernel.RecoveryCommitted && (e != nil || retained.UserID != s.UserID || retained.SessionID != s.SessionID || retained.FamilyID != s.FamilyID) {
			t.Fatal("owned primary reader lost retained password identity", e)
		}
		if want == kernel.RecoveryNotCommitted && (!errors.Is(e, ErrRecordAbsent) || retained != (PasswordSigninIdentity{})) {
			t.Fatal("missing historical issuance fabricated retained identity", e)
		}
		foreign := b
		foreign.AnonymousFlowID = "AgICAgICAgICAgICAgICAg"
		if substituted, e := native.ReadPasswordSigninIdentity(ctx, foreign); e == nil || substituted != (PasswordSigninIdentity{}) {
			t.Fatal("retained identity disclosed for substituted original binding")
		}
	}
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	id := mustCommandBytes(t, b.CommandID)
	// Use a real foreign selected user so the FK admits the corruption and the
	// retained commitment decoder, rather than schema enforcement, denies it.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'changed-retained-identity','active',1) ON CONFLICT DO NOTHING`, string(s.TenantID)); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, column := range []string{"user_id", "session_id", "family_id"} {
		if _, err := tx.Exec(ctx, `SAVEPOINT retained_original`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`='changed-retained-identity' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		got, status, err := readNativeIssuanceIdentity(ctx, tx, `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
		if err != nil || status != kernel.RecoveryUnknown || got != (OTPSigninIdentity{}) {
			t.Fatal("corrupt retained tuple fabricated commit", err)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT retained_original`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE session_store.session_issuances SET record_digest=decode(repeat('00',32),'hex') WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	got, status, err := readNativeIssuanceIdentity(ctx, tx, `"session_store"`, b, kernel.LifecyclePlan{}, passwordIssuanceDigest)
	if err != nil || status != kernel.RecoveryUnknown || got != (OTPSigninIdentity{}) {
		t.Fatal("corrupt retained digest fabricated commit", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	native, e := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	for _, expired := range []bool{false, true} {
		bounded, cancel := context.WithCancel(ctx)
		cancel()
		if expired {
			bounded, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
		}
		got, e := native.ReadPasswordSigninIdentity(bounded, b)
		cancel()
		var cancelled identity.CancelledError
		var deadline identity.DeadlineExceededError
		if got != (PasswordSigninIdentity{}) || !expired && !errors.As(e, &cancelled) || expired && !errors.As(e, &deadline) {
			t.Fatal("retained password inspection lost cancellation/deadline classification", e)
		}
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.otp.signin" },
		func(b *identity.CommandBinding) { b.SchemaID = "identity-otp-signin" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.PolicyID = "foreign" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.CorrelationID = "foreign" },
		func(b *identity.CommandBinding) { b.CommandID, _ = identity.NewCommandID() },
	} {
		foreign := b
		mutate(&foreign)
		if got, e := native.ReadPasswordSigninIdentity(ctx, foreign); e == nil || got != (PasswordSigninIdentity{}) {
			t.Fatal("primary password inspection accepted substituted original scope")
		}
	}
	// Commit corruption only in this disposable fixture so the public PRIMARY
	// reader, rather than a borrowed test transaction, observes each mutation.
	for _, column := range []string{"user_id", "session_id", "family_id"} {
		var original string
		if e := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM session_store.session_issuances WHERE command_id=$1`, id).Scan(&original); e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`='changed-retained-identity' WHERE command_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		got, e := native.ReadPasswordSigninIdentity(ctx, b)
		if _, restore := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`=$2 WHERE command_id=$1`, id, original); restore != nil {
			t.Fatal("restore retained fixture")
		}
		if !errors.Is(e, ErrInvalidRecord) || got != (PasswordSigninIdentity{}) {
			t.Fatal("primary inspection disclosed corrupted retained identity", e)
		}
	}
	for _, column := range []string{"binding_digest", "record_digest"} {
		var original []byte
		if e := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM session_store.session_issuances WHERE command_id=$1`, id).Scan(&original); e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`=decode(repeat('00',32),'hex') WHERE command_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		got, e := native.ReadPasswordSigninIdentity(ctx, b)
		if _, restore := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`=$2 WHERE command_id=$1`, id, original); restore != nil {
			t.Fatal("restore retained commitment")
		}
		if !errors.Is(e, ErrInvalidRecord) || got != (PasswordSigninIdentity{}) {
			t.Fatal("primary inspection disclosed corrupted retained commitment", e)
		}
	}
	_, status, err = readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, otpIssuanceDigest)
	if err != nil || status != kernel.RecoveryUnknown {
		t.Fatal("OTP digest domain authenticated password evidence", err)
	}
	b.CommandID, _ = identity.NewCommandID()
	read(kernel.RecoveryNotCommitted)
}
