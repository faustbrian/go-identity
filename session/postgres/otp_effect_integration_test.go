//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// This deliberate OTP-phase seam isolates session-owned effect behavior under
// real sealed coordinator Work. It is NOT OTP cryptography, bearer possession,
// challenge/pre-auth finalization or proof of the public Send/Signin journey.
type otpEffectAdmission struct{}

func (*otpEffectAdmission) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}
}
func (*otpEffectAdmission) ValidateOTPAttemptCommand(identity.Command, kernel.OTPAttemptPlan) error {
	return nil
}
func (*otpEffectAdmission) RecordOTPAttemptDenial(context.Context, kernel.OTPAttemptWork) (kernel.OTPAttemptDisposition, error) {
	return kernel.OTPAttemptUnchanged, nil
}
func (*otpEffectAdmission) ReserveOTP(context.Context, kernel.OTPReservationWork) error { return nil }
func (*otpEffectAdmission) RebindOTP(context.Context, kernel.OTPReservationWork) error  { return nil }
func (*otpEffectAdmission) CheckOTP(context.Context, kernel.OTPApplyWork) error         { return nil }
func (*otpEffectAdmission) FinalizeOTP(context.Context, kernel.OTPFinalizeWork) error   { return nil }
func (*otpEffectAdmission) ReleaseOTP(context.Context, kernel.OTPReleaseWork) error     { return nil }
func (*otpEffectAdmission) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryNotCommitted, nil
}

type otpEffectFeature struct {
	otpEffectAdmission
	effect    *OTPSigninEffect
	op        identity.FeatureOperation
	recipient kernel.RecipientRecord
	fail      bool
}

func (*otpEffectFeature) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}
}
func (p *otpEffectFeature) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.op}
}
func (*otpEffectFeature) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	_, err := OTPSigninSession(command)
	return err
}
func (p *otpEffectFeature) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	r, err := p.effect.Apply(ctx, w, p, command, p.recipient)
	if err == nil && p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return r, err
}
func (p *otpEffectFeature) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.effect.Recover(ctx, w, p)
}

func testNativeOTPSessionEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('otp-effect',1,true);
 INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('otp-effect','recipient','active',1),('otp-effect','different-retained-identity','active',1);
 INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at)
 VALUES('otp-effect','recipient','01ARZ3NDEKTSV4RRFFQ69G5FAX','email','effect@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	scope := policy.AuthorityScope{TenantID: "otp-effect", PolicyNamespace: "users", SubjectID: "recipient"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := OTPAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a"}
	effect, err := NewOTPSigninEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"user", "anonymous", "csrf", "rollback", "stale-user", "stale-authorization", "wait-expiry"} {
		t.Run(mode, func(t *testing.T) {
			b := revokeBinding()
			b.CommandID, _ = identity.NewCommandID()
			b.TenantID, b.UserID, b.RecordID, b.OperationID, b.SchemaID = "otp-effect", "recipient", "", "identity.otp.signin", "identity-otp-signin"
			op := identity.FeatureOperation{Owner: "identity/otp", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
			if mode == "anonymous" || mode == "csrf" {
				b.UserID, b.AnonymousFlowID = "", "original-flow"
				op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
			}
			recipient, err := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "effect@example.test", Eligibility: kernel.RecipientVerified})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			s, _ := otpRecordFixture(t, false).Bindings()
			s.TenantID, s.UserID, s.SessionID, s.FamilyID = b.TenantID, recipient.User.ID, "effect-session-"+mode, "effect-family-"+mode
			s.Version, s.FamilyVersion, s.IssuedAt, s.LastActivityAt = 1, 1, now, now
			token, err := session.NewToken(32)
			if err != nil {
				t.Fatal(err)
			}
			key, err := session.NewDigestKey(1, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			s.Lookup, err = token.Digest(key, string(s.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: b.TenantID}, s.UserID)
			sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			pk, _ := scope.Key()
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global), Tenant: a(keys.Tenant), User: a(keys.User), Identifier: a(keys.Identifier), Credential: a(keys.Credential), SessionFamily: a(sk.Family), Session: a(sk.Session), Authorization: a(pk)})
			if err != nil {
				t.Fatal(err)
			}
			p, _ := otpRecordFixture(t, false).OTPAuthentication().Bindings()
			p.CommandID, p.AttemptID, p.IdentifierID, p.IdentifierKind = b.CommandID, string(b.CommandID), recipient.Identifier.ID, recipient.Identifier.Kind
			p.IdentifierVersion, p.VerificationVersion, p.AuthenticatedAt, p.ValidUntil = recipient.Identifier.Version, recipient.Verification.Version, now, now.Add(time.Minute)
			if mode == "wait-expiry" {
				p.ValidUntil = now.Add(250 * time.Millisecond)
			}
			metadata, err := session.NewOTPAuthentication(p)
			if err != nil {
				t.Fatal(err)
			}
			record, err := session.NewSessionWithOTP(s, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "csrf" {
				csrf, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: 1}, KeyVersion: 1, Digest: [32]byte{1}})
				if err != nil {
					t.Fatal(err)
				}
				record, err = session.NewSessionWithOTPAndCSRF(s, metadata, csrf)
				if err != nil {
					t.Fatal(err)
				}
			}
			fields, err := OTPSigninSessionFields(record)
			if err != nil {
				t.Fatal(err)
			}
			code, _ := auth.NewOneTimeCode("123456")
			command, err := identity.NewFeatureOneTimeCodeCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, code)
			if err != nil {
				t.Fatal(err)
			}
			feature := &otpEffectFeature{effect: effect, op: op, recipient: recipient, fail: mode == "rollback"}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, &revokeAudit{}, &revokeOutbox{}, feature})
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
			seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: "identity.otp.signin", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprint(b.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": "0", "retention.class": "standard"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := coordinator.PrepareOTPReservationPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: feature.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1"}, OTP: &kernel.OTPAttemptPlan{AttemptID: p.AttemptID, AttemptFingerprint: [32]byte{1}, FingerprintKeyVersion: 1, ChallengeID: p.ChallengeID, ScopeDigest: [32]byte{2}, DigestKeyVersion: 1, ExpectedVersion: 1, Mode: kernel.OTPConsume}, Audits: []kernel.AuditPlan{{EventType: "identity.otp.signin", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "standard", BindingDigest: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "stale-user" || mode == "stale-authorization" {
				table, column := "identity.users", "authority_version"
				if mode == "stale-authorization" {
					table, column = "authorization_subject_authorities", "version"
				}
				if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET "+column+"=2 WHERE tenant_id='otp-effect'"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, "UPDATE "+table+" SET "+column+"=1 WHERE tenant_id='otp-effect'"); err != nil {
						t.Error(err)
					}
				}()
			}
			reservation, _, err := coordinator.ReserveOTPCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			w, err := coordinator.Begin(ctx, reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer coordinator.Abort(w, identity.UnavailableError{})
			var result identity.CommandResult
			if mode == "wait-expiry" {
				result, err = applyOTPAfterFamilyWait(t, ctx, pool, coordinator, w, command, s, p.ValidUntil)
			} else {
				result, err = coordinator.ApplyFeature(ctx, w, command)
			}
			want := 1
			if feature.fail || mode == "stale-user" || mode == "stale-authorization" || mode == "wait-expiry" {
				want = 0
				if err == nil {
					t.Fatal("denied effect admitted")
				}
				aborted, abortErr := coordinator.Abort(w, err)
				if aborted.Outcome != identity.CommitOutcomeNotCommitted || abortErr == nil {
					t.Fatal("denied effect did not retain rollback outcome", abortErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				result, err = coordinator.Commit(w, result)
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("session effect did not commit", err)
				}
			}
			var sessions, families, issuances int
			wantFamily := want
			if mode == "wait-expiry" {
				wantFamily = 1 // The pre-existing locked family must survive denial.
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id='otp-effect' AND session_id=$1),(SELECT count(*) FROM session_store.families WHERE tenant_id='otp-effect' AND family_id=$2),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$3)`, s.SessionID, s.FamilyID, mustCommandBytes(t, b.CommandID)).Scan(&sessions, &families, &issuances); err != nil || sessions != want || families != wantFamily || issuances != want {
				t.Fatalf("atomic session/family/evidence %d/%d/%d: %v", sessions, families, issuances, err)
			}
			if want == 1 {
				native, _ := NewRepository(pool, config)
				stored, err := native.Get(ctx, s.TenantID, s.SessionID)
				if err != nil {
					t.Fatal(err)
				}
				a, _, _ := encodeRecord(record)
				b, _, _ := encodeRecord(stored.Session)
				if !bytes.Equal(a, b) {
					t.Fatal("original session changed")
				}
				var owner string
				if err := pool.Raw().QueryRow(ctx, `SELECT user_id FROM session_store.session_issuances WHERE command_id=$1`, mustCommandBytes(t, p.CommandID)).Scan(&owner); err != nil || owner != "recipient" {
					t.Fatal("anonymous flow replaced actual owner", err)
				}
				// Exercise the retained native decoder against actual committed
				// rows. This is not current disclosure authorization or proof of
				// the OTP owner's separate ambiguous-commit reconciliation.
				testRetainedOTPIssuance(t, ctx, pool, command, s)
			}
		})
	}
}

func applyOTPAfterFamilyWait(t *testing.T, ctx context.Context, pool *database.Pool, coordinator *kernel.Coordinator, w kernel.Work, command identity.Command, s session.SessionSpec, deadline time.Time) (identity.CommandResult, error) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(s.TenantID), s.FamilyID, string(s.UserID), s.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
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
	go func() {
		result, err := coordinator.ApplyFeature(bounded, w, command)
		completed <- applied{result, err}
	}()
	joined := false
	defer func() {
		if !joined {
			stop()
			<-completed
		}
	}()
	// Observe the actual family share-lock wait, then primary time crossing the
	// original deadline. No sleep is used as evidence that the writer blocked.
	for blocked, expired := false, false; !blocked || !expired; {
		var waiting bool
		// Separate autocommit observations avoid retaining the lock owner's
		// initial statistics snapshot across the polling transaction.
		if err := pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%session_store%.families%'),clock_timestamp()>$1`, deadline).Scan(&waiting, &expired); err != nil {
			t.Fatal("OTP family lock/deadline barrier", err)
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

func testRetainedOTPIssuance(t *testing.T, ctx context.Context, pool *database.Pool, command identity.Command, s session.SessionSpec) {
	t.Helper()
	f, _ := command.Feature()
	b := f.Binding
	native, err := NewRepository(pool, Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	read := func(want kernel.RecoveryStatus) {
		t.Helper()
		got, err := recoverOTPIssuance(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{})
		if err != nil || got != want {
			t.Fatalf("retained OTP issuance status=%v want=%v: %v", got, want, err)
		}
		projection, projectionErr := native.ReadOTPSigninIdentity(ctx, b)
		switch want {
		case kernel.RecoveryCommitted:
			if projectionErr != nil || projection.UserID != s.UserID || projection.SessionID != s.SessionID || projection.FamilyID != s.FamilyID {
				t.Fatal("original historical identity lost", projectionErr)
			}
		case kernel.RecoveryNotCommitted:
			if !errors.Is(projectionErr, ErrRecordAbsent) || projection != (OTPSigninIdentity{}) {
				t.Fatal("missing issuance fabricated identity", projectionErr)
			}
		case kernel.RecoveryUnknown:
			if !errors.Is(projectionErr, ErrInvalidRecord) || projection != (OTPSigninIdentity{}) {
				t.Fatal("corrupt commitment disclosed identity", projectionErr)
			}
		}
	}
	read(kernel.RecoveryCommitted)
	for _, expired := range []bool{false, true} {
		bounded, cancel := context.WithCancel(ctx)
		if expired {
			cancel()
			bounded, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		got, err := native.ReadOTPSigninIdentity(bounded, b)
		cancel()
		var cancelled identity.CancelledError
		var deadline identity.DeadlineExceededError
		if got != (OTPSigninIdentity{}) || (!expired && !errors.As(err, &cancelled)) || (expired && !errors.As(err, &deadline)) {
			t.Fatal("historical read lost cancellation/deadline classification", err)
		}
	}
	for _, changed := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other-tenant" },
		func(b *identity.CommandBinding) { b.ActorID = "other-actor" },
		func(b *identity.CommandBinding) { b.CorrelationID = "other-correlation" },
		func(b *identity.CommandBinding) { b.PolicyVersion++ },
		func(b *identity.CommandBinding) { b.OperationID = "identity.session.issue" },
	} {
		other := b
		changed(&other)
		if got, err := native.ReadOTPSigninIdentity(ctx, other); err == nil || got != (OTPSigninIdentity{}) {
			t.Fatal("changed historical scope disclosed identity")
		}
	}
	// Retiring the live payload must not turn a historical commit into rollback.
	if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	id := mustCommandBytes(t, b.CommandID)
	for _, column := range []string{"user_id", "session_id", "family_id"} {
		var original string
		if err := pool.Raw().QueryRow(ctx, `SELECT `+column+` FROM session_store.session_issuances WHERE command_id=$1`, id).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`='different-retained-identity' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		defer func(column, original string) {
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`=$2 WHERE command_id=$1`, id, original); err != nil {
				t.Error(err)
			}
		}(column, original)
		read(kernel.RecoveryUnknown)
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET `+column+`=$2 WHERE command_id=$1`, id, original); err != nil {
			t.Fatal(err)
		}
	}
	var original []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record_digest FROM session_store.session_issuances WHERE command_id=$1`, id).Scan(&original); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET record_digest=$2 WHERE command_id=$1`, id, changed); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET record_digest=$2 WHERE command_id=$1`, id, original); err != nil {
			t.Error(err)
		}
	}()
	read(kernel.RecoveryUnknown)
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.session_issuances SET record_digest=$2 WHERE command_id=$1`, id, original); err != nil {
		t.Fatal(err)
	}
	read(kernel.RecoveryCommitted)
	b.CommandID, _ = identity.NewCommandID()
	read(kernel.RecoveryNotCommitted)
}
