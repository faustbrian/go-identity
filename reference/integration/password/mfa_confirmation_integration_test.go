//go:build integration

package passwordintegration_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

func testPublicTOTPConfirmation(t *testing.T, ctx context.Context, pool *database.Pool, enroller *mfapg.TOTPEnrollmentService, primary *passworddb.MFAEnablePrimarySource, reveal mfa.TotpUriRequest, secret []byte, sessionSchema string, cfg mfapg.TOTPEnrollmentConfig, keys *keyring.Provider) {
	t.Helper()
	service, err := mfapg.NewTOTPConfirmationService(enroller, mfapg.TOTPConfirmationConfig{Primary: primary, AllowedOrigins: []string{"https://app.test"}, ComparisonKey: [32]byte{92}, ComparisonKeyVersion: 1})
	if err != nil {
		t.Fatal("native confirmation composition unavailable", err)
	}
	caller := reveal.Caller.Clone()
	caller.Request.Action = "identity.mfa.totp-verify"
	command, _ := identity.NewCommandID()
	var now time.Time
	if pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
		t.Fatal("authoritative fixture time unavailable")
	}
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, secret)
	_, _ = h.Write(step[:])
	digest := h.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 15
	code, _ := auth.NewOneTimeCode(fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000))
	r := mfa.TotpVerifyRequest{TenantID: reveal.TenantID, CommandID: command, FactorID: mfa.FactorID(reveal.EnrollmentID), Code: code, Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: reveal.Session, CSRFToken: reveal.CSRFToken}, Caller: caller, Origin: reveal.Origin, Network: reveal.Network}
	sessionSnapshot := func() string {
		t.Helper()
		var wire string
		if pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY session_id),'[]'::jsonb)::text FROM `+pgx.Identifier{sessionSchema, "sessions"}.Sanitize()+` s WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(caller.Request.Subject.ID)).Scan(&wire) != nil {
			t.Fatal("original session snapshot unavailable")
		}
		return wire
	}
	beforeSessions := sessionSnapshot()
	wrongCSRF, _ := session.NewCSRFToken()
	for _, change := range []func(*mfa.TotpVerifyRequest){
		func(r *mfa.TotpVerifyRequest) { r.Enrollment.CSRFToken = wrongCSRF },
		func(r *mfa.TotpVerifyRequest) {
			r.Enrollment.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		func(r *mfa.TotpVerifyRequest) { r.Origin = "https://foreign.test" },
	} {
		candidate := r
		possession := *r.Enrollment
		candidate.Enrollment = &possession
		candidate.CommandID, _ = identity.NewCommandID()
		change(&candidate)
		if denied, err := service.TotpVerify(ctx, candidate); err == nil || denied.Enrollment.ID != "" {
			t.Fatal("foreign confirmation possession or origin admitted")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if denied, err := service.TotpVerify(canceled, r); err == nil || denied.Enrollment.ID != "" {
		t.Fatal("canceled confirmation activated factor")
	}
	wrong := r
	wrong.CommandID, _ = identity.NewCommandID()
	wrong.Code, _ = auth.NewOneTimeCode("0000000")
	if denied, err := service.TotpVerify(ctx, wrong); err == nil || denied.Enrollment.ID != "" || denied.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("invalid confirmation code activated pending factor")
	}
	assertState := func(wantFactor, wantRecovery, wantActive int16) {
		t.Helper()
		var factor, recovery, active int16
		if pool.Raw().QueryRow(ctx, `SELECT f.state,r.state,a.active_factors FROM identity_mfa.totp_factors f JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.set_id=f.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&factor, &recovery, &active) != nil || factor != wantFactor || recovery != wantRecovery || active != wantActive {
			t.Fatal("confirmation factor/recovery/authority transition is not atomic")
		}
	}
	assertState(1, 1, 0)
	// Fail after factor activation, before recovery/authority/lifecycle commit.
	if _, err = pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_mfa_activation_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN IF NEW.state=2 THEN RAISE EXCEPTION 'fixture rollback'; END IF; RETURN NEW; END $fn$; CREATE TRIGGER reject_mfa_activation_fixture AFTER UPDATE ON identity_mfa.totp_factors FOR EACH ROW EXECUTE FUNCTION public.reject_mfa_activation_fixture()`); err != nil {
		t.Fatal("activation rollback fixture unavailable")
	}
	rollback := r
	rollback.CommandID, _ = identity.NewCommandID()
	denied, err := service.TotpVerify(ctx, rollback)
	if _, cleanup := pool.Raw().Exec(ctx, `DROP TRIGGER reject_mfa_activation_fixture ON identity_mfa.totp_factors; DROP FUNCTION public.reject_mfa_activation_fixture()`); cleanup != nil {
		t.Fatal("activation rollback fixture cleanup failed")
	}
	if err == nil || denied.Enrollment.ID != "" || denied.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatalf("failed activation disclosed success: outcome=%d error=%T", denied.Outcome, err)
	}
	assertState(1, 1, 0)
	beforeCommit := r
	beforeCommit.CommandID, _ = identity.NewCommandID()
	testTOTPConfirmationAmbiguity(t, ctx, pool, cfg, keys, primary, beforeCommit, true)
	assertState(1, 1, 0)
	testTOTPConfirmationAmbiguity(t, ctx, pool, cfg, keys, primary, r, false)
	out, err := service.TotpVerify(ctx, r)
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Enrollment.ID != reveal.EnrollmentID || out.Enrollment.Version != 3 {
		t.Fatalf("public native confirmation failed: outcome=%d error=%T", out.Outcome, err)
	}
	assertState(2, 2, 1)
	if sessionSnapshot() != beforeSessions {
		t.Fatal("enrollment confirmation silently promoted, replaced or revoked original sessions")
	}
	var recorded bool
	if pool.Raw().QueryRow(ctx, `SELECT confirmed_at IS NOT NULL AND last_step IS NOT NULL AND activation_command_id IS NOT NULL FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&recorded) != nil || !recorded {
		t.Fatal("confirmation lacks replay and original-command attribution")
	}
	replay, err := service.TotpVerify(ctx, r)
	if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Enrollment != out.Enrollment {
		t.Fatalf("confirmation retry lost original outcome: outcome=%d error=%T", replay.Outcome, err)
	}
	alternate := r
	alternate.CommandID, _ = identity.NewCommandID()
	if denied, err := service.TotpVerify(ctx, alternate); err == nil || denied.Enrollment.ID != "" {
		t.Fatal("another confirmation reactivated active factor")
	}
	q := identity.RecoveryQuery{TenantID: r.TenantID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, RecordID: string(r.FactorID), OperationID: "identity.mfa.totp-verify", CommandID: r.CommandID}
	if recovered, err := service.RecoverTotpVerify(ctx, q, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Enrollment.ID != "" {
		t.Fatalf("secret-free activation recovery failed: outcome=%d error=%T", recovered.Outcome, err)
	}
}

func testTOTPConfirmationAmbiguity(t *testing.T, ctx context.Context, pool *database.Pool, cfg mfapg.TOTPEnrollmentConfig, keys *keyring.Provider, primary *passworddb.MFAEnablePrimarySource, r mfa.TotpVerifyRequest, before bool) {
	t.Helper()
	fault := &reauthenticationCommitFault{before: before, marker: []byte("UPDATE identity_mfa.totp_factors SET state=2")}
	faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal("confirmation fault pool unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if faultPool.Close(cleanup) != nil {
			t.Error("confirmation fault pool cleanup failed")
		}
	}()
	cfg.Coordinator.LeaseDuration = 500 * time.Millisecond
	enroller, err := mfapg.NewTOTPEnrollmentService(faultPool, cfg, keys)
	if err != nil {
		t.Fatal("confirmation fault enrollment composition rejected")
	}
	service, err := mfapg.NewTOTPConfirmationService(enroller, mfapg.TOTPConfirmationConfig{Primary: primary, AllowedOrigins: []string{"https://app.test"}, ComparisonKey: [32]byte{92}, ComparisonKeyVersion: 1})
	if err != nil {
		t.Fatal("confirmation fault composition rejected")
	}
	out, err := service.TotpVerify(ctx, r)
	if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.Enrollment.ID != "" || !fault.hit.Load() {
		t.Fatalf("ambiguous activation fabricated success: outcome=%d error=%T hit=%t", out.Outcome, err, fault.hit.Load())
	}
	q := identity.RecoveryQuery{TenantID: r.TenantID, UserID: identity.UserID(r.Caller.Request.Subject.ID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, RecordID: string(r.FactorID), OperationID: "identity.mfa.totp-verify", CommandID: r.CommandID}
	want := identity.CommitOutcomeCommitted
	if before {
		want = identity.CommitOutcomeNotCommitted
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		recovered, err := service.RecoverTotpVerify(bounded, q, r.Caller)
		if recovered.Enrollment.ID != "" {
			t.Fatal("activation recovery returned authority metadata")
		}
		if recovered.Outcome == want {
			if !before && err != nil {
				t.Fatal("committed activation failed recovery")
			}
			break
		}
		select {
		case <-bounded.Done():
			t.Fatalf("activation ambiguity unresolved: outcome=%d error=%T", recovered.Outcome, err)
		case <-ticker.C:
		}
	}
	retry, err := service.TotpVerify(ctx, r)
	if retry.Outcome != want || before && retry.Enrollment.ID != "" || !before && err != nil {
		t.Fatalf("activation retry invented a successor: outcome=%d error=%T", retry.Outcome, err)
	}
}
