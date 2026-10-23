//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

// Only protected metadata is observed. Codes, recipient values, credentials,
// signatures, ciphertext and lookup digests never enter test diagnostics.
func otpActiveProtectedState(t *testing.T, ctx context.Context, f liveStores) string {
	t.Helper()
	var state string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,state,row_version) ORDER BY tenant_id,user_id,factor_id) FROM identity_mfa.otp_factors),
 (SELECT count(*) FROM identity_mfa.otp_factor_verifications),
 (SELECT jsonb_agg(jsonb_build_array(session_id,state,version) ORDER BY session_id) FROM session_store.sessions)
 )::text`).Scan(&state); err != nil {
		t.Fatal("active OTP protected metadata unavailable", err)
	}
	return state
}

type otpActiveAttemptState struct {
	state        string
	used, failed int
	consumed     bool
}

func otpActiveAttempts(t *testing.T, ctx context.Context, f liveStores, r mfa.OtpVerifyRequest) otpActiveAttemptState {
	t.Helper()
	var s otpActiveAttemptState
	if err := f.pool.Raw().QueryRow(ctx, `SELECT state,used_attempts,failed_attempts,consumer_command_id IS NOT NULL FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(r.TenantID), string(r.StepUp.SendCommandID)).Scan(&s.state, &s.used, &s.failed, &s.consumed); err != nil {
		t.Fatal("active OTP attempt metadata unavailable", err)
	}
	return s
}

func requireOTPActiveDenial(t *testing.T, out mfa.OtpVerifyResult, err error) {
	t.Helper()
	if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.StepUpProof.Bindings().Proof.ID != "" || out.Session.Token != (session.Token{}) {
		t.Fatalf("active OTP denial: error_present=%t outcome=%v proof_present=%t session_present=%t", err != nil, out.Outcome, out.StepUpProof.Bindings().Proof.ID != "", out.Session.Token != (session.Token{}))
	}
}

func proveOTPActiveCustodyDenials(t *testing.T, ctx context.Context, f liveStores, owner mfa.OTPCompletionService, original mfa.OtpVerifyRequest, previous mfa.OTPAuthenticatedStepUp) {
	t.Helper()
	var priorSend []byte
	current, _ := base64.RawURLEncoding.DecodeString(string(original.StepUp.SendCommandID))
	if err := f.pool.Raw().QueryRow(ctx, `SELECT command_id FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.mfa.otp-send' AND state='committed' AND command_id<>$2 ORDER BY created_at LIMIT 1`, string(original.TenantID), current).Scan(&priorSend); err != nil {
		t.Fatal("genuine prior OTP send unavailable", err)
	}
	otherFactor, _ := identity.NewCommandID()
	before := otpActiveProtectedState(t, ctx, f)
	attempts := otpActiveAttempts(t, ctx, f, original)
	for name, change := range map[string]func(*mfa.OtpVerifyRequest){
		"prior-send": func(r *mfa.OtpVerifyRequest) {
			r.StepUp.SendCommandID = identity.CommandID(base64.RawURLEncoding.EncodeToString(priorSend))
		},
		"prior-session": func(r *mfa.OtpVerifyRequest) {
			send := r.StepUp.SendCommandID
			*r.StepUp = previous
			r.StepUp.SendCommandID = send
		},
		"other-factor": func(r *mfa.OtpVerifyRequest) { r.FactorID = mfa.FactorID(otherFactor) },
		"foreign-tenant": func(r *mfa.OtpVerifyRequest) {
			r.TenantID = "foreign-tenant"
			r.Caller.Request.Tenant = "foreign-tenant"
		},
		"wrong-csrf":     func(r *mfa.OtpVerifyRequest) { r.StepUp.CSRFToken, _ = session.NewCSRFToken() },
		"foreign-origin": func(r *mfa.OtpVerifyRequest) { r.Origin = "https://other.invalid" },
		"wrong-purpose":  func(r *mfa.OtpVerifyRequest) { r.StepUp.Purpose = "identity.mfa.recovery-regenerate" },
		"other-selected-purpose": func(r *mfa.OtpVerifyRequest) {
			r.StepUp.Purpose = "identity.mfa.disable"
			if original.StepUp.Purpose == "identity.mfa.disable" {
				r.StepUp.Purpose = "identity.mfa.factor-update"
			}
		},
		"mixed-enrollment": func(r *mfa.OtpVerifyRequest) {
			r.Enrollment = &mfa.OTPEnrollmentContext{Session: r.StepUp.Session, CSRFToken: r.StepUp.CSRFToken}
		},
	} {
		r, step := original, *original.StepUp
		r.StepUp = &step
		r.CommandID, _ = identity.NewCommandID()
		change(&r)
		out, err := owner.OtpVerify(ctx, r)
		requireOTPActiveDenial(t, out, err)
		if otpActiveProtectedState(t, ctx, f) != before || otpActiveAttempts(t, ctx, f, original) != attempts {
			t.Fatal(name, "changed protected state or charged the original challenge")
		}
	}
	// Change current primary/recipient authority, not request projections. Restore
	// only these fixture flags; never rewind a version or recreate a credential.
	var identifier string
	var verifiedAt time.Time
	var primary bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT i.identifier_id,i.verified_at,i.is_primary FROM identity.identifiers i JOIN identity_mfa.otp_factors f USING(tenant_id,user_id,identifier_id) WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(original.TenantID), string(original.FactorID)).Scan(&identifier, &verifiedAt, &primary); err != nil {
		t.Fatal("original verified recipient metadata unavailable", err)
	}
	var credential string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND kind=1 AND enabled`, string(original.TenantID), string(original.Caller.Request.Subject.ID)).Scan(&credential); err != nil {
		t.Fatal("original enabled credential metadata unavailable", err)
	}
	for _, recipient := range []bool{true, false} {
		var query, restore string
		var args []any
		if recipient {
			query = `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND identifier_id=$2`
			restore = `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$3,is_primary=$4 WHERE tenant_id=$1 AND identifier_id=$2`
			args = []any{string(original.TenantID), identifier}
		} else {
			query = `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND credential_id=$2 AND kind=1 AND enabled`
			restore = `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1 AND credential_id=$2 AND kind=1 AND NOT enabled`
			args = []any{string(original.TenantID), credential}
		}
		func() {
			if tag, err := f.pool.Raw().Exec(ctx, query, args...); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("owned authority change failed", err)
			}
			defer func() {
				bounded, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if recipient {
					args = append(args, verifiedAt, primary)
				}
				if _, err := f.pool.Raw().Exec(bounded, restore, args...); err != nil {
					t.Error("owned authority restoration failed", err)
				}
			}()
			r := original
			r.CommandID, _ = identity.NewCommandID()
			out, err := owner.OtpVerify(ctx, r)
			requireOTPActiveDenial(t, out, err)
			if otpActiveProtectedState(t, ctx, f) != before || otpActiveAttempts(t, ctx, f, original) != attempts {
				t.Fatal("authority denial changed protected state or charged OTP")
			}
		}()
	}
}

func proveOTPActiveBudget(t *testing.T, ctx context.Context, f liveStores, owner mfa.OTPCompletionService, original mfa.OtpVerifyRequest, wrong string) {
	t.Helper()
	before := otpActiveProtectedState(t, ctx, f)
	initial := otpActiveAttempts(t, ctx, f, original)
	if initial.state != "issued" || initial.used != 0 || initial.failed != 0 || initial.consumed {
		t.Fatal("active challenge did not begin unused")
	}
	for attempt := 1; attempt <= 3; attempt++ {
		r := original
		r.CommandID, _ = identity.NewCommandID()
		r.Code, _ = auth.NewOneTimeCode(wrong)
		out, err := owner.OtpVerify(ctx, r)
		requireOTPActiveDenial(t, out, err)
		s := otpActiveAttempts(t, ctx, f, original)
		want := "issued"
		if attempt == 3 {
			want = "exhausted"
		}
		if s.state != want || s.used != attempt || s.failed != attempt || s.consumed || otpActiveProtectedState(t, ctx, f) != before {
			t.Fatal("wrong active code did not debit exactly one attempt without proof")
		}
		out, err = owner.OtpVerify(ctx, r)
		// The native coordinator returns a historical terminal result without
		// re-executing it; an absent retry error does not mean authentication.
		if err != nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.StepUpProof.Bindings().Proof.ID != "" || out.Session.Token != (session.Token{}) {
			t.Fatal("exact wrong-code retry did not retain its metadata-only denial")
		}
		if otpActiveAttempts(t, ctx, f, original) != s {
			t.Fatal("exact active verification retry debited twice")
		}
	}
	r := original
	r.CommandID, _ = identity.NewCommandID()
	out, err := owner.OtpVerify(ctx, r)
	requireOTPActiveDenial(t, out, err)
	if otpActiveProtectedState(t, ctx, f) != before || otpActiveAttempts(t, ctx, f, original).state != "exhausted" {
		t.Fatal("correct code escaped exhausted original challenge")
	}
}

func waitOTPActiveUntil(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("original OTP deadline wait interrupted")
	}
}

func proveOTPActiveLockExpiry(t *testing.T, ctx context.Context, f liveStores, owner mfa.OTPCompletionService, original mfa.OtpVerifyRequest) {
	t.Helper()
	before := otpActiveProtectedState(t, ctx, f)
	var expires time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT expires_at FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(original.TenantID), string(original.StepUp.SendCommandID)).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	gate, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = gate.Rollback(bounded)
	}()
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(77092031)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.otp_active_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(77092031); RETURN NEW; END $$; CREATE TRIGGER otp_active_pause BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.otp_active_pause()`); err != nil {
		t.Fatal("owned OTP lock fixture unavailable", err)
	}
	work, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = gate.Rollback(bounded)
		workers.Wait()
		if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER otp_active_pause ON public.identity_outbox_bindings; DROP FUNCTION public.otp_active_pause()`); err != nil {
			t.Error("owned OTP lock fixture cleanup failed", err)
		}
	}()
	type result struct {
		out mfa.OtpVerifyResult
		err error
	}
	done := make(chan result, 1)
	workers.Add(1)
	go func() { defer workers.Done(); out, err := owner.OtpVerify(work, original); done <- result{out, err} }()
	bounded, stop := context.WithTimeout(ctx, time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer stop()
	defer tick.Stop()
	for {
		var blocked bool
		if err := f.pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO public.identity_outbox_bindings%')`).Scan(&blocked); err != nil {
			t.Fatal("bounded OTP lock observation failed", err)
		}
		if blocked {
			break
		}
		select {
		case <-tick.C:
		case <-bounded.Done():
			t.Fatal("OTP verification did not reach protected lifecycle wait")
		}
	}
	waitOTPActiveUntil(t, ctx, expires.Add(30*time.Millisecond))
	if err := gate.Commit(ctx); err != nil {
		t.Fatal("owned OTP lock release failed", err)
	}
	select {
	case got := <-done:
		requireOTPActiveDenial(t, got.out, got.err)
	case <-ctx.Done():
		t.Fatal("OTP verification did not finish after lock release")
	}
	if otpActiveProtectedState(t, ctx, f) != before || otpActiveAttempts(t, ctx, f, original).state == "finalized" {
		t.Fatal("expired OTP wait retained protected consumption or proof")
	}
}

func proveOTPActiveObservationExpiry(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, owner mfa.OTPCompletionService, original mfa.OtpVerifyRequest) {
	t.Helper()
	before := otpActiveProtectedState(t, ctx, f)
	if f.completionFault == nil {
		t.Fatal("actual preparation COMMIT fault not selected")
	}
	f.completionFault.armed.Store(true)
	out, err := owner.OtpVerify(ctx, original)
	if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.StepUpProof.Bindings().Proof.ID != "" || !f.completionFault.hit.Load() {
		t.Fatal("actual preparation acknowledgement loss was not retained as unknown", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	var created time.Time
	var generation string
	var retained bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT created_at,preparation_ciphertext_generation::text,preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, raw).Scan(&created, &generation, &retained); err != nil || !retained || generation == "" {
		t.Fatal("original active preparation was not retained", err)
	}
	// The journal is created after the authoritative read begins. Waiting from
	// its creation therefore exceeds the original immutable 20-second lease.
	waitOTPActiveUntil(t, ctx, created.Add(20*time.Second+30*time.Millisecond))
	token, err := session.ParseToken(original.StepUp.Session.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if current, err := sessions.Get(ctx, session.GetRequest{TenantID: original.TenantID, Credential: credential}); err != nil || !current.Authenticated {
		t.Fatal("source credential expired instead of retained observation", err)
	}
	out, err = owner.OtpVerify(ctx, original)
	requireOTPActiveDenial(t, out, err)
	var unchanged bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT preparation_ciphertext_generation::text=$2 AND preparation_started_generation::text=$2 AND preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, raw, generation).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("expired original preparation was regenerated", err)
	}
	if otpActiveProtectedState(t, ctx, f) != before || otpActiveAttempts(t, ctx, f, original).state == "finalized" {
		t.Fatal("fresh read renewed expired command authority")
	}
}
