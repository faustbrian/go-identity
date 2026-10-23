//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresOTPDisableOneWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, mfaOTPDisable: true}, true)
}

func TestReferencePostgresOTPDisableAllWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, mfaOTPDisable: true, mfaOTPDisableAll: true}, true)
}

func TestReferencePostgresOTPDisableCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, mfaOTPDisable: true, completionCommitFault: true}, true)
}

func TestReferencePostgresOTPDisableCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, mfaOTPDisable: true, mfaOTPRemovalRace: true}, true)
}

func otpDisableSnapshot(t *testing.T, ctx context.Context, f liveStores) string {
	t.Helper()
	var value string
	err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities t),
 (SELECT jsonb_agg(to_jsonb(t) ORDER BY tenant_id,factor_id) FROM identity_mfa.otp_factors t),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,state,row_version) ORDER BY tenant_id,user_id,factor_id,state,row_version) FROM identity_mfa.recovery_sets),
 (SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id,used_purpose,used_at) ORDER BY proof_id) FROM identity_mfa.otp_factor_verifications),
 (SELECT count(*) FROM identity_mfa.otp_factor_update_effects),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.mfa.disable')
)::text`).Scan(&value)
	if err != nil {
		t.Fatal("OTP disable protected state unavailable", err)
	}
	return value
}

func proveReferenceOTPDisable(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer string, csrf session.CSRFToken, origin string, factor mfa.FactorID, user identity.UserID, proof auth.ReauthenticationProof) {
	t.Helper()
	owner, err := features.MFAOTPDisable()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("otp-disable-original"))
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.mfa.disable", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	r := mfa.DisableRequest{TenantID: otpTenant, Target: mfa.OneFactor, FactorID: factor, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key}
	if f.mfaOTPDisableAll {
		r.Target, r.FactorID = mfa.AllFactors, ""
	}
	before := otpDisableSnapshot(t, ctx, f)
	deny := func(name string, q mfa.DisableRequest) {
		t.Helper()
		q.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-disable-deny-" + name))
		out, e := owner.Disable(ctx, q)
		if e == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Factors != nil || otpDisableSnapshot(t, ctx, f) != before {
			t.Fatal(name, "changed protected state or returned factor metadata", e)
		}
	}
	wrong := r
	wrong.FactorProof.Purpose = "identity.mfa.factor-update"
	deny("wrong-purpose", wrong)
	wrong = r
	wrong.FactorProof.IssuedAt = wrong.FactorProof.IssuedAt.Add(time.Microsecond)
	deny("changed-proof", wrong)
	wrong = r
	wrong.CSRFToken = session.CSRFToken{}
	deny("missing-csrf", wrong)
	wrong = r
	wrong.Target, wrong.FactorID = mfa.OneFactor, "AAAAAAAAAAAAAAAAAAAABQ"
	deny("other-factor", wrong)
	var recipient string
	var verified time.Time
	if e := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND verified`, otpTenant, string(user)).Scan(&recipient, &verified); e != nil {
		t.Fatal(e)
	}
	if _, e := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), recipient); e != nil {
		t.Fatal(e)
	}
	deny("unusable-recovery", r)
	if _, e := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), recipient, verified); e != nil {
		t.Fatal(e)
	}
	if _, e := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.otp_disable_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic OTP disable rollback'; END $$; CREATE TRIGGER otp_disable_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.otp_disable_fixture_fail()`); e != nil {
		t.Fatal(e)
	}
	failed, e := owner.Disable(ctx, r)
	unchanged := otpDisableSnapshot(t, ctx, f) == before
	if e == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.Factors != nil || !unchanged {
		t.Fatalf("failed required effect did not roll back OTP disable: outcome=%v command=%t projection=%t unchanged=%t error=%v", failed.Outcome, failed.CommandID != "", failed.Factors != nil, unchanged, e)
	}
	if _, e := f.pool.Raw().Exec(ctx, `DROP TRIGGER otp_disable_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION public.otp_disable_fixture_fail()`); e != nil {
		t.Fatal(e)
	}
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-disable-after-rollback"))
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	var out mfa.DisableResult
	if f.mfaOTPRemovalRace {
		type result struct {
			out mfa.DisableResult
			err error
			key identity.IdempotencyKey
		}
		results := make(chan result, 2)
		start := make(chan struct{})
		for _, name := range []string{"otp-disable-race-a", "otp-disable-race-b"} {
			q := r
			q.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(name))
			go func() { <-start; got, err := owner.Disable(ctx, q); results <- result{got, err, q.IdempotencyKey} }()
		}
		close(start)
		wins := 0
		for range 2 {
			got := <-results
			if got.err == nil && got.out.Outcome == identity.CommitOutcomeCommitted {
				wins++
				out, r.IdempotencyKey = got.out, got.key
			} else if got.err == nil || got.out.Factors != nil || got.out.Outcome == identity.CommitOutcomeCommitted {
				t.Error("competing disable loser disclosed state")
			}
		}
		if wins != 1 {
			t.Fatal("competing OTP disables did not have one winner")
		}
	} else {
		out, err = owner.Disable(ctx, r)
	}
	if f.completionFault != nil {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID == "" || out.Factors != nil || !f.completionFault.hit.Load() {
			t.Fatal("lost actual COMMIT acknowledgment did not retain uncertainty", err)
		}
	} else {
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID == "" {
			t.Fatal("OTP disable failed", err)
		}
		if f.mfaOTPDisableAll {
			if len(out.Factors) != 0 {
				t.Fatal("all-target disable retained pending OTP metadata")
			}
		} else if len(out.Factors) != 1 || string(out.Factors[0].ID) != f.pendingDisableFactor || out.Factors[0].Method != "otp" || out.Factors[0].State != mfa.FactorPending || out.Factors[0].Version != 1 {
			t.Fatal("one-target disable did not preserve genuine pending sibling")
		}
	}
	var active, live, refs, uses, effects, revoked, events int
	id, _ := base64.RawURLEncoding.DecodeString(string(out.CommandID))
	if e := f.pool.Raw().QueryRow(ctx, `SELECT a.active_factors,
 (SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND state<>3),
 (SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND identifier_id IS NOT NULL),
 (SELECT count(*) FROM identity_mfa.otp_factor_verifications WHERE used_command_id=$3 AND used_purpose='identity.mfa.disable'),
 (SELECT count(*) FROM identity_mfa.otp_factor_update_effects WHERE command_id=$3 AND purpose='identity.mfa.disable' AND disable_target=$4),
 (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked'),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3)
 FROM identity_mfa.factor_authorities a WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user), id, int16(r.Target)).Scan(&active, &live, &refs, &uses, &effects, &revoked, &events); e != nil {
		t.Fatal(e)
	}
	want := 1
	if f.mfaOTPDisableAll {
		want = 0
	}
	if active != 0 || live != want || refs != want || uses != 1 || effects != 1 || revoked != 2 || events != 1 {
		t.Fatalf("OTP disable lost atomic effects: active=%d live=%d refs=%d uses=%d effects=%d revoked=%d events=%d", active, live, refs, uses, effects, revoked, events)
	}
	q := identity.RecoveryQuery{TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.disable", CommandID: out.CommandID}
	if got, e := owner.RecoverDisable(ctx, q, caller); e != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Factors != nil {
		t.Fatal("OTP disable recovery renewed proof or lost original outcome", e)
	}
	r.CommandID = out.CommandID
	if got, e := owner.Disable(ctx, r); e != nil || got.Outcome != identity.CommitOutcomeCommitted || got.CommandID != out.CommandID || got.Factors != nil {
		t.Fatal("OTP disable retry did not conserve original metadata-only outcome", e)
	}
	changed := r
	if r.Target == mfa.OneFactor {
		changed.Target, changed.FactorID = mfa.AllFactors, ""
	} else {
		changed.Target, changed.FactorID = mfa.OneFactor, factor
	}
	if got, e := owner.Disable(ctx, changed); e == nil || got.Outcome == identity.CommitOutcomeCommitted || got.Factors != nil {
		t.Fatal("same key changed original disable target", e)
	}
	before = otpDisableSnapshot(t, ctx, f)
	r.CommandID = ""
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-disable-fresh-reuse"))
	if got, e := owner.Disable(ctx, r); e == nil || got.Outcome == identity.CommitOutcomeCommitted || got.Factors != nil || otpDisableSnapshot(t, ctx, f) != before {
		t.Fatal("fresh command reused disabled factor custody", e)
	}
}
