//go:build integration

package reference_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// Only protected public metadata/use flags are compared. Never serialize
// credential, proof payload, recipient, encrypted material or lookup digests.
func otpManagementState(t *testing.T, ctx context.Context, f liveStores) string {
	t.Helper()
	var state string
	err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,label,state,row_version,identifier_id IS NULL,identifier_version IS NULL,verification_version IS NULL) ORDER BY tenant_id,user_id,factor_id) FROM identity_mfa.otp_factors),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,set_id,state,row_version) ORDER BY tenant_id,user_id,set_id) FROM identity_mfa.recovery_sets),
 (SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id IS NOT NULL) ORDER BY proof_id) FROM identity_mfa.otp_factor_verifications),
 (SELECT count(*) FROM identity_mfa.otp_factor_update_effects),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.mfa.factor-update')
 )::text`).Scan(&state)
	if err != nil {
		t.Fatal("OTP management state unavailable", err)
	}
	return state
}

func proveOTPFactorRenameDenials(t *testing.T, ctx context.Context, f liveStores, owner mfa.FactorManagementService, original mfa.FactorUpdateRequest) {
	t.Helper()
	before := otpManagementState(t, ctx, f)
	for name, change := range map[string]func(*mfa.FactorUpdateRequest){
		"stale-version": func(r *mfa.FactorUpdateRequest) { r.ExpectedVersion++ },
		"changed-proof": func(r *mfa.FactorUpdateRequest) {
			r.FactorProof.IssuedAt = r.FactorProof.IssuedAt.Add(time.Microsecond)
		},
		"wrong-method":   func(r *mfa.FactorUpdateRequest) { r.FactorProof.Method = "totp" },
		"wrong-purpose":  func(r *mfa.FactorUpdateRequest) { r.FactorProof.Purpose = "identity.mfa.recovery-regenerate" },
		"foreign-origin": func(r *mfa.FactorUpdateRequest) { r.Origin = "https://other.invalid" },
		"wrong-csrf":     func(r *mfa.FactorUpdateRequest) { r.CSRFToken, _ = session.NewCSRFToken() },
	} {
		r := original
		change(&r)
		r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-rename-denial-" + name))
		if err := r.Validate(); err != nil && name != "wrong-purpose" {
			t.Fatal(name, "did not reach the native contract", err)
		}
		out, err := owner.FactorUpdate(ctx, r)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Factor.ID != "" {
			t.Fatal(name, "was not denied without disclosure")
		}
		if otpManagementState(t, ctx, f) != before {
			t.Fatal(name, "changed protected OTP/proof/session state")
		}
	}
}

func proveOTPFactorRenameRollback(t *testing.T, ctx context.Context, f liveStores, owner mfa.FactorManagementService, request mfa.FactorUpdateRequest) {
	t.Helper()
	before := otpManagementState(t, ctx, f)
	_, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.otp_rename_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic OTP rename rollback'; END $$; CREATE TRIGGER otp_rename_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.otp_rename_fail()`)
	if err != nil {
		t.Fatal("owned OTP rename rollback fixture", err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if _, e := f.pool.Raw().Exec(bounded, `DROP TRIGGER otp_rename_fail ON public.identity_outbox_bindings; DROP FUNCTION public.otp_rename_fail()`); e != nil {
			t.Error("owned OTP rollback fixture cleanup", e)
		}
	}()
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-rename-required-effect-rollback"))
	out, err := owner.FactorUpdate(ctx, request)
	if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.CommandID == "" || out.Factor.ID != "" {
		t.Fatal("required effect failure did not abort OTP rename", out.Outcome, err)
	}
	if otpManagementState(t, ctx, f) != before {
		t.Fatal("OTP rename rollback retained factor/proof/session effects")
	}
}
