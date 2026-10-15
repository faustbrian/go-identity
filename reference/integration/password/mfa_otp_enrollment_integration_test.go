//go:build integration

package passwordintegration_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This is real pending-enrollment admission, not OTP confirmation or a login
// journey. It consumes the native primary exactly with pending/recovery state.
func testPublicOTPEnrollment(t *testing.T, ctx context.Context, pool *database.Pool, primary *passworddb.ReauthenticationService, verification passworddb.ReauthenticationRequest, original session.Session, keys *keyring.Provider, existing mfapg.TOTPEnrollmentConfig, request mfa.EnableRequest, beforeProvider *func(context.Context), sourceConfig passworddb.ReauthenticationConfig, confirmation string) {
	t.Helper()
	base := mfapg.TOTPActivationMigrationSource{Base: mfapg.URIRevealMigrationSource{Base: mfapg.RecoveryMigrationSource{Base: mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}, Version: 6}
	history, err := (mfapg.OTPFactorMigrationSource{Base: mfapg.FactorReferenceMigrationSource{Base: base, Version: 13}, Version: 14}).Load(ctx)
	if err != nil {
		t.Fatal("OTP enrollment history unavailable", err)
	}
	for _, item := range history {
		if item.Version() > 6 {
			if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
				t.Fatal("OTP enrollment installation failed", err)
			}
		}
	}
	cfg, err := mfapg.NewOTPEnrollmentConfig(existing.RequestKeys, [32]byte{84}, [32]byte{85}, 1, "totp-v1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConfigurationID, cfg.PolicyID, cfg.MaximumDuration, cfg.TTL, cfg.Primary = "otp-enrollment-test", existing.PolicyID, existing.MaximumDuration, existing.TTL, existing.Primary
	cfg.Coordinator, cfg.Risk, cfg.Counters = existing.Coordinator, existing.Risk, existing.Counters
	// Separate fixture deployment, same real protected policy and unchanged
	// limits. Its deliberate failed attempts must not exhaust the pre-existing
	// TOTP journey's protected budget before that journey reaches its assertions.
	cfg.Counters.Schema = "otp_enrollment_risk"
	riskHistory, err := (riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: cfg.Counters.Schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range riskHistory {
		if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
			t.Fatal("isolated OTP protected-risk fixture unavailable", err)
		}
	}
	service, err := mfapg.NewOTPEnrollmentService(pool, cfg, keys)
	if err != nil {
		t.Fatal("native OTP enrollment composition unavailable", err)
	}
	issued, err := primary.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("distinct OTP enrollment primary proof unavailable", err)
	}
	request.Reauthentication = issued.Proof
	request.FactorPolicy.Method = "otp"
	request.OTP = &mfa.OTPEnrollmentSelection{Channel: delivery.ChannelEmail, IdentifierID: "mfa-fixture-email"}
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("native-otp-enrollment"))
	request.Caller = request.Caller.Clone()
	b, _ := original.Bindings()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version) VALUES($1,$2,'otp-unverified','email','unverified@example.test',false,false,1,1,1)`, string(request.TenantID), b.UserID); err != nil {
		t.Fatal("recipient denial fixture unavailable", err)
	}
	if _, err := pool.Raw().Exec(ctx, `WITH owner AS (INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,'otp-foreign-owner','active',1) RETURNING tenant_id,user_id)
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) SELECT tenant_id,user_id,'foreign-identifier','email','foreign@example.test',true,false,1,2,1,clock_timestamp() FROM owner`, string(request.TenantID)); err != nil {
		t.Fatal("real foreign-owned recipient fixture unavailable", err)
	}
	for _, selection := range []mfa.OTPEnrollmentSelection{
		{Channel: delivery.ChannelSMS, IdentifierID: "mfa-fixture-email"},
		{Channel: delivery.ChannelEmail, IdentifierID: "otp-unverified"},
		{Channel: delivery.ChannelEmail, IdentifierID: "foreign-identifier"},
	} {
		candidate := request
		candidate.OTP = &selection
		candidate.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(fmt.Sprintf("denied-%s-%d", selection.IdentifierID, selection.Channel)))
		if denied, err := service.Enable(ctx, candidate); err == nil || len(denied.RecoveryMaterial.Codes) != 0 {
			t.Fatal("unverified, foreign or wrong-channel enrollment admitted")
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_otp_enrollment_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $fn$;
CREATE TRIGGER reject_otp_enrollment_fixture AFTER INSERT ON identity_mfa.otp_factors FOR EACH ROW EXECUTE FUNCTION public.reject_otp_enrollment_fixture()`); err != nil {
		t.Fatal(err)
	}
	rolled, rollbackErr := service.Enable(ctx, request)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_otp_enrollment_fixture ON identity_mfa.otp_factors; DROP FUNCTION public.reject_otp_enrollment_fixture()`); err != nil {
		t.Fatal(err)
	}
	if rollbackErr == nil || rolled.Outcome != identity.CommitOutcomeNotCommitted || len(rolled.RecoveryMaterial.Codes) != 0 {
		t.Fatal("failed pending enrollment disclosed recovery codes or claimed commitment")
	}
	var used bool
	var factors int64
	if err := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,(SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND proof_id=$3`, string(request.TenantID), b.UserID, string(issued.Proof.Proof.ID)).Scan(&used, &factors); err != nil || used || factors != 0 {
		t.Fatal("rollback retained OTP factor or consumed primary proof", err)
	}
	// A known rolled-back original command stays terminal. Its request key is
	// not authority to repeat a mutation; a new attempt explicitly uses a new key.
	retry, err := service.Enable(ctx, request)
	if err != nil || retry.Outcome != identity.CommitOutcomeNotCommitted || retry.CommandID != rolled.CommandID || len(retry.RecoveryMaterial.Codes) != 0 {
		t.Fatal("original rolled-back request changed outcome or regenerated material", err)
	}
	// The external provider seam runs after authenticated original preparation
	// and before the protected effect. Change the actual native recipient there:
	// retained permission or a clean provider answer cannot refresh its versions.
	fenced := request
	fenced.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("native-otp-recipient-changed"))
	*beforeProvider = func(providerContext context.Context) {
		*beforeProvider = nil
		if _, err := pool.Raw().Exec(providerContext, `UPDATE identity.identifiers SET version=version+1,verification_version=verification_version+1,verification_state=3,verified=false,is_primary=false WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='mfa-fixture-email'`, string(request.TenantID), b.UserID); err != nil {
			t.Error("native recipient authority change failed", err)
		}
	}
	denied, fenceErr := service.Enable(ctx, fenced)
	*beforeProvider = nil
	if fenceErr == nil || denied.Outcome == identity.CommitOutcomeCommitted || len(denied.RecoveryMaterial.Codes) != 0 {
		t.Fatalf("changed recipient admitted or disclosed enrollment output: outcome=%d error=%T", denied.Outcome, fenceErr)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,(SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND proof_id=$3`, string(request.TenantID), b.UserID, string(issued.Proof.Proof.ID)).Scan(&used, &factors); err != nil || used || factors != 0 {
		t.Fatal("recipient denial retained pending OTP or primary consumption", err)
	}
	// Reverify only the disposable fixture with a new version. New admission may
	// use that version; the denied original request remains terminal and unchanged.
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verification_version=verification_version+1,verification_state=2,verified=true,is_primary=true,verified_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='mfa-fixture-email'`, string(request.TenantID), b.UserID); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("native-otp-enrollment-successor-attempt"))
	result, err := service.Enable(ctx, request)
	defer func() {
		for _, code := range result.RecoveryMaterial.Codes {
			code.Destroy()
		}
	}()
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == rolled.CommandID || result.Enrollment.FactorMethod != "otp" || len(result.RecoveryMaterial.Codes) != 10 {
		t.Fatalf("native OTP pending enrollment failed: outcome=%d error=%T", result.Outcome, err)
	}
	wire, _ := base64.RawURLEncoding.Strict().DecodeString(string(result.CommandID))
	var state int16
	var active int32
	var identifier, method string
	var codes, charges int64
	var identifierVersion, verificationVersion string
	if err := pool.Raw().QueryRow(ctx, `SELECT f.state,a.active_factors,f.identifier_id,r.factor_method,
(SELECT count(*) FROM identity_mfa.recovery_codes c WHERE c.tenant_id=r.tenant_id AND c.set_id=r.set_id),
p.consumed_command_id=$3,(SELECT count(*) FROM otp_enrollment_risk.counter_charges c WHERE c.command_id=$3 AND c.allowed)
FROM identity_mfa.otp_factors f JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id)
JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id
JOIN identity_password.reauthentication_records p ON p.tenant_id=f.tenant_id AND p.proof_id=$4
WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(request.TenantID), string(result.Enrollment.ID), wire, string(issued.Proof.Proof.ID)).Scan(&state, &active, &identifier, &method, &codes, &used, &charges); err != nil || state != 1 || active != 0 || identifier != "mfa-fixture-email" || method != "otp" || codes != 10 || !used || charges != 1 {
		t.Fatal("pending OTP, recovery, primary and protected risk effects are not atomic", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT identifier_version::text,verification_version::text FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(request.TenantID), string(result.Enrollment.ID)).Scan(&identifierVersion, &verificationVersion); err != nil || identifierVersion != "2" || verificationVersion != "3" {
		t.Fatal("fresh OTP enrollment did not retain actual current recipient versions", err)
	}
	replay, err := service.Enable(ctx, request)
	if err != nil || replay.CommandID != result.CommandID || replay.Enrollment.ID != result.Enrollment.ID || len(replay.RecoveryMaterial.Codes) != 0 {
		t.Fatal("original pending enrollment retry regenerated or disclosed recovery material", err)
	}
	altered := request
	altered.OTP = &mfa.OTPEnrollmentSelection{Channel: delivery.ChannelEmail, IdentifierID: "otp-unverified"}
	if _, err := service.Enable(ctx, altered); err == nil {
		t.Fatal("same-key retry changed the original OTP recipient")
	}
	changedStore := cfg
	changedStore.Counters.Schema = existing.Counters.Schema
	misconfigured, err := mfapg.NewOTPEnrollmentService(pool, changedStore, keys)
	if err != nil {
		t.Fatal("otherwise valid changed-owner fixture rejected before request", err)
	}
	if replay, err := misconfigured.Enable(ctx, request); err == nil || len(replay.RecoveryMaterial.Codes) != 0 {
		t.Fatal("original OTP request restored with a different protected-counter owner")
	}
	restarted, err := mfapg.NewOTPEnrollmentService(pool, cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: result.CommandID, TenantID: request.TenantID, UserID: identity.UserID(b.UserID), ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.enable", RecordID: string(result.Enrollment.ID)}
	recovered, err := restarted.RecoverEnable(ctx, query, request.Caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != result.CommandID || len(recovered.RecoveryMaterial.Codes) != 0 {
		t.Fatal("code/proof-free original OTP enrollment recovery failed", err)
	}
	testPublicOTPEnrollmentSend(t, ctx, pool, service, cfg, sourceConfig, request, result, keys, confirmation, beforeProvider)
}
