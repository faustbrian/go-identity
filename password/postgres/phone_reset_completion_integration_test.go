//go:build integration

package passwordpostgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Actual registration, verified phone, confirmed independent factor, original
// browser, risk issuance and delivered SMS/capability precede this boundary.
// Only the external HIBP observation is controlled; no domain authority is fake.
func testNativePhoneResetCompletion(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, source phonePasswordRecoverySelection, fresh func() *PhonePasswordResetRequestService, crypto *envelope.Service, request phone.PasswordResetRequestRequestSpec, caller authorization.DecisionContext, command, issuance identity.CommandID, proof capability.Proof, code string, totpSecret []byte, evidence risk.RiskEvidenceRef, profile nativePhoneResetProfile, origin password.ResetGrantSpec) {
	t.Helper()
	// Install only the actual newly selected forward histories; prior password
	// and session tables contain the genuine enrollment/signin consumer state.
	replacement := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	for _, source := range []migrations.Source{
		kernel.PhonePasswordResetMigrationSource{Base: kernel.CredentialResetMigrationSource{Base: replacement, Version: 126}, Version: 127},
		PhonePasswordResetMigrationSource{Base: MigrationSource{}, Version: 128},
		sessionpg.PasswordResetMigrationSource{Schema: config.Session.Schema, Version: 130},
		sessionpg.PhonePasswordResetMigrationSource{Schema: config.Session.Schema, Version: 131},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if step.Version() < 126 {
				continue
			}
			if _, err = pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("native phone reset forward history", err)
			}
		}
	}
	base := signupScreeningPolicy(t)
	var profiles []risk.Profile
	for _, action := range []risk.Action{"identity.password.signin", "identity.password.change", "identity.admin.user-ban", "identity.session.get"} {
		admitted, err := base.Admit(action)
		if err != nil {
			t.Fatal(err)
		}
		if admitted.Profile.Class == risk.Authentication {
			// Status and carrier authority come from actual distinct completion
			// RiskEvidence and current Work fences. Screening owns only HIBP;
			// its existing protected lane defers velocity to that real owner.
			admitted.Profile.RequiredSignals = []string{"velocity"}
		}
		profiles = append(profiles, admitted.Profile)
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Profiles: profiles, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.phone.password-reset-complete"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := primitive.New(config.Repository.HashPolicy)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := passwords.Hash(ctx, []byte("phone-reset-public-test-dummy"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := mfapg.NewPhoneRecoveryTOTPVerifier(crypto, [32]byte{230}, 1)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	c := PhonePasswordResetCompletionConfig{ConfigurationID: "phone-reset-completion-v1", AttemptKeyVersion: 1, TOTP: verifier, Screening: password.HashPreparationConfig{Primitive: passwords, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: dummy, Policy: policy, Now: func() time.Time { return time.Now().UTC() }, Collect: func(ctx context.Context, scope risk.Context, _ primitive.Secret) ([]risk.Signal, error) {
		calls++
		fact, err := policy.PasswordSignal(ctx, scope, risk.PasswordObservation{ObservedAt: scope.Now, CheckedAt: scope.Now, ValidUntil: scope.Now.Add(time.Hour)})
		return []risk.Signal{fact}, err
	}}}
	completion := func() *PhonePasswordResetService {
		service, err := NewPhonePasswordResetService(fresh(), c)
		if err != nil {
			t.Fatal("actual native phone completion startup", err)
		}
		return service
	}
	service := completion()
	newPassword, _ := primitive.NewSecret([]byte(" exact new phone password "))
	defer newPassword.Destroy()
	sms, _ := auth.NewOneTimeCode(code)
	var now time.Time
	if err = pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	// Enrollment consumed its current step. The real authenticator supplies
	// the next step inside the explicitly configured one-step skew window.
	totp := testPhoneTOTPCode(t, totpSecret, now.Add(30*time.Second))
	if profile == phoneResetWrongSMSProfile {
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		sms, err = auth.NewOneTimeCode(wrong)
		if err != nil {
			t.Fatal(err)
		}
	}
	if profile == phoneResetWrongTOTPProfile {
		totp = testPhoneResetInvalidTOTP(t, totpSecret, now)
	}
	inputSpec := phone.PasswordResetCompleteRequestSpec{TenantID: request.TenantID, CommandID: command, Flow: request.Flow, ResetCapability: proof, PhoneCode: sms, IndependentTOTP: totp, RiskEvidence: evidence, RiskIssuanceCommandID: issuance, NewPassword: newPassword, Caller: caller, Origin: request.Origin, Network: request.Network, Device: request.Device}
	input, err := phone.NewPasswordResetCompleteRequest(inputSpec)
	if err != nil {
		t.Fatal(err)
	}
	var active int
	if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+config.Session.Schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(request.TenantID), string(source.recipient.User.ID)).Scan(&active); err != nil || active < 1 {
		t.Fatal("genuine issued-session revocation oracle missing", err, active)
	}
	before, err := fresh().read().source.passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: request.TenantID, SubjectID: source.recipient.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	if profile == phoneResetRollbackProfile {
		// The actual audit owner fails after provisional TOTP/password/session
		// effects; no consuming participant is replaced with a fake. A sequence
		// survives rollback to prove the successful audit INSERT was reached;
		// earlier denial and the later failure-audit path cannot advance it.
		if _, err = pool.Raw().Exec(ctx, `CREATE SEQUENCE audit.phone_reset_complete_reached;
ALTER TABLE audit.records ADD CONSTRAINT phone_reset_complete_stop CHECK(outcome<>1 OR nextval('audit.phone_reset_complete_reached')<0) NOT VALID`); err != nil {
			t.Fatal(err)
		}
	}
	result, err := service.PasswordResetComplete(ctx, input)
	if profile != phoneResetCompleteProfile {
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted || calls != 1 {
			t.Fatal("denied/failed completion reported committed or skipped real screening", err)
		}
		if profile == phoneResetRollbackProfile {
			var reached bool
			if err := pool.Raw().QueryRow(ctx, `SELECT is_called FROM audit.phone_reset_complete_reached`).Scan(&reached); err != nil || !reached {
				t.Fatal("rollback oracle did not reach required success-audit persistence after provisional mutation", err)
			}
		}
		after, err := fresh().read().source.passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: request.TenantID, SubjectID: source.recipient.User.ID})
		if err != nil || after.Authority() != before.Authority() || after.EncodedHash().String() != before.EncodedHash().String() {
			t.Fatal("failed completion changed original password or authority", err)
		}
		var retained int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+config.Session.Schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(request.TenantID), string(source.recipient.User.ID)).Scan(&retained); err != nil || retained != active {
			t.Fatal("failed completion changed genuine issued sessions", err)
		}
		metadata, err := source.factor.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		reader, err := mfapg.NewTOTPFactorReader(pool, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		factor, err := reader.ReadForPhoneRecovery(ctx, metadata.TenantID, metadata.UserID, metadata.FactorID)
		current, metadataErr := factor.Metadata()
		if err != nil || metadataErr != nil || current != metadata {
			t.Fatal("failed completion advanced independent TOTP replay or authority", err, metadataErr)
		}
		var state string
		if err = pool.Raw().QueryRow(ctx, `SELECT state FROM phone_reset_risk.issued_evidence WHERE record_id=$1`, string(issuance)).Scan(&state); err != nil || state == "finalized" {
			t.Fatal("failed completion consumed its distinct completion evidence", err)
		}
		var used, failed int
		if err = pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,state FROM phone_codes.challenges WHERE issue_command_purpose='identity.phone.password-reset-request'`).Scan(&used, &failed, &state); err != nil || used != 1 || state == "finalized" {
			t.Fatal("failed completion lost its single counted attempt or consumed SMS", err, used, failed)
		}
		if profile != phoneResetRollbackProfile && failed != 1 || profile == phoneResetRollbackProfile && failed != 0 {
			t.Fatal("wrong SMS/TOTP did not share counted denial semantics", failed)
		}
		return
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CredentialVersion != source.credential.Credential.Version+1 || !result.SessionsRevoked || calls != 1 {
		var used, failed int
		var state string
		observed := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,state FROM phone_codes.challenges WHERE issue_command_purpose='identity.phone.password-reset-request'`).Scan(&used, &failed, &state)
		t.Log("bounded attempt state", used, failed, state, observed)
		t.Fatal("actual phone reset did not atomically replace and revoke", err, result.Outcome, calls)
	}
	material, err := fresh().read().source.passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: request.TenantID, SubjectID: source.recipient.User.ID})
	if err != nil || material.Authority().Credential.Version != result.CredentialVersion {
		t.Fatal("phone reset successor missing", err)
	}
	match, err := passwords.Verify(ctx, []byte(" exact new phone password "), material.EncodedHash().String())
	if err != nil || !match.Match() {
		t.Fatal("phone reset altered the replacement password bytes", err)
	}
	var current int
	if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+config.Session.Schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, string(request.TenantID), string(source.recipient.User.ID)).Scan(&current); err != nil || current != 0 {
		t.Fatal("phone reset retained genuine active sessions", err, current)
	}
	q := identity.RecoveryQuery{CommandID: command, TenantID: request.TenantID, UserID: source.recipient.User.ID, RecordID: string(source.credential.Credential.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: phonePasswordResetOperation().OperationID}
	recoveryCaller := caller.Clone()
	recoveryCaller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	recovered, err := service.RecoverPasswordResetComplete(ctx, q, recoveryCaller)
	if err != nil || recovered != result || calls != 1 {
		t.Fatal("code-free recovery lost original reset or reran providers", err)
	}
	replayed, err := completion().PasswordResetComplete(ctx, input)
	if err != nil || replayed != result || calls != 1 {
		t.Fatal("fresh completion replay changed the historical result or reran screening", err)
	}
	testPhoneResetCompletionRateSource(t, ctx, pool, fresh, proof, request.Flow, caller, origin)
	changedPassword, _ := primitive.NewSecret([]byte("different replacement password"))
	defer changedPassword.Destroy()
	for _, tc := range []struct {
		name   string
		mutate func(*phone.PasswordResetCompleteRequestSpec)
	}{
		{"device", func(r *phone.PasswordResetCompleteRequestSpec) { r.Device = "different-recovery-browser" }},
		{"network", func(r *phone.PasswordResetCompleteRequestSpec) { r.Network = "192.0.2.2" }},
		{"origin", func(r *phone.PasswordResetCompleteRequestSpec) { r.Origin = "https://foreign.identity.test" }},
		{"evidence", func(r *phone.PasswordResetCompleteRequestSpec) { r.RiskEvidence = request.RiskEvidence }},
		{"issuance", func(r *phone.PasswordResetCompleteRequestSpec) { r.RiskIssuanceCommandID, _ = identity.NewCommandID() }},
		{"password", func(r *phone.PasswordResetCompleteRequestSpec) { r.NewPassword = changedPassword }},
	} {
		t.Run("terminal-retry-"+tc.name, func(t *testing.T) {
			changed := inputSpec
			tc.mutate(&changed)
			other, err := phone.NewPasswordResetCompleteRequest(changed)
			if err != nil {
				t.Fatal("changed retry did not reach native orchestration", err)
			}
			out, err := completion().PasswordResetComplete(ctx, other)
			if err == nil || out.Outcome == identity.CommitOutcomeCommitted || calls != 1 {
				t.Fatal("changed terminal retry was accepted or repeated providers", err)
			}
		})
	}
	// This full native slice uses the real existing material/session owners;
	// reference signin after replacement remains a separate composition check.
}

// Choose a well-formed numeric submission that differs from every currently
// admissible authenticator step (and the next boundary). Opaque digests compare
// test-owned values without exposing codes through formatting or accessors.
func testPhoneResetInvalidTOTP(t *testing.T, secret []byte, now time.Time) auth.OneTimeCode {
	t.Helper()
	key := [32]byte{231}
	valid := make(map[[32]byte]bool, 5)
	for offset := -1; offset <= 3; offset++ {
		actual := testPhoneTOTPCode(t, secret, now.Add(time.Duration(offset)*30*time.Second))
		digest, err := actual.CommandDigest(key, "test.phone.reset.totp")
		if err != nil {
			t.Fatal(err)
		}
		valid[digest] = true
	}
	for candidate := 0; candidate < 6; candidate++ {
		code, err := auth.NewOneTimeCode(fmt.Sprintf("%06d", candidate))
		if err != nil {
			t.Fatal(err)
		}
		digest, err := code.CommandDigest(key, "test.phone.reset.totp")
		if err != nil {
			t.Fatal(err)
		}
		if !valid[digest] {
			return code
		}
	}
	t.Fatal("could not choose an independently invalid authenticator code")
	return auth.OneTimeCode{}
}
