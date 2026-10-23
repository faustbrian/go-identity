//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresOTPFactorRemovalWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true}, true)
}

func TestReferencePostgresOTPFactorRemovalCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, completionCommitFault: true}, true)
}

func TestReferencePostgresOTPFactorRemovalCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPActive: true, mfaOTPManage: true, mfaOTPRemoval: true, mfaOTPRemovalRace: true}, true)
}

func TestReferencePostgresTOTPFactorRemovalWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorRemoval: true}, true)
}

func proveOTPRemovalPasswordSignin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, browser []*http.Cookie, factor mfa.FactorID) session.Credential {
	t.Helper()
	login, token := referencePasswordLogin(t, ctx, f, client, base, origin, browser, f.removalSignin, "synthetic-registration-password", "registered@example.invalid")
	if !login.SignedIn {
		t.Fatal("removal left an unusable primary-password signin before reset")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("post-removal password session not usable", err)
	}
	bindings, err := current.Session.Bindings()
	if err != nil || bindings.Authentication.Proof.Method != "password" {
		t.Fatal("post-removal session retained the removed second factor", err)
	}
	listing, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := listing.List(ctx, mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "otp-removal-password-inventory"})
	if err != nil || inventory.RecoveryCodeCount != 0 {
		t.Fatal("revoked recovery set remained usable in safe inventory", err)
	}
	found := false
	for _, item := range inventory.Factors {
		if item.ID == factor {
			found = item.Method == "otp" && item.State == mfa.FactorRevoked
		}
	}
	if !found {
		t.Fatal("new primary session could not read revoked OTP metadata")
	}
	return credential
}

func proveOTPRemovalCompetingCommands(t *testing.T, ctx context.Context, owner mfa.FactorManagementService, r mfa.FactorUpdateRequest) (mfa.FactorUpdateResult, identity.IdempotencyKey) {
	t.Helper()
	type result struct {
		out mfa.FactorUpdateResult
		err error
		key identity.IdempotencyKey
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for _, key := range []string{"otp-removal-race-a", "otp-removal-race-b"} {
		request := r
		request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(key))
		go func() {
			<-start
			out, err := owner.FactorUpdate(ctx, request)
			results <- result{out, err, request.IdempotencyKey}
		}()
	}
	close(start)
	var winner mfa.FactorUpdateResult
	var winnerKey identity.IdempotencyKey
	wins := 0
	// Drain both bounded calls before returning; no worker can outlive its
	// database fixture. The caller's context bounds native Work and all IO.
	for range 2 {
		got := <-results
		if got.err == nil && got.out.Outcome == identity.CommitOutcomeCommitted && got.out.Factor.State == mfa.FactorRevoked {
			wins++
			winner = got.out
			winnerKey = got.key
		} else if got.out.Outcome == identity.CommitOutcomeCommitted || got.out.Factor.ID != "" {
			t.Error("losing OTP removal disclosed committed factor metadata", got.err)
		}
	}
	if wins != 1 {
		t.Fatal("one original OTP proof did not produce exactly one removal winner")
	}
	return winner, winnerKey
}

func proveOTPRemovalRecoveryDenials(t *testing.T, ctx context.Context, f liveStores, owner mfa.FactorManagementService, r mfa.FactorUpdateRequest) {
	t.Helper()
	deny := func(name string) {
		t.Helper()
		before := otpManagementState(t, ctx, f)
		r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-removal-recovery-" + name))
		out, err := owner.FactorUpdate(ctx, r)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Factor.ID != "" || otpManagementState(t, ctx, f) != before {
			t.Fatal(name, "allowed removal without usable recovery or changed protected state", err)
		}
	}
	// Match the selected reset owner's ambiguity rule, even for a disabled
	// duplicate. A verified email alone does not prove a usable reset workflow.
	for _, enabled := range []bool{true, false} {
		if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'otp-removal-ambiguous',1,'identity/password',1,$3)`, r.TenantID, r.FactorProof.Subject, enabled); err != nil {
			t.Fatal("owned ambiguous recovery fixture", err)
		}
		if enabled {
			deny("ambiguous-active-password")
		} else {
			deny("ambiguous-disabled-password")
		}
		if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id='otp-removal-ambiguous'`, r.TenantID, r.FactorProof.Subject); err != nil {
			t.Fatal("owned recovery fixture cleanup", err)
		}
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=2 WHERE tenant_id=$1 AND user_id=$2`, r.TenantID, r.FactorProof.Subject); err != nil {
		t.Fatal("owned nonsingle factor-authority fixture", err)
	}
	deny("nonsingle-factor-authority")
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, r.TenantID, r.FactorProof.Subject); err != nil {
		t.Fatal("owned factor-authority fixture cleanup", err)
	}
	var identifier string
	var verifiedAt time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND verified`, r.TenantID, r.FactorProof.Subject).Scan(&identifier, &verifiedAt); err != nil {
		t.Fatal("original recovery identifier unavailable", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, r.TenantID, r.FactorProof.Subject, identifier); err != nil {
		t.Fatal("owned recovery withdrawal", err)
	}
	deny("unverified-email")
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, r.TenantID, r.FactorProof.Subject, identifier, verifiedAt); err != nil {
		t.Fatal("owned recovery withdrawal cleanup", err)
	}
}

func proveOTPRemovalState(t *testing.T, ctx context.Context, f liveStores, factor mfa.FactorID, user identity.UserID, command identity.CommandID) {
	t.Helper()
	commandBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(command))
	if err != nil {
		t.Fatal("original removal command malformed", err)
	}
	var erased, retired, effects, active int
	err = f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=3 AND identifier_id IS NULL AND identifier_version IS NULL AND verification_version IS NULL),
 (SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=3),
 (SELECT count(*) FROM identity_mfa.otp_factor_update_effects WHERE tenant_id=$1 AND user_id=$2 AND command_id=$4 AND action=2 AND octet_length(recovery_identity)=32),
 (SELECT active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2)`, otpTenant, string(user), string(factor), commandBytes).Scan(&erased, &retired, &effects, &active)
	if err != nil || erased != 1 || retired != 1 || effects != 1 || active != 0 {
		t.Fatal("OTP removal did not conserve erasure/recovery/authority/command effects", err)
	}
}
