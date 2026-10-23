//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresOTPFactorInventoryNative(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPEnrollmentOnly: true, mfaOTPListing: true}, true)
}

func TestReferencePostgresOTPFactorInventoryHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaOTPEnrollment: true, mfaOTPListing: true, mfaOTPListingHTTP: true}, true)
}

func TestReferencePostgresTOTPInventoryCompatibility(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, mfaEnrollment: true, mfaListing: true, mfaListHTTP: true}, true)
}

func otpInventoryRequest(t *testing.T, cookies []*http.Cookie) mfa.ListRequest {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("original inventory cookie unavailable")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "otp-factor-inventory"}
}

func proveOTPFactorInventory(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, factor string, state mfa.FactorState, remaining uint32) {
	t.Helper()
	owner, err := features.MFAListing()
	if err != nil {
		t.Fatal("selected OTP inventory unavailable", err)
	}
	request := otpInventoryRequest(t, cookies)
	check := func(out mfa.ListResult, err error) {
		t.Helper()
		want := 1
		if f.pendingDisableFactor != "" {
			want = 2
		}
		if err != nil || out.Outcome != 0 || len(out.Factors) != want || out.RecoveryCodeCount != remaining || len(out.TrustedDevices) != 0 {
			t.Fatal("OTP inventory lost native state or recovery count", err)
		}
		found, pending := false, f.pendingDisableFactor == ""
		for _, item := range out.Factors {
			if string(item.ID) == factor {
				found = item.Method == "otp" && item.State == state && item.Version > 0
			}
			if string(item.ID) == f.pendingDisableFactor {
				pending = item.Method == "otp" && item.State == mfa.FactorPending && item.Version == 1
			}
		}
		if !found || !pending {
			t.Fatal("OTP inventory lost target or genuine pending sibling")
		}
	}
	check(owner.List(ctx, request))
	foreign := request
	foreign.TenantID = "foreign-tenant"
	if denied, err := owner.List(ctx, foreign); err == nil || len(denied.Factors) != 0 || denied.RecoveryCodeCount != 0 {
		t.Fatal("foreign inventory disclosed original state")
	}
	if f.config.HTTPMFAList == nil {
		return
	}
	for _, mode := range []string{"anonymous", "target-override", "authorized"} {
		path := base + "/v1/mfa/list"
		if mode == "target-override" {
			path += "?userID=other"
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mode != "anonymous" {
			r.AddCookie(cookies[0])
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := io.ReadAll(io.LimitReader(response.Body, 262145))
		closed := response.Body.Close()
		var out mfa.ListResult
		decode := json.Unmarshal(wire, &out)
		clear(wire)
		if err != nil || closed != nil || decode != nil || len(wire) > 262144 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("OTP inventory transport lost bounded secret-free response")
		}
		if mode == "authorized" {
			if response.StatusCode != http.StatusOK {
				t.Fatal("authorized OTP inventory unavailable", response.StatusCode)
			}
			check(out, nil)
		} else {
			want := http.StatusForbidden
			if mode == "target-override" {
				want = http.StatusBadRequest
			}
			if response.StatusCode != want || len(out.Factors) != 0 || out.RecoveryCodeCount != 0 {
				t.Fatal("denied OTP inventory disclosed metadata", response.StatusCode)
			}
		}
	}
}

func proveOTPInventoryCorruption(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, cookies []*http.Cookie, user identity.UserID) {
	t.Helper()
	owner, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct{ change, restore string }{
		{`UPDATE identity_mfa.recovery_sets SET code_count=code_count+1 WHERE tenant_id=$1 AND user_id=$2 AND state=2`, `UPDATE identity_mfa.recovery_sets SET code_count=code_count-1 WHERE tenant_id=$1 AND user_id=$2 AND state=2`},
		{`UPDATE identity_mfa.factor_authorities SET active_factors=active_factors+1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity_mfa.factor_authorities SET active_factors=active_factors-1 WHERE tenant_id=$1 AND user_id=$2`},
	} {
		func() {
			changed, err := f.pool.Raw().Exec(ctx, table.change, otpTenant, string(user))
			if err != nil || changed.RowsAffected() != 1 {
				t.Fatal("inventory corruption fixture", err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(ctx, table.restore, otpTenant, string(user)); err != nil {
					t.Error("inventory fixture restoration", err)
				}
			}()
			if out, err := owner.List(ctx, otpInventoryRequest(t, cookies)); err == nil || len(out.Factors) != 0 || out.RecoveryCodeCount != 0 {
				t.Fatal("corrupt/unsupported inventory disclosed a partial result")
			}
		}()
	}
}

// This is a metadata-reader storage fixture after genuine OTP authentication,
// not a fabricated usable credential or proof of TOTP enrollment/signin. The
// revoked TOTP row contains no secret and borrows an actual creation command.
func proveOTPMixedFactorInventory(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, cookies []*http.Cookie, user identity.UserID, otpFactor string) {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors
 (tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,
 created_command_id,created_purpose,created_at,enrollment_expires_at)
 SELECT tenant_id,user_id,$3,3,1,1,'SHA256',6,30,0,'inventory-fixture',
 created_command_id,created_purpose,created_at,enrollment_expires_at
 FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$4`, otpTenant, string(user), string(id), otpFactor)
	if err != nil || inserted.RowsAffected() != 1 {
		t.Fatal("mixed revoked metadata fixture", err)
	}
	defer func() {
		for _, table := range []string{"totp_factors", "factor_references"} {
			if _, err := f.pool.Raw().Exec(ctx, "DELETE FROM identity_mfa."+table+" WHERE tenant_id=$1 AND factor_id=$2", otpTenant, string(id)); err != nil {
				t.Error("mixed metadata cleanup", err)
			}
		}
	}()
	owner, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	out, err := owner.List(ctx, otpInventoryRequest(t, cookies))
	if err != nil || len(out.Factors) != 2 || out.RecoveryCodeCount != 10 {
		t.Fatal("mixed native inventory omitted a method or changed recovery count", err)
	}
	seen := map[string]bool{}
	for _, factor := range out.Factors {
		switch string(factor.ID) {
		case string(id):
			if factor.Method != "totp" || factor.State != mfa.FactorRevoked {
				t.Fatal("revoked native TOTP metadata was reinterpreted")
			}
		case otpFactor:
			if factor.Method != "otp" || factor.State != mfa.FactorActive {
				t.Fatal("active native OTP metadata was reinterpreted")
			}
		default:
			t.Fatal("mixed inventory invented a factor")
		}
		if seen[string(factor.ID)] {
			t.Fatal("mixed inventory duplicated a factor")
		}
		seen[string(factor.ID)] = true
	}
}

func proveOTPInventoryLoggedOut(t *testing.T, ctx context.Context, features reference.FeatureSet, cookies []*http.Cookie) {
	t.Helper()
	owner, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := owner.List(ctx, otpInventoryRequest(t, cookies)); err == nil || len(out.Factors) != 0 || out.RecoveryCodeCount != 0 {
		t.Fatal("revoked session retained inventory access")
	}
}
