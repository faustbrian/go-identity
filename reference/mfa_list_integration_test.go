//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceMFAListingFromRealEnrollment(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true}, true)
}

func TestReferenceMFAListingHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, mfaListHTTP: true, passwordRecovery: true}, true)
}

func TestReferenceMFAListingHTTPWithoutSessionRoutes(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, mfaListHTTP: true, mfaListStandalone: true}, true)
}

func proveReferenceMFAListingHTTP(t *testing.T, ctx context.Context, client *http.Client, base string, cookie *http.Cookie, factor string, remaining uint32) {
	t.Helper()
	for _, mode := range []string{"missing-cookie", "query", "fresh"} {
		path := base + "/v1/mfa/list"
		if mode == "query" {
			path += "?userID=other"
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mode != "missing-cookie" {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("public listing unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 262145))
		response.Body.Close()
		var out struct {
			Factors []struct {
				ID      string
				State   mfa.FactorState
				Version uint64
			}
			TrustedDevices    []json.RawMessage
			RecoveryCodeCount uint32
			Error             string
		}
		decodeErr := json.Unmarshal(data, &out)
		clear(data)
		if readErr != nil || decodeErr != nil || len(data) > 262144 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("public list lost bounded credential-free policy")
		}
		if mode != "fresh" {
			want := 403
			if mode == "query" {
				want = 400
			}
			if response.StatusCode != want || len(out.Factors) != 0 || out.RecoveryCodeCount != 0 {
				t.Fatal("denied HTTP list disclosed metadata", response.StatusCode)
			}
			continue
		}
		if response.StatusCode != 200 || out.RecoveryCodeCount != remaining || len(out.TrustedDevices) != 0 || out.Error != "" {
			t.Fatal("public list lost native unused count", response.StatusCode)
		}
		if factor == "" {
			if len(out.Factors) != 0 {
				t.Fatal("empty HTTP list invented factors")
			}
		} else if len(out.Factors) != 1 || out.Factors[0].ID != factor || out.Factors[0].State != mfa.FactorActive || out.Factors[0].Version == 0 {
			t.Fatal("public factor metadata differs from native owner")
		}
	}
}

func TestReferenceMFAListingDeniesCorruptAndBlockedState(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, mfaListDenials: true}, true)
}

func TestReferenceMFAListingTracksConsumedRecoveryCodes(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, passwordRecovery: true}, true)
}

func TestReferenceMFAListingRechecksAuthorityAfterMetadataRead(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, mfaListRecheck: true}, true)
}

// This test-only decorator obtains metadata through the actual selected public
// native owner. It does not fabricate rows or session-result custody. The owned
// fixture changes account authority only after that real read has completed.
type blockAfterNativeFactorRead struct {
	service mfa.FactorListingService
	request mfa.ListRequest
	fixture liveStores
}

func (r blockAfterNativeFactorRead) ReadFactors(ctx context.Context, q mfa.FactorListQuery) (mfa.FactorListSnapshot, error) {
	out, err := r.service.List(ctx, r.request)
	if err != nil {
		return mfa.FactorListSnapshot{}, err
	}
	var version uint64
	if err := r.fixture.pool.Raw().QueryRow(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, q.TenantID, q.UserID).Scan(&version); err != nil {
		return mfa.FactorListSnapshot{}, err
	}
	changed, err := r.fixture.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, q.TenantID, q.UserID)
	if err != nil || changed.RowsAffected() != 1 {
		return mfa.FactorListSnapshot{}, identity.UnavailableError{}
	}
	return mfa.FactorListSnapshot{TenantID: q.TenantID, UserID: q.UserID, AuthorityVersion: version, Factors: out.Factors, TrustedDevices: out.TrustedDevices, RecoveryCodeCount: out.RecoveryCodeCount}, nil
}

func proveReferenceMFAListRecheck(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer string) {
	t.Helper()
	native, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	request := mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "reference-list-recheck"}
	read := blockAfterNativeFactorRead{service: native, request: request, fixture: f}
	service, err := mfa.NewListService(sessions, read, mfa.ListConfig{Authorization: referenceRegistrationPolicy{}, Clock: clock.System{}, PolicyRevision: 9, MaximumDuration: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.List(ctx, request)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || len(out.Factors) != 0 || len(out.TrustedDevices) != 0 || out.RecoveryCodeCount != 0 {
		t.Fatal("post-read authority loss disclosed captured metadata", err)
	}
}

func proveReferenceMFAListing(t *testing.T, ctx context.Context, features reference.FeatureSet, bearer, factor string, remaining uint32) {
	t.Helper()
	service, err := features.MFAListing()
	if err != nil {
		t.Fatal("selected native factor listing unavailable", err)
	}
	token, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal("original listing session unavailable")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	request := mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "reference-factor-list"}
	listed, err := service.List(ctx, request)
	if err != nil || listed.Outcome != 0 || listed.RecoveryCodeCount != remaining || len(listed.TrustedDevices) != 0 {
		t.Fatal("safe native list lost known inventory or unused count", err)
	}
	if factor == "" {
		if len(listed.Factors) != 0 {
			t.Fatal("known-empty generation fabricated enrolled factors")
		}
	} else if len(listed.Factors) != 1 || string(listed.Factors[0].ID) != factor || listed.Factors[0].Method != "totp" || listed.Factors[0].State != mfa.FactorActive || listed.Factors[0].Version == 0 {
		t.Fatal("activated factor missing from native safe inventory")
	}
	request.TenantID = "AAAAAAAAAAAAAAAAAAAAAg"
	if foreign, err := service.List(ctx, request); err == nil || len(foreign.Factors) != 0 || foreign.RecoveryCodeCount != 0 {
		t.Fatal("foreign tenant disclosed original factor inventory")
	}
}

func proveReferenceMFAListDenials(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer string) {
	t.Helper()
	service, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	request := mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "reference-list-denials"}
	denies := func(name string, r mfa.ListRequest, unavailable bool) {
		t.Helper()
		out, err := service.List(ctx, r)
		var forbidden identity.ForbiddenError
		var failed identity.UnavailableError
		classified := errors.As(err, &forbidden)
		if unavailable {
			classified = errors.As(err, &failed)
		}
		if !classified || len(out.Factors) != 0 || len(out.TrustedDevices) != 0 || out.RecoveryCodeCount != 0 {
			t.Fatal(name, "disclosed partial inventory or lost denial", err)
		}
	}
	wrong := request
	zero, _ := session.ParseToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	wrong.Credential, _ = session.NewCredential(session.CredentialCookie, zero)
	denies("unknown-credential", wrong, false)
	// Deliberately remove one row in this disposable graph only. Native reading
	// must not turn an incomplete ten-code set into an apparently healthy count9.
	deleted, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.recovery_codes c USING identity_mfa.recovery_sets r WHERE c.tenant_id=r.tenant_id AND c.set_id=r.set_id AND r.tenant_id=$1 AND r.state=2 AND c.code_index=0`, otpTenant)
	if err != nil || deleted.RowsAffected() != 1 {
		t.Fatal("owned corrupt-set fixture unavailable")
	}
	denies("incomplete-set", request, true)
	// Suspend the genuine account and leave it suspended. Restoring fixture state
	// would resurrect authority and obscure the required current-state boundary.
	suspended, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND status='active'`, otpTenant)
	if err != nil || suspended.RowsAffected() != 1 {
		t.Fatal("owned blocked-account fixture unavailable")
	}
	denies("blocked-account", request, false)
	var used int
	if f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.recovery_codes WHERE consumed_at IS NOT NULL`).Scan(&used) != nil || used != 0 {
		t.Fatal("safe listing consumed recovery authority")
	}
}
