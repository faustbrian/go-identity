package reference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestEmailLifetimeRejectionKeepsOperationResponse(t *testing.T) {
	for _, removal := range []bool{false, true} {
		path, field := "/v1/email/verification-send", "queued"
		operation := "identity.email.verification-send"
		if removal {
			path, field = "/v1/email/address-remove", "removed"
			operation = "identity.email.address-remove"
		}
		s := &Server{state: &storeState{closed: true}}
		called := false
		h := s.guardEmailRequestLifetime(operation, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://tenant.example"+path, nil))
		var out map[string]any
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != http.StatusServiceUnavailable || called || len(out) != 3 || out[field] != false || out["commitOutcome"] != "none" || out["error"] != "unavailable" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("lifetime rejection violated operation response shape", path)
		}
	}
}

func TestEmailSelectionAndGraphLifetime(t *testing.T) {
	if owner, err := composeEmail(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}, nil, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected email acquired dependencies", err)
	}
	for _, config := range []*EmailConfiguration{{}, {Verification: &EmailManagementConfiguration{}}, {Change: &EmailManagementConfiguration{}}, {Addresses: &EmailAddressConfiguration{}}, {Removal: &EmailRemovalConfiguration{}}, {OTPVerification: &EmailOTPVerificationConfiguration{}}, {OTPChangeInitialPrimary: true}} {
		c := StoreConfiguration{Email: config}
		if owner, err := composeEmail(c, ReferenceDependencies{}, risk.Evaluator{}, nil, nil, nil); err == nil || owner != nil {
			t.Fatal("selected email accepted absent native authority")
		}
		if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
			t.Fatal("selected email disappeared from an empty graph")
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second}}
	f := FeatureSet{state: s}
	if owner, err := f.EmailVerification(); err == nil || owner != nil {
		t.Fatal("unselected graph exported verification")
	}
	if owner, err := f.EmailChange(); err == nil || owner != nil {
		t.Fatal("unselected graph exported change")
	}
	if owner, err := f.EmailRemoval(); err == nil || owner != nil {
		t.Fatal("unselected graph exported removal")
	}
	if owner, err := f.EmailAddresses(); err == nil || owner != nil {
		t.Fatal("unselected graph exported address queries")
	}
	if owner, err := f.EmailOTPVerification(); err == nil || owner != nil {
		t.Fatal("unselected graph exported email OTP")
	}
	if owner, err := f.EmailVerificationRequests(); err == nil || owner != nil {
		t.Fatal("unselected graph exported portable verification")
	}
	if owner, err := f.EmailChangeRequests(); err == nil || owner != nil {
		t.Fatal("unselected graph exported portable change")
	}
	s.features.email = &emailState{verification: &passwordpg.EmailManagementService{}, change: &passwordpg.EmailManagementService{}, addresses: &email.AddressQueryService{}, verificationRequests: &passwordpg.EmailRequestWorkflow{}, changeRequests: &passwordpg.EmailRequestWorkflow{}, removal: &passwordpg.EmailRemovalService{}, otpVerification: &otppg.EmailVerificationService{}}
	emailOTP, err := f.EmailOTPVerification()
	if err != nil {
		t.Fatal(err)
	}
	removal, err := f.EmailRemoval()
	if err != nil {
		t.Fatal(err)
	}
	portableVerification, err := f.EmailVerificationRequests()
	if err != nil {
		t.Fatal(err)
	}
	portableChange, err := f.EmailChangeRequests()
	if err != nil {
		t.Fatal(err)
	}
	verification, err := f.EmailVerification()
	if err != nil {
		t.Fatal(err)
	}
	change, err := f.EmailChange()
	if err != nil {
		t.Fatal(err)
	}
	queries, err := f.EmailAddresses()
	if err != nil {
		t.Fatal(err)
	}
	deny := func() {
		t.Helper()
		if _, err := emailOTP.SendEmailVerification(t.Context(), otp.EmailVerificationSendRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("foreign/inactive graph issued email OTP")
		}
		if _, err := emailOTP.EmailVerify(t.Context(), otp.EmailVerifyRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("foreign/inactive graph verified email")
		}
		if _, err := emailOTP.RecoverEmailVerify(t.Context(), otp.EmailVerifyRecoveryRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("foreign/inactive graph disclosed email OTP recovery")
		}
		if _, err := removal.AddressRemove(t.Context(), email.AddressRemoveRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("foreign/inactive graph removed address")
		}
		if _, err := removal.AddressRemoveRecover(t.Context(), identity.RecoveryQuery{TenantID: "foreign"}, authorization.DecisionContext{}); err == nil {
			t.Fatal("foreign/inactive graph disclosed removal outcome")
		}
		if user, err := removal.AddressRemoveRateSource(t.Context(), email.AddressRemoveRequest{TenantID: "foreign"}); err == nil || user != "" {
			t.Fatal("foreign/inactive graph disclosed removal rate scope")
		}
		if _, err := portableVerification.VerificationSend(t.Context(), email.VerificationSendRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("portable request escaped graph/tenant lifetime")
		}
		if user, destination, err := portableVerification.VerificationSendRateSource(t.Context(), email.VerificationSendRequest{TenantID: "foreign"}); err == nil || user != "" || destination != "" {
			t.Fatal("portable source escaped graph/tenant lifetime")
		}
		if _, err := portableChange.ChangeRequest(t.Context(), email.ChangeRequestRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("portable change escaped graph/tenant lifetime")
		}
		if user, destination, err := portableChange.ChangeRequestRateSource(t.Context(), email.ChangeRequestRequest{TenantID: "foreign"}); err == nil || user != "" || destination != "" {
			t.Fatal("portable change source escaped graph/tenant lifetime")
		}
		r := passwordpg.EmailManagementRequest{Primary: passwordpg.EmailPrimaryRequest{TenantID: "foreign"}}
		for _, owner := range []*ManagedEmailService{verification, change} {
			if _, err := owner.VerificationSendKeyed(t.Context(), r, identity.IdempotencyKey{}); err == nil {
				t.Fatal("inactive/foreign graph admitted keyed verification")
			}
			if _, err := owner.ChangeRequestKeyed(t.Context(), r, identity.IdempotencyKey{}); err == nil {
				t.Fatal("inactive/foreign graph admitted keyed change")
			}
			if user, address, err := owner.RequestRateSourceKeyed(t.Context(), r, identity.IdempotencyKey{}, false); err == nil || user != "" || address != "" {
				t.Fatal("inactive/foreign graph disclosed keyed rate metadata")
			}
			if _, err := owner.VerificationSend(t.Context(), r); err == nil {
				t.Fatal("inactive/foreign graph admitted verification")
			}
			if _, err := owner.ChangeRequest(t.Context(), r); err == nil {
				t.Fatal("inactive/foreign graph admitted change")
			}
			if _, err := owner.VerificationSendRecover(t.Context(), identity.RecoveryQuery{TenantID: "foreign"}, authorization.DecisionContext{}); err == nil {
				t.Fatal("inactive/foreign graph disclosed original receipt")
			}
		}
		if _, err := queries.AddressGet(t.Context(), email.AddressGetRequest{TenantID: "foreign"}); err == nil {
			t.Fatal("inactive/foreign graph disclosed address")
		}
		if s.active != 0 {
			t.Fatal("email calls leaked graph lifetime admission")
		}
	}
	deny()
	s.features.ready = true
	deny()
	s.closed = true
	deny()
	if owner, err := f.EmailChange(); err == nil || owner != nil {
		t.Fatal("closed graph exported new email handle")
	}
	if owner, err := f.EmailOTPVerification(); err == nil || owner != nil {
		t.Fatal("closed graph exported email OTP handle")
	}
}

func TestEmailOTPHTTPSelectionRequiresNativeOwners(t *testing.T) {
	if owner, err := composeEmailOTPVerificationHTTP(StoreConfiguration{}, nil, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected email OTP HTTP acquired resources", err)
	}
	c := StoreConfiguration{HTTPEmailOTPVerification: &HTTPEmailOTPVerificationConfiguration{}}
	if owner, err := composeEmailOTPVerificationHTTP(c, nil, nil, nil); err == nil || owner != nil {
		t.Fatal("email OTP HTTP accepted absent native owners")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("email OTP HTTP silently disappeared from empty graph")
	}
}

func TestEmailRequestSelectionRequiresNativeOwners(t *testing.T) {
	if owner, err := composeEmailRequestsHTTP(StoreConfiguration{}, nil, nil, nil, nil, nil); err != nil || owner != nil {
		t.Fatal("unselected request acquired resources", err)
	}
	for _, selected := range []HTTPEmailRequestsConfiguration{{}, {VerificationSend: true}, {ChangeRequest: true}, {ChangeConfirm: true}, {AddressRemove: true}} {
		c := StoreConfiguration{HTTPEmailRequests: &selected}
		if owner, err := composeEmailRequestsHTTP(c, nil, nil, nil, nil, nil); err == nil || owner != nil {
			t.Fatal("request accepted absent native owners")
		}
		if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
			t.Fatal("request selection disappeared from empty graph")
		}
	}
	for _, change := range []bool{false, true} {
		h := composedEmailRequests{change: change}
		if change {
			if _, err := h.VerificationSend(t.Context(), email.VerificationSendRequest{}); err == nil {
				t.Fatal("change handle used verification")
			}
		} else if _, err := h.ChangeRequest(t.Context(), email.ChangeRequestRequest{}); err == nil {
			t.Fatal("verification handle used change")
		}
	}
}

func TestKeyedEmailHandleDoesNotSelectAnotherProfile(t *testing.T) {
	// Profile selection is local and must reject before graph/lifetime work.
	// Nil state distinguishes the wrong-profile guard from native execution.
	change := &ManagedEmailService{change: true}
	_, err := change.VerificationSendKeyed(t.Context(), passwordpg.EmailManagementRequest{}, identity.IdempotencyKey{})
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field != "reference_email_keyed" {
		t.Fatal("change handle selected verification", err)
	}
	_, err = change.VerificationResendKeyed(t.Context(), passwordpg.EmailManagementRequest{}, identity.IdempotencyKey{})
	if !errors.As(err, &invalid) || invalid.Field != "reference_email_keyed" {
		t.Fatal("change handle selected resend", err)
	}
}
