package reference

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneOTPSigninSelectionAndLifetime(t *testing.T) {
	if selected, err := composePhoneOTPSignin(StoreConfiguration{}, ReferenceDependencies{}, otppg.SendConfig{}, nil); err != nil || selected != nil {
		t.Fatal("unselected phone OTP acquired an owner", err)
	}
	if selected, err := composePhoneOTPSignin(StoreConfiguration{PhoneOTPSignin: &PhoneOTPSigninConfiguration{}}, ReferenceDependencies{}, otppg.SendConfig{}, nil); err == nil || selected != nil {
		t.Fatal("phone OTP accepted missing real dependencies")
	}
	if selected, err := composePhoneOTPSigninHTTP(StoreConfiguration{}, nil, nil); err != nil || selected != nil {
		t.Fatal("unselected phone OTP acquired HTTP", err)
	}
	if selected, err := composePhoneOTPSigninHTTP(StoreConfiguration{HTTPPhoneOTPSignin: &HTTPPhoneOTPSigninConfiguration{}}, nil, nil); err == nil || selected != nil {
		t.Fatal("phone OTP HTTP accepted missing real dependencies")
	}
	for _, features := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if owner, err := features.PhoneOTPSignin(); err == nil || owner != nil {
			t.Fatal("unselected graph exposed phone OTP")
		}
		if owner, err := features.PhoneOTPSigninPreAuth(); err == nil || owner != nil {
			t.Fatal("unselected graph exposed phone OTP initiation")
		}
	}
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	s := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second, phoneOTPSignin: &phoneOTPSigninState{owner: &otppg.PhoneSigninService{}, preauth: &session.PreAuthIssuer{}, bind: func(context.Context, identity.TenantID, string) ([32]byte, error) {
		t.Fatal("inactive or foreign binder invoked")
		return [32]byte{}, nil
	}}}}
	s.tenants = map[string]*tenantRecovery{"selected": {}}
	f := FeatureSet{state: s}
	owner, err := f.PhoneOTPSignin()
	if err != nil {
		t.Fatal(err)
	}
	preauth, err := f.PhoneOTPSigninPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(t.Context(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewPreAuthSendFlow("AAAAAAAAAAAAAAAAAAAAAQ", auth.NewBearerCredential("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("phone-otp-guard-test"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := phone.NewSigninSendRequest(phone.SigninSendRequestSpec{TenantID: "foreign", Number: number, Flow: flow, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "foreign", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "service"}, Action: "identity.phone.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.phone.signin"}}}, Network: "127.0.0.1", Device: "test-device", IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	deny := func(tenant identity.TenantID) {
		t.Helper()
		var unavailable identity.UnavailableError
		spec, err := request.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		spec.TenantID, spec.Caller.Request.Tenant = tenant, authorization.TenantID(tenant)
		selected, err := phone.NewSigninSendRequest(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.SendSignin(t.Context(), selected); !errors.As(err, &unavailable) {
			t.Fatal("inactive or foreign send crossed graph admission", err)
		}
		if _, err := owner.Signin(t.Context(), otp.SigninRequest{TenantID: tenant}); !errors.As(err, &unavailable) {
			t.Fatal("inactive or foreign graph issued a session")
		}
		if _, err := owner.ResolveSigninSource(t.Context(), otp.SigninSourceRequest{TenantID: tenant}); !errors.As(err, &unavailable) {
			t.Fatal("inactive or foreign graph discovered a destination")
		}
		if _, err := owner.RecoverSignin(t.Context(), otp.SigninRecoveryRequest{TenantID: tenant}); !errors.As(err, &unavailable) {
			t.Fatal("inactive or foreign graph exposed outcome history")
		}
		if binding, err := preauth.BindPreAuthIdentifier(t.Context(), tenant, "+12025550123"); !errors.As(err, &unavailable) || binding != ([32]byte{}) {
			t.Fatal("inactive or foreign graph bound a target")
		}
		if _, err := preauth.Prepare(t.Context(), session.PreAuthPrepareInput{TenantID: tenant, IdentifierBinding: [32]byte{1}}); !errors.As(err, &unavailable) {
			t.Fatal("inactive or foreign graph prepared an original flow")
		}
		if s.active != 0 {
			t.Fatal("phone OTP leaked graph admission")
		}
	}
	deny("foreign")
	deny("selected")
	s.features.ready = true
	deny("foreign")
	s.closed = true
	cancel()
	deny("foreign")
	deny("selected")
}
