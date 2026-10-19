package reference

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func TestPhoneSigninSelectionRequiresRealLiveOwners(t *testing.T) {
	if selected, err := composePhoneSignin(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}); err != nil || selected != nil {
		t.Fatal("unselected phone signin acquired authority", err)
	}
	p, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []*PhoneSigninConfiguration{{}, {Policy: p}} {
		if owner, err := composePhoneSignin(StoreConfiguration{PhoneSignin: selected}, ReferenceDependencies{}, risk.Evaluator{}); err == nil || owner != nil {
			t.Fatal("selected phone signin accepted missing real upstream owners")
		}
	}
	for _, f := range []FeatureSet{{}, {state: &storeState{features: &featureState{composed: true}}}} {
		if owner, err := f.PhoneSignin(); err == nil || owner != nil {
			t.Fatal("unselected graph exposed phone signin")
		}
		if owner, err := f.PhoneSigninPreAuth(); err == nil || owner != nil {
			t.Fatal("unselected graph exposed phone initiation")
		}
	}
}

func TestPhoneSigninHandlesRetainStartupTenantAndShutdownGuards(t *testing.T) {
	lifetime, cancel := context.WithCancel(t.Context())
	defer cancel()
	drained := make(chan struct{})
	close(drained)
	state := &storeState{lifetime: lifetime, cancel: cancel, drained: drained, features: &featureState{composed: true, timeout: time.Second, phoneSignin: &phoneSigninState{owner: &passwordpg.SigninService{}, preauth: &session.PreAuthIssuer{}, bind: func(context.Context, identity.TenantID, string) ([32]byte, error) {
		t.Fatal("inactive or foreign binder invoked")
		return [32]byte{}, nil
	}}}}
	f := FeatureSet{state: state}
	signin, err := f.PhoneSignin()
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := signin.(passwordhttp.SigninService)
	if !ok {
		t.Fatal("native phone owner does not expose its own rate custody")
	}
	preauth, err := f.PhoneSigninPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	deny := func() {
		t.Helper()
		if binding, err := preauth.BindPreAuthIdentifier(t.Context(), "foreign", "+12025550123"); err == nil || binding != ([32]byte{}) {
			t.Fatal("inactive or foreign graph bound a target")
		}
		if _, err := preauth.Prepare(t.Context(), session.PreAuthPrepareInput{TenantID: "foreign", IdentifierBinding: [32]byte{1}}); err == nil {
			t.Fatal("inactive or foreign graph prepared a flow")
		}
		if _, err := preauth.Issue(t.Context(), session.PreparedPreAuthIssuance{}); err == nil {
			t.Fatal("inactive or foreign graph issued a flow")
		}
		if _, err := preauth.Recover(t.Context(), session.PreAuthIssueCommand{}); err == nil {
			t.Fatal("inactive or foreign graph exposed history")
		}
		if value, err := owner.SigninRateSource(t.Context(), password.SigninRequest{}); err == nil || value != "" {
			t.Fatal("inactive or foreign graph exposed rate input")
		}
		if _, err := owner.Signin(t.Context(), password.SigninRequest{}); err == nil {
			t.Fatal("inactive or foreign graph signed in")
		}
		if _, err := owner.RecoverSignin(t.Context(), password.SigninRecoveryRequest{}); err == nil {
			t.Fatal("inactive or foreign graph recovered signin")
		}
		if state.active != 0 {
			t.Fatal("phone graph leaked lifetime admission")
		}
	}
	deny()
	state.features.ready = true
	deny()
	state.closed = true
	cancel()
	deny()
}
