package reference

import (
	"testing"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/username"
)

func TestUsernameCompositionIsExplicitAndRequiresRealOwners(t *testing.T) {
	if selected, err := composeUsername(StoreConfiguration{}, ReferenceDependencies{}, risk.Evaluator{}, nil); err != nil || selected != nil {
		t.Fatal("unselected username acquired owners", err)
	}
	p, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []*UsernameConfiguration{{}, {Policy: p}, {Policy: p, Signup: true}, {Policy: p, Signin: true}} {
		if state, err := composeUsername(StoreConfiguration{Username: selected}, ReferenceDependencies{}, risk.Evaluator{}, nil); err == nil || state != nil {
			t.Fatal("username selection accepted absent real upstream owner")
		}
	}
}

func TestUsernameHandlesDenyUnselectedGraph(t *testing.T) {
	f := FeatureSet{}
	if owner, err := f.UsernameSignup(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username signup")
	}
	if owner, err := f.UsernameRegistrationVerification(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username registration confirmation")
	}
	if owner, err := f.UsernameSignin(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username signin")
	}
	if owner, err := f.UsernameAvailability(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username availability")
	}
	if owner, err := f.UsernameRename(); err == nil || owner != nil {
		t.Fatal("empty graph exposed protected rename")
	}
	if owner, err := f.UsernameSignupPreAuth(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username signup initiation")
	}
	if owner, err := f.UsernameSigninPreAuth(); err == nil || owner != nil {
		t.Fatal("empty graph exposed username signin initiation")
	}
}

func TestUsernameHTTPSelectionRequiresActualNativeOwners(t *testing.T) {
	if state, err := composeUsernameHTTP(StoreConfiguration{}, nil, nil, nil, nil); err != nil || state != nil {
		t.Fatal("unselected username acquired HTTP state", err)
	}
	for _, selected := range []*HTTPUsernameConfiguration{{}, {Signup: true}, {Signin: true}, {Availability: true}, {Rename: &HTTPPasswordProtectionConfiguration{}}} {
		if state, err := composeUsernameHTTP(StoreConfiguration{HTTPUsername: selected}, nil, nil, nil, nil); err == nil || state != nil {
			t.Fatal("username HTTP selection accepted absent native owner")
		}
	}
}
