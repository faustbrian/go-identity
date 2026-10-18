package password_test

import (
	"strings"
	"testing"

	password "github.com/faustbrian/go-identity/password"
)

func TestUsernameSignupInputRetainsItsOriginalOperation(t *testing.T) {
	r := signupInput(t)
	r.Username = "Straße"
	r.Caller.Request.Action = "identity.username.signup"
	r.Caller.Request.Resource.ID = "identity.username.signup"
	if err := r.Validate(); err != nil {
		t.Fatal("bounded username signup input denied", err)
	}
	if r.Username != "Straße" || r.Email != " generic-owned-address " {
		t.Fatal("input normalized raw identifiers")
	}
	for _, name := range []string{"", "\xff", strings.Repeat("x", 129)} {
		bad := r
		bad.Username = name
		if bad.Validate() == nil {
			t.Fatal("missing or unbounded username accepted")
		}
	}
	r.Caller.Request.Action = "identity.password.signup"
	if r.Validate() == nil {
		t.Fatal("username input silently relabeled as legacy signup")
	}
}

func TestUsernameRecoveryRetainsOriginalSignupAndSigninOperations(t *testing.T) {
	r := signupInput(t)
	q, flow, _ := signupRecovery(t).Bindings()
	q.OperationID = "identity.username.signup"
	recovery, err := password.NewSignupRecovery(q, flow)
	if err != nil {
		t.Fatal("username signup recovery denied", err)
	}
	r.Caller.Request.Action = "identity.username.signup"
	r.Caller.Request.Resource.ID = "identity.username.signup"
	request := password.SignupRecoveryRequest{Recovery: recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	if request.Validate() != nil {
		t.Fatal("original username signup recovery provenance denied")
	}
	request.Caller.Request.Action = "identity.password.signup"
	if request.Validate() == nil {
		t.Fatal("username recovery relabeled as password signup")
	}
	q, flow, _ = signinRecovery(t, true).Bindings()
	q.OperationID = "identity.username.signin"
	signin, err := password.NewSigninRecovery(q, flow)
	if err != nil {
		t.Fatal("username signin recovery denied", err)
	}
	input := signinInput(t)
	input.Caller.Request.Action = "identity.username.signin"
	input.Caller.Request.Resource.ID = "identity.username.signin"
	signinRequest := password.SigninRecoveryRequest{Recovery: signin, Cookie: input.Cookie, Caller: input.Caller, Origin: input.Origin, Network: input.Network, Device: input.Device}
	if signinRequest.Validate() != nil {
		t.Fatal("original username signin recovery provenance denied")
	}
	signinRequest.Caller.Request.Action = "identity.password.signin"
	if signinRequest.Validate() == nil {
		t.Fatal("username recovery relabeled as password signin")
	}
}
