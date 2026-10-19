package passwordpostgres

import (
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-identity/username"
	primitive "github.com/faustbrian/go-password/v2"
	"testing"
)

func TestEmailRemovalRequiresNativeSigninAndResetOwners(t *testing.T) {
	for _, input := range []struct {
		primary *EmailPrimarySource
		signin  *SigninService
		reset   *ResetService
	}{
		{},
		{primary: &EmailPrimarySource{}},
		{primary: &EmailPrimarySource{}, signin: &SigninService{}, reset: &ResetService{}},
	} {
		service, err := NewEmailRemovalService(input.primary, input.signin, input.reset, EmailRemovalConfig{}, nil)
		if err == nil || service != nil {
			t.Fatal("incomplete native signin/recovery composition admitted")
		}
	}
}

func TestEmailRemovalRequiresCompatibleRemainingOwners(t *testing.T) {
	_, _, policy := storedFixture(t)
	crypto, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"compatible", "signin-phone", "signin-username", "signin-global", "reset-global", "signin-policy", "reset-policy", "password-bound", "hash-bound", "primitive-bound"} {
		t.Run(mode, func(t *testing.T) {
			profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users"}
			primary := &EmailPrimarySource{source: &ReauthenticationService{repository: &Repository{policy: policy}, c: ReauthenticationConfig{Profile: profile, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128}}}}
			signin := &SigninService{repository: &Repository{policy: policy}, c: SigninConfig{Profile: profile, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128}}}
			config := ResetConfig{GlobalAuthorityID: "deployment", AuthorizationNamespace: "users"}
			reset := &ResetService{repository: &Repository{policy: policy}, config: func() ResetConfig { return config }}
			switch mode {
			case "signin-phone":
				signin.c.Phone, err = phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
				if err != nil {
					t.Fatal(err)
				}
			case "signin-username":
				p, e := username.NewPolicy(username.ReferencePolicySpec())
				if e != nil {
					t.Fatal(e)
				}
				signin.c.Username = p
			case "signin-global":
				signin.c.Profile.GlobalAuthorityID = "other"
			case "reset-global":
				config.GlobalAuthorityID = "other"
			case "signin-policy":
				signin.c.Profile.PolicyNamespace = "other"
			case "reset-policy":
				config.AuthorizationNamespace = "other"
			case "password-bound":
				signin.c.Verifier.MaximumBytes = 64
			case "hash-bound", "primitive-bound":
				limits := policy.Limits()
				limits.MemoryKiB = 8
				stricter, e := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: policy.Algorithm(), Argon2id: policy.Argon2idParameters(), Limits: limits})
				if e != nil {
					t.Fatal(e)
				}
				if mode == "hash-bound" {
					signin.repository.policy = stricter
				} else {
					signin.c.Verifier.Primitive, e = primitive.New(stricter)
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if compatibleRemovalOwners(primary, signin, reset) != (mode == "compatible") {
				t.Fatal("remaining owner compatibility misclassified", mode)
			}
		})
	}
}
