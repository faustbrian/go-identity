package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

func TestTOTPVerifierOwnedSecretAndOpaqueCode(t *testing.T) {
	verifier, err := NewTOTPVerifier([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("94287082")
	profile := TOTPProfile{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second, Issuer: "Example"}
	step, err := verifier.Verify(context.Background(), secret, code, profile, []byte("fixture/tenant/factor/challenge/key-version-1"), time.Unix(59, 0), TOTPReplayState{})
	if err != nil || step != 1 {
		t.Fatal("real opaque factor verification failed")
	}
	_, err = verifier.Verify(context.Background(), secret, code, profile, []byte("fixture/tenant/factor/challenge/key-version-1"), time.Unix(59, 0), TOTPReplayState{Used: true, LastStep: 1})
	if !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("replay not denied")
	}
	secret.Destroy()
	_, err = verifier.Verify(context.Background(), secret, code, profile, []byte("fixture/tenant/factor/challenge/key-version-1"), time.Unix(59, 0), TOTPReplayState{})
	if !errors.Is(err, identity.UnavailableError{}) {
		t.Fatal("destroyed secret treated as valid or wrong code")
	}
}

func TestTOTPVerifierInvalidProfileAndCancellation(t *testing.T) {
	verifier, _ := NewTOTPVerifier([32]byte{1})
	secret, _ := password.NewSecret([]byte("12345678901234567890"))
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("94287082")
	good := TOTPProfile{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second, Issuer: "Example"}
	for _, change := range []func(*TOTPProfile){func(p *TOTPProfile) { p.Algorithm = "MD5" }, func(p *TOTPProfile) { p.Digits = 0 }, func(p *TOTPProfile) { p.Period++ }, func(p *TOTPProfile) { p.AllowedSkewSteps = 3 }, func(p *TOTPProfile) { p.Issuer = "bad:issuer" }, func(p *TOTPProfile) { p.Issuer = "bad\nissuer" }, func(p *TOTPProfile) { p.Issuer = strings.Repeat("x", 129) }} {
		p := good
		change(&p)
		if _, err := verifier.Verify(context.Background(), secret, code, p, []byte("scope/key-version-1"), time.Unix(59, 0), TOTPReplayState{}); !errors.Is(err, identity.InvalidInputError{Field: "totp"}) {
			t.Fatal("invalid profile not rejected")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.Verify(ctx, secret, code, good, []byte("scope/key-version-1"), time.Unix(59, 0), TOTPReplayState{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if _, err := (TOTPVerifier{}).Verify(context.Background(), secret, code, good, []byte("scope/key-version-1"), time.Unix(59, 0), TOTPReplayState{}); !errors.Is(err, identity.InvalidInputError{Field: "totp"}) {
		t.Fatal("zero verifier accepted")
	}
	if _, err := NewTOTPVerifier([32]byte{}); !errors.Is(err, identity.InvalidInputError{Field: "totp"}) {
		t.Fatal("zero comparison key accepted")
	}
	if strings.Contains(fmt.Sprintf("%#v", verifier), "[1 0") {
		t.Fatal("comparison key traversable in diagnostics")
	}
}
