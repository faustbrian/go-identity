package mfa

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

func TestTOTPProvisioningExactProfileAndEscapedLabel(t *testing.T) {
	secret, err := password.NewSecret([]byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	profile := TOTPProfile{Algorithm: "SHA256", Digits: 8, Period: 45 * time.Second, AllowedSkewSteps: 1, Issuer: "Example & Company"}
	id := EnrollmentID("AAAAAAAAAAAAAAAAAAAAAQ")
	for _, account := range []string{"alice+test@example.com", "alice/name?next=#fragment", "δοκιμή@example.com"} {
		material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, account, id)
		if err != nil {
			t.Fatal("provisioning rejected valid profile")
		}
		uri, err := url.Parse(material.URI)
		if err != nil || uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Path != "/"+profile.Issuer+":"+account || uri.Fragment != "" || material.EnrollmentID != id {
			t.Fatal("label or enrollment binding changed")
		}
		query := uri.Query()
		if len(query) != 5 || query.Get("issuer") != profile.Issuer || query.Get("algorithm") != "SHA256" || query.Get("digits") != "8" || query.Get("period") != "45" || query.Get("secret") != base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890")) {
			t.Fatal("stored factor profile changed in provisioning")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(verb, material), query.Get("secret")) || strings.Contains(fmt.Sprintf(verb, material), account) {
				t.Fatal("diagnostic secret disclosure")
			}
		}
		if _, err := json.Marshal(material); !errors.Is(err, identity.ForbiddenError{}) {
			t.Fatal("implicit URI serialization accepted")
		}
		if _, err := material.MarshalText(); !errors.Is(err, identity.ForbiddenError{}) {
			t.Fatal("implicit URI text export accepted")
		}
		if strings.Contains(material.LogValue().String(), query.Get("secret")) {
			t.Fatal("structured log disclosed secret")
		}
	}
	if secret.Len() != 20 {
		t.Fatal("borrowed secret destroyed by provisioning")
	}
}

func TestTOTPProvisioningInvalidAndCancelledNeverReturnsMaterial(t *testing.T) {
	secret, _ := password.NewSecret([]byte("12345678901234567890"))
	defer secret.Destroy()
	profile := TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, Issuer: "Example"}
	id := EnrollmentID("AAAAAAAAAAAAAAAAAAAAAQ")
	for _, account := range []string{"", " edge", "edge ", "bad:label", "bad\x00label", "bad\nlabel", string([]byte{0xff}), strings.Repeat("a", 257)} {
		material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, account, id)
		if err == nil || material.URI != "" || material.EnrollmentID != "" {
			t.Fatal("invalid label disclosed material")
		}
	}
	for _, change := range []func(*TOTPProfile){func(p *TOTPProfile) { p.Algorithm = "MD5" }, func(p *TOTPProfile) { p.Digits = 5 }, func(p *TOTPProfile) { p.Period++ }, func(p *TOTPProfile) { p.Issuer = "bad:issuer" }, func(p *TOTPProfile) { p.AllowedSkewSteps = 3 }} {
		bad := profile
		change(&bad)
		material, err := NewTOTPProvisioningURI(context.Background(), secret, bad, "alice", id)
		if err == nil || material.URI != "" {
			t.Fatal("invalid profile disclosed material")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, candidate := range []context.Context{nil, ctx} {
		material, err := NewTOTPProvisioningURI(candidate, secret, profile, "alice", id)
		if err == nil || material.URI != "" {
			t.Fatal("invalid context disclosed material")
		}
		if candidate != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	}
	material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, "alice", EnrollmentID("invalid"))
	if err == nil || material.URI != "" {
		t.Fatal("invalid enrollment disclosed material")
	}
	secret.Destroy()
	material, err = NewTOTPProvisioningURI(context.Background(), secret, profile, "alice", id)
	if !errors.Is(err, identity.UnavailableError{}) || material.URI != "" {
		t.Fatal("destroyed secret accepted")
	}
}

func TestTOTPProvisioningKeyURIRejectsUnsupportedDigitCounts(t *testing.T) {
	secret, _ := password.NewSecret([]byte("12345678901234567890"))
	defer secret.Destroy()
	for _, digits := range []uint32{7, 9, 10} {
		profile := TOTPProfile{Algorithm: "SHA1", Digits: digits, Period: 30 * time.Second, Issuer: "Example"}
		material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, "alice", EnrollmentID("AAAAAAAAAAAAAAAAAAAAAQ"))
		if err == nil || material.URI != "" {
			t.Fatal("non-Key-URI digit profile advertised as portable provisioning")
		}
	}
}

func TestTOTPProvisioningSecretBoundsAndAllAlgorithms(t *testing.T) {
	for _, length := range []int{19, 20, 128, 129} {
		bytes := make([]byte, length)
		secret, err := password.NewSecret(bytes)
		clear(bytes)
		if err != nil {
			t.Fatal("fixture secret unavailable")
		}
		for _, algorithm := range []string{"SHA1", "SHA256", "SHA512"} {
			profile := TOTPProfile{Algorithm: algorithm, Digits: 8, Period: 120 * time.Second, Issuer: "Issuer"}
			material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, strings.Repeat("a", 256), EnrollmentID("AAAAAAAAAAAAAAAAAAAAAQ"))
			if length == 19 || length == 129 {
				if !errors.Is(err, identity.UnavailableError{}) || material.URI != "" {
					t.Fatal("out-of-bounds secret accepted")
				}
			} else {
				if err != nil {
					t.Fatal("bounded secret denied")
				}
				u, err := url.Parse(material.URI)
				if err != nil || u.Query().Get("algorithm") != algorithm || u.Query().Get("digits") != "8" || u.Query().Get("period") != "120" {
					t.Fatal("algorithm/profile changed")
				}
				decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
				if err != nil || len(decoded) != length {
					clear(decoded)
					t.Fatal("secret encoding changed")
				}
				clear(decoded)
			}
		}
		secret.Destroy()
	}
}

func FuzzTOTPProvisioningLabel(f *testing.F) {
	for _, account := range []string{"alice@example.com", "a/b?c=d#fragment", "δοκιμή@example.com", "bad:label", "bad\x00label", "", " edge"} {
		f.Add(account)
	}
	f.Fuzz(func(t *testing.T, account string) {
		// Bound test resources independently of whether production accepts input.
		if len(account) > 4096 {
			return
		}
		secret, err := password.NewSecret([]byte("12345678901234567890"))
		if err != nil {
			t.Fatal("fixture secret unavailable")
		}
		defer secret.Destroy()
		profile := TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, Issuer: "Example"}
		material, err := NewTOTPProvisioningURI(context.Background(), secret, profile, account, EnrollmentID("AAAAAAAAAAAAAAAAAAAAAQ"))
		if err != nil {
			if material.URI != "" || material.EnrollmentID != "" {
				t.Fatal("failed construction disclosed partial material")
			}
			return
		}
		u, err := url.Parse(material.URI)
		if err != nil || len(material.URI) > 4096 || u.Scheme != "otpauth" || u.Host != "totp" || u.User != nil || u.Fragment != "" || u.Path != "/Example:"+account || len(u.Query()) != 5 || u.Query().Get("issuer") != "Example" {
			t.Fatal("label altered provisioning scope")
		}
	})
}
