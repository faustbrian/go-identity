package reference

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestSessionSelectionRequiresNativeOwners(t *testing.T) {
	if owner, err := composeSession(StoreConfiguration{}, ReferenceDependencies{}, nil); err != nil || owner != nil {
		t.Fatal("unselected sessions acquired dependencies", err)
	}
	c := StoreConfiguration{Session: &SessionConfiguration{}}
	if owner, err := composeSession(c, ReferenceDependencies{}, nil); err == nil || owner != nil {
		t.Fatal("selected sessions accepted absent native authority")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected sessions silently disappeared without a graph")
	}
}

func TestSessionSelectionMatchesEverySelectedIssuer(t *testing.T) {
	configuration := func() StoreConfiguration {
		cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
		lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{1}, 32))
		otpLookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{2}, 32))
		magicLookup, _ := session.NewDigestKey(3, bytes.Repeat([]byte{3}, 32))
		csrf, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{4}, 32))
		otpCSRF, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{5}, 32))
		magicCSRF, _ := session.NewCSRFKey(3, bytes.Repeat([]byte{6}, 32))
		store := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
		profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: 1, CredentialOwner: "identity/password"}
		return StoreConfiguration{
			Session:        &SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: store, Profile: sessionpg.IssueAdmissionConfig(profile)}, Validation: session.ServiceConfig{LookupKeys: []session.DigestKey{lookup, otpLookup, magicLookup}}, Cookie: cookie}, CSRFKeys: []session.CSRFKey{csrf, otpCSRF, magicCSRF}},
			PasswordSignin: &PasswordSigninConfiguration{Native: passwordpg.SigninConfig{Session: store, Profile: profile, Issuance: session.IssuerConfig{LookupKey: lookup, Cookie: cookie}, CSRFKey: csrf}},
			OTP:            &OTPSendConfiguration{Signin: &otppg.SigninConfig{Session: store, Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}, Issuer: session.IssuerConfig{LookupKey: otpLookup, Cookie: cookie}, CSRFKey: otpCSRF}},
			MagicLink:      &MagicLinkConfiguration{Request: magicpg.RequestConfig{Session: store, GlobalAuthorityID: "deployment", Issuer: issuerpg.IssuerConfig{Audience: "service-a"}}, Consume: &magicpg.ConsumeConfig{PolicyNamespace: "users", Issuer: session.IssuerConfig{LookupKey: magicLookup, Cookie: cookie}, CSRF: magicCSRF}},
		}
	}
	c := configuration()
	selected, err := sessionAdmissionSelection(c)
	if err != nil || selected.Verified == nil || selected.OTP == nil || selected.MagicLink == nil {
		t.Fatal("selected issuers did not share primary read/logout admission", err)
	}
	for name, alter := range map[string]func(*StoreConfiguration){
		"OTP audience": func(c *StoreConfiguration) { c.OTP.Signin.Profile.Audience = "foreign" },
		"OTP store":    func(c *StoreConfiguration) { c.OTP.Signin.Session.Schema = "foreign" },
		"OTP lookup": func(c *StoreConfiguration) {
			c.OTP.Signin.Issuer.LookupKey, _ = session.NewDigestKey(2, bytes.Repeat([]byte{99}, 32))
		},
		"OTP CSRF": func(c *StoreConfiguration) {
			c.OTP.Signin.CSRFKey, _ = session.NewCSRFKey(2, bytes.Repeat([]byte{99}, 32))
		},
		"OTP cookie": func(c *StoreConfiguration) {
			c.OTP.Signin.Issuer.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-other", SameSite: http.SameSiteStrictMode})
		},
		"magic audience":   func(c *StoreConfiguration) { c.MagicLink.Request.Issuer.Audience = "foreign" },
		"magic deployment": func(c *StoreConfiguration) { c.MagicLink.Request.GlobalAuthorityID = "foreign" },
		"magic namespace":  func(c *StoreConfiguration) { c.MagicLink.Consume.PolicyNamespace = "foreign" },
		"magic store":      func(c *StoreConfiguration) { c.MagicLink.Request.Session.Schema = "foreign" },
		"magic lookup": func(c *StoreConfiguration) {
			c.MagicLink.Consume.Issuer.LookupKey, _ = session.NewDigestKey(3, bytes.Repeat([]byte{99}, 32))
		},
		"magic CSRF": func(c *StoreConfiguration) {
			c.MagicLink.Consume.CSRF, _ = session.NewCSRFKey(3, bytes.Repeat([]byte{99}, 32))
		},
		"magic cookie": func(c *StoreConfiguration) {
			c.MagicLink.Consume.Issuer.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-other", SameSite: http.SameSiteStrictMode})
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := configuration()
			alter(&c)
			if _, err := sessionAdmissionSelection(c); err == nil {
				t.Fatal("incompatible selected issuer admitted")
			}
		})
	}
	c.MagicLink.Consume = nil
	c.MagicLink.Request = magicpg.RequestConfig{}
	selected, err = sessionAdmissionSelection(c)
	if err != nil || selected.MagicLink != nil {
		t.Fatal("request-only selection acquired session authority", err)
	}
	c.OTP.Signin = nil
	selected, err = sessionAdmissionSelection(c)
	if err != nil || selected.Verified == nil || selected.OTP != nil {
		t.Fatal("password session selection implicitly required or admitted OTP signin", err)
	}
}

func TestSessionSelectionMatchesIssuedKeyMaterial(t *testing.T) {
	lookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{1}, 32))
	older, _ := session.NewDigestKey(1, bytes.Repeat([]byte{3}, 32))
	copyLookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{1}, 32))
	wrongLookup, _ := session.NewDigestKey(2, bytes.Repeat([]byte{4}, 32))
	csrf, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{2}, 32))
	copyCSRF, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{2}, 32))
	wrongCSRF, _ := session.NewCSRFKey(2, bytes.Repeat([]byte{5}, 32))
	p := passwordpg.SigninConfig{Issuance: session.IssuerConfig{LookupKey: lookup}, CSRFKey: csrf}
	n := SessionConfiguration{CSRFKeys: []session.CSRFKey{copyCSRF}}
	n.Native.Validation.LookupKeys = []session.DigestKey{older, copyLookup}
	if !sessionIssuerKeysMatch(n, p) {
		t.Fatal("independent immutable copies or rotation overlap rejected")
	}
	n.Native.Validation.LookupKeys[1] = wrongLookup
	if sessionIssuerKeysMatch(n, p) {
		t.Fatal("lookup version accepted different material")
	}
	n.Native.Validation.LookupKeys[1] = copyLookup
	n.CSRFKeys[0] = wrongCSRF
	if sessionIssuerKeysMatch(n, p) {
		t.Fatal("CSRF version accepted different material")
	}
	n.CSRFKeys = nil
	if !sessionIssuerKeysMatch(n, p) {
		t.Fatal("bearer-only composition required cookie keys")
	}
}
