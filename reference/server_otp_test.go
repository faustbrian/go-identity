package reference

import (
	"net/http"
	"testing"
	"time"

	identifier "github.com/faustbrian/go-identifier"
	email "github.com/faustbrian/go-identity/email"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func serverOTPSelection(t *testing.T, c ReferenceConfig) StoreConfiguration {
	t.Helper()
	profile, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "reference-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewBrowserDeviceKey(1, []byte("reference-device-unit-fixture-key"))
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	sessionCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	return StoreConfiguration{HTTPRate: &HTTPRateConfiguration{Namespace: "server-otp-unit", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: time.Second, LockTimeout: time.Second, RollbackTimeout: time.Second},
		HTTPPreAuth:     &HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "server-otp-unit", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: deviceCookie}},
		HTTPEmailSignin: &HTTPEmailSigninConfiguration{ActorID: "operator", PolicyRevision: 9, TargetID: "login", Address: email.AddressPolicy{MaximumBytes: 4096, Canonicalization: profile}},
		OTP:             &OTPSendConfiguration{PreAuth: &OTPPreAuthConfiguration{FlowTTL: 5 * time.Minute, Cookie: flowCookie, Origin: "https://login.example"}, PreAuthAction: "identity.otp.signin", PolicyID: "otp-policy", PolicyVersion: 7, RequestKeys: kernel.RequestKeyConfig{Policy: kernel.CommandQueryPolicy{Authorization: c.Policies.Authorize, PolicyVersion: 9}}, Signin: &otppg.SigninConfig{Coordinator: kernel.CoordinatorConfig{QueryPolicy: &kernel.CommandQueryPolicy{Authorization: c.Policies.Authorize, PolicyVersion: 9}}, Profile: sessionpg.OTPAdmissionConfig{Audience: "service-a"}, Issuer: session.IssuerConfig{Cookie: sessionCookie}}}}
}

// Pure native-owner selection is distinct from service-backed journey proof.
func TestReferenceServerOTPSelectedNativeContributions(t *testing.T) {
	c, d, f := serverFixture(t)
	c.HTTP.Network.Limits.MaximumFields = 64
	selection := serverOTPSelection(t, c)
	h, err := composePreAuthHTTP(selection)
	if err != nil {
		t.Fatal(err)
	}
	o, err := composeEmailSigninHTTP(selection, h)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := composeHTTPRate(selection.HTTPRate, d.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rate.limiter.Close(); err != nil {
			t.Error(err)
		}
	})
	f.state.httpRate = rate
	f.state.features.httpPreAuth, f.state.features.httpEmailSignin = h, o
	f.state.features.otp, f.state.features.signin, f.state.features.preauth = &otppg.SendService{}, &otppg.SigninService{}, &session.PreAuthIssuer{}
	f.state.features.timeout = time.Second
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal("selected pure constructor", err)
	}
	operations := s.OpenAPI().Operations()
	if len(operations) != 6 {
		t.Fatal("selected native contributions", len(operations))
	}
	seen := map[string]bool{}
	for _, op := range operations {
		seen[op.Record.OperationID] = true
	}
	for _, id := range []string{"identity.otp.send", "identity.otp.signin", "identity.otp.signin.recover", "identity.session.preauth-issue"} {
		if !seen[id] {
			t.Fatal("missing selected operation", id)
		}
	}
	if len(s.OpenAPI().JSON()) == 0 {
		t.Fatal("empty selected wire document")
	}
	c.HTTP.Network.Limits.MaximumFields = 43
	if server, err := NewServer(c, d, f); err == nil || server != nil {
		t.Fatal("impossible native recovery envelope admitted")
	}
	c.HTTP.Network.Limits.MaximumFields = 44
	for _, depth := range []uint32{1, 2} {
		c.HTTP.Network.Limits.MaximumDepth = depth
		if server, err := NewServer(c, d, f); err == nil || server != nil {
			t.Fatal("impossible native recovery depth admitted", depth)
		}
	}
	c.HTTP.Network.Limits.MaximumDepth = 3
	if server, err := NewServer(c, d, f); err != nil || server == nil {
		t.Fatal("minimum native recovery limits rejected", err)
	}
}

func TestReferenceServerOTPSelectionRequiresNativeGraph(t *testing.T) {
	c, _, _ := serverFixture(t)
	for _, change := range []func(*StoreConfiguration){
		func(c *StoreConfiguration) { c.OTP = nil },
		func(c *StoreConfiguration) { c.OTP.Signin = nil },
		func(c *StoreConfiguration) { c.HTTPPreAuth = nil },
		func(c *StoreConfiguration) { c.HTTPPreAuth.Device = nil },
		func(c *StoreConfiguration) { c.HTTPRate = nil },
		func(c *StoreConfiguration) { c.HTTPEmailSignin.Address = email.AddressPolicy{} },
		func(c *StoreConfiguration) {
			c.OTP.Signin.Coordinator.QueryPolicy.Authorization = &serverNoCallPolicy{}
		},
		func(c *StoreConfiguration) { c.HTTPEmailSignin.PolicyRevision = 8 },
	} {
		selection := serverOTPSelection(t, c)
		change(&selection)
		h, err := composePreAuthHTTP(selection)
		if err != nil {
			continue
		}
		if o, err := composeEmailSigninHTTP(selection, h); err == nil || o != nil {
			t.Fatal("missing/foreign native graph accepted")
		}
	}
	selection := serverOTPSelection(t, c)
	selection.HTTPEmailSignin = nil
	if o, err := composeEmailSigninHTTP(selection, nil); err != nil || o != nil {
		t.Fatal("unselected OTP HTTP required dependencies", err)
	}
}
