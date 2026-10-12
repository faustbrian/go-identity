package reference

import (
	"testing"
	"time"

	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Pure server construction intentionally uses zero native services. Actual
// durable serving must be proven separately; no constructor may call them.
func TestReferenceMagicLinkSelectedServerRoutes(t *testing.T) {
	c, d, f := serverFixture(t)
	selection := serverOTPSelection(t, c)
	selection.HTTPEmailSignin = nil
	base, err := composePreAuthHTTP(selection)
	if err != nil {
		t.Fatal(err)
	}
	rate, err := composeHTTPRate(selection.HTTPRate, d.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.limiter.Close() })
	query := kernel.CommandQueryPolicy{Authorization: c.Policies.Authorize, PolicyVersion: 9}
	selection.MagicLink = &MagicLinkConfiguration{Request: magicpg.RequestConfig{MaximumDuration: time.Second, PolicyID: "magic-login", Coordinator: kernel.CoordinatorConfig{QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: kernel.RequestKeyConfig{Policy: query}}, Consume: &magicpg.ConsumeConfig{Issuer: session.IssuerConfig{Cookie: selection.OTP.Signin.Issuer.Cookie}}, PreAuth: &MagicLinkPreAuthConfiguration{ActorID: "operator", Origin: "https://login.example", CallbackURL: "https://login.example/login", FlowTTL: 5 * time.Minute, Cookie: base.deployment.Cookie}}
	selection.MagicLink.Request.Issuer.Audience = "service-a"
	selection.HTTPMagicLink = &HTTPMagicLinkConfiguration{Request: true, Consume: true, ActorID: "operator", PolicyRevision: 9, VerificationNamespace: "magic-test", VerificationKey: [32]byte{11}}
	h, err := composeMagicLinkHTTP(selection, base, rate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.rate.Close() })
	f.state.httpRate = rate
	f.state.features.httpPreAuth = base
	f.state.features.preauth = &session.PreAuthIssuer{}
	f.state.features.magicPreauth = &session.PreAuthIssuer{}
	f.state.features.magicRequest = &magicpg.RequestService{}
	f.state.features.magicConsume = &magicpg.ConsumeService{}
	f.state.features.httpMagicLink = h
	f.state.features.timeout = time.Second
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal("selected construction", err)
	}
	seen := map[string]bool{}
	for _, op := range s.OpenAPI().Operations() {
		seen[op.Record.OperationID] = true
	}
	if len(seen) != 5 || !seen["identity.magic-link.request"] || !seen["identity.magic-link.consume"] || !seen["identity.session.preauth-issue"] {
		t.Fatal("selected routes/metadata absent or unrelated feature exposed")
	}
	f.state.features.httpMagicLink = nil
	s, err = NewServer(c, d, f)
	if err != nil || len(s.OpenAPI().Operations()) != 3 {
		t.Fatal("disabled magic-link still exposed", err)
	}
	if absent, err := composeMagicLinkHTTP(StoreConfiguration{}, nil, nil); err != nil || absent != nil {
		t.Fatal("unselected HTTP acquired dependencies")
	}
	for _, mutate := range []func(*StoreConfiguration){
		func(c *StoreConfiguration) { c.MagicLink = nil },
		func(c *StoreConfiguration) { c.MagicLink.PreAuth = nil },
		func(c *StoreConfiguration) { c.MagicLink.Consume = nil },
		func(c *StoreConfiguration) { c.HTTPMagicLink.PolicyRevision = 8 },
		func(c *StoreConfiguration) { c.HTTPMagicLink.ActorID = "foreign" },
		func(c *StoreConfiguration) { c.HTTPMagicLink.Request = false; c.HTTPMagicLink.Consume = false },
		func(c *StoreConfiguration) { c.HTTPRate = nil },
	} {
		x := selection
		n := *selection.MagicLink
		h := *selection.HTTPMagicLink
		x.MagicLink = &n
		x.HTTPMagicLink = &h
		mutate(&x)
		if selected, err := composeMagicLinkHTTP(x, base, rate); err == nil || selected != nil {
			t.Fatal("invalid graph exposed HTTP")
		}
	}
}
