package postgres

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
)

func signinCallbackInputFixture(t *testing.T) (*signinStartPhase, signinStartOutput, oauth.SigninCallbackRequest, time.Time) {
	t.Helper()
	p := signinOutputFixture(t)
	_, _, key, now := signinBrowserFixture(t)
	p.input.Binding.PolicyID = "login"
	s := p.service
	s.config.PolicyID, s.config.Origin = "login", "https://app.example"
	s.config.FlowKeys = []session.DigestKey{key}
	s.config.Coordinator.AdmissionPolicy = &kernel.CommandQueryPolicy{PolicyVersion: 1}
	profile := s.profiles[p.input.Provider]
	profile.AuthorizationEndpoint, profile.TokenEndpoint = "https://issuer.example/authorize", "https://issuer.example/token"
	profile.ClientAuthentication, profile.Scopes, profile.Algorithms = oauth.PublicClient, []string{"openid"}, []string{"ES256"}
	profile.Timeout, profile.ClockSkew, profile.MaxResponseBytes, profile.MaxTokenBytes, profile.MaxCodeBytes = time.Second, time.Minute, 65536, 16384, 4096
	s.profiles[p.input.Provider] = profile
	wire, err := p.generateOutput(context.Background(), 1, risk.AuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"original-provider-code"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parsed.Destroy)
	return p, out, oauth.SigninCallbackRequest{Callback: parsed, TenantID: p.request.TenantID, FlowCookie: p.request.FlowCookie, Origin: p.request.Origin, Network: p.request.Network, Device: p.request.Device}, now
}

func TestSigninCallbackAuthenticatesOriginalBrowserAndCanonicalState(t *testing.T) {
	p, out, r, now := signinCallbackInputFixture(t)
	stored, err := p.openTransaction(context.Background(), out.Binding, out.BindingCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := p.service.authenticateSigninCallback(context.Background(), r, stored, p.flow, out.StateProofCiphertext, now)
	if err != nil {
		t.Fatal("original anonymous browser/canonical state rejected", err)
	}
	defer flow.destroy()
	if flow.statePlan != kernel.CapabilityPlan(stored.State) || flow.binding.Input.Binding.UserID != "" || flow.stateGrant.EnvelopeDigest() != flow.statePlan.ProofFingerprint {
		t.Fatal("callback selected a user or substituted original grant")
	}
	for name, change := range map[string]func(*oauth.SigninCallbackRequest){
		"other browser": func(r *oauth.SigninCallbackRequest) {
			r.FlowCookie = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")
		},
		"other tenant": func(r *oauth.SigninCallbackRequest) { r.TenantID = "another-tenant" },
		"other origin": func(r *oauth.SigninCallbackRequest) { r.Origin = "https://another.example" },
		"other device": func(r *oauth.SigninCallbackRequest) { r.Device = "another-device" },
	} {
		t.Run(name, func(t *testing.T) {
			other := r
			change(&other)
			got, err := p.service.authenticateSigninCallback(context.Background(), other, stored, p.flow, out.StateProofCiphertext, now)
			defer got.destroy()
			if err == nil {
				t.Fatal("changed original callback binding admitted")
			}
		})
	}
	corrupt := bytes.Clone(out.StateProofCiphertext)
	corrupt[len(corrupt)-1] ^= 1
	if got, err := p.service.authenticateSigninCallback(context.Background(), r, stored, p.flow, corrupt, now); err == nil {
		got.destroy()
		t.Fatal("corrupt canonical proof admitted")
	}
	if got, err := p.service.authenticateSigninCallback(context.Background(), r, stored, p.flow, out.StateProofCiphertext, out.Binding.ExpiresAt); err == nil {
		got.destroy()
		t.Fatal("expired state renewed at callback")
	}
}
