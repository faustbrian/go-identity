package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This exercises authenticated binding and actual canonical-proof custody,
// not primary session admission, reservation or the complete business journey.
func rpCallbackInputFixture(t *testing.T) (*rpStartPhase, rpStartOutput, oauth.CallbackRequest, *time.Time) {
	t.Helper()
	p, now, _ := rpOutputFixture(t)
	c := p.service.config()
	c.Origin = "https://app.example"
	c.MaximumDuration = time.Second
	c.Coordinator.AdmissionPolicy = &kernel.CommandQueryPolicy{PolicyVersion: 1}
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.Session.Validation.LookupKeys = []session.DigestKey{key}
	p.service.config = func() LinkServiceConfig { return c }
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{22}, 32)))
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	original, err := p.originalSession()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	original, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	p.input.Session, err = sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	profile := p.service.profiles[p.input.Provider]
	profile.AuthorizationEndpoint, profile.TokenEndpoint = "https://issuer.example/authorize", "https://issuer.example/token"
	profile.ClientAuthentication, profile.Scopes, profile.Algorithms = oauth.PublicClient, []string{"openid"}, []string{"ES256"}
	profile.Timeout, profile.ClockSkew, profile.MaxResponseBytes, profile.MaxTokenBytes, profile.MaxCodeBytes = time.Second, time.Minute, 65536, 16384, 4096
	p.service.profiles[profile.ID] = profile
	wire, err := p.generateOutput(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"synthetic-original-code"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parsed.Destroy)
	b := p.input.binding()
	r := oauth.CallbackRequest{Callback: parsed, TenantID: b.TenantID, Session: bearer, Origin: c.Origin, Network: "192.0.2.12"}
	return p, out, r, now
}

func TestRPCallbackAuthenticatesOriginalStateWithoutReleasingPKCE(t *testing.T) {
	p, out, r, now := rpCallbackInputFixture(t)
	flow, err := p.service.authenticateRPCallback(context.Background(), r, out.Binding, out.StateProofCiphertext, *now)
	if err != nil {
		t.Fatal("actual issued callback state could not be authenticated", err)
	}
	defer flow.destroy()
	want := out.Plan.native().Grants[0]
	if flow.statePlan != want || flow.stateGrant.EnvelopeDigest() != want.ProofFingerprint || flow.binding.CallbackCommandID != out.Binding.CallbackCommandID || flow.binding.AccountRecordID != out.Binding.AccountRecordID {
		t.Fatal("callback replaced original state, final command or account identity")
	}
	if err := flow.stateProof.Transfer(context.Background(), func(_ context.Context, proof []byte) error {
		if len(proof) == 0 {
			t.Fatal("state verification transferred original proof")
		}
		return nil
	}); err != nil {
		t.Fatal("read-only authentication consumed proof custody", err)
	}
	// The verifier ciphertext remains byte-identical; this admission has no
	// verifier-release callback or provider exchange boundary.
	if len(out.PKCECiphertext) == 0 || len(out.StateProofCiphertext) == 0 {
		t.Fatal("input fixture lacks distinct encrypted custody")
	}
}

func TestRPCallbackRejectsSubstitutedBrowserStateProfileAndCanonicalProof(t *testing.T) {
	p, out, request, now := rpCallbackInputFixture(t)
	for name, mutate := range map[string]func(*oauth.CallbackRequest, *rpStartBinding, *[]byte, *time.Time){
		"browser": func(r *oauth.CallbackRequest, _ *rpStartBinding, _ *[]byte, _ *time.Time) {
			r.Session = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)))
		},
		"subject": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) {
			b.Input.Binding.UserID, b.Input.Binding.ActorID = "foreign", "foreign"
		},
		"tenant": func(r *oauth.CallbackRequest, _ *rpStartBinding, _ *[]byte, _ *time.Time) {
			r.TenantID = "foreign"
		},
		"origin": func(r *oauth.CallbackRequest, _ *rpStartBinding, _ *[]byte, _ *time.Time) {
			r.Origin = "https://foreign.example"
		},
		"policy": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) {
			b.Input.Binding.PolicyVersion++
		},
		"state": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) {
			b.State = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{24}, 32))
		},
		"profile": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) { b.Provider.Version++ },
		"callback command": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) {
			b.CallbackCommandID, _ = identity.NewCommandID()
		},
		"account record": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, _ *time.Time) {
			b.AccountRecordID = "foreign-account"
		},
		"proof ciphertext": func(_ *oauth.CallbackRequest, _ *rpStartBinding, proof *[]byte, _ *time.Time) {
			(*proof)[len(*proof)-1] ^= 1
		},
		"before issue": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, at *time.Time) {
			*at = b.IssuedAt.Add(-time.Nanosecond)
		},
		"exclusive expiry": func(_ *oauth.CallbackRequest, b *rpStartBinding, _ *[]byte, at *time.Time) { *at = b.ExpiresAt },
	} {
		t.Run(name, func(t *testing.T) {
			r, b, proof, at := request, out.Binding, bytes.Clone(out.StateProofCiphertext), *now
			mutate(&r, &b, &proof, &at)
			flow, err := p.service.authenticateRPCallback(context.Background(), r, b, proof, at)
			defer flow.destroy()
			if err == nil || flow.statePlan.CapabilityID != "" {
				t.Fatal("substituted original callback admitted")
			}
		})
	}
}

func TestRPProviderDenialAuthenticatesOriginalStateWithoutCodeOrPKCE(t *testing.T) {
	p, out, r, now := rpCallbackInputFixture(t)
	profile := out.Binding.Provider
	callback, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"error": {"access_denied"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	r.Callback = callback
	flow, err := p.service.authenticateRPCallback(context.Background(), r, out.Binding, out.StateProofCiphertext, *now)
	if err != nil {
		t.Fatal("denial lost original signed state", err)
	}
	defer flow.destroy()
	if flow.statePlan != out.Plan.native().Grants[0] || len(flow.pkce.ciphertext) != 0 {
		t.Fatal("denial changed consumption identity or released PKCE")
	}
	if _, ok := callback.Input(); ok {
		t.Fatal("denial fabricated an authorization code")
	}
	r.Session = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)))
	foreign, err := p.service.authenticateRPCallback(context.Background(), r, out.Binding, out.StateProofCiphertext, *now)
	defer foreign.destroy()
	if err == nil {
		t.Fatal("foreign browser authenticated another browser's denial")
	}
}
