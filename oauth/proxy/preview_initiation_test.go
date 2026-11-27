package oauthproxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/session"
)

func TestPreviewInitiationAdmissionReturnsOnlyConfiguredTrustedBindings(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		t.Run(fmt.Sprint(choice), func(t *testing.T) {
			config, request := initiationFixture(t, choice)
			var calls int
			config.Authentication = initiationAuthenticator(func(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
				calls++
				bearer, ok := credential.(authentication.BearerCredential)
				if !ok || bearer.Token() != request.Credential.Token() {
					t.Fatal("authentication did not receive the presented bearer credential")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > config.MaximumDuration || ctx.Err() != nil {
					t.Fatal("authentication did not receive a live bounded context")
				}
				// Hints never choose or override the deployment's tenant binding.
				return initiationAuthenticated(t, authentication.PrincipalSpec{
					Subject: string(config.ActorID), Method: "bearer", Issuer: config.Issuer,
					Audiences: []string{config.Audience}, Scopes: []string{"identity.oauth.proxy-start"},
					TenantHints: []string{"untrusted-other-tenant"},
				}), nil
			})
			admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := admission.Admit(t.Context(), request)
			want := oauthproxy.InitiationBinding{
				TenantID: config.TenantID, ActorID: config.ActorID, Target: config.Target,
				CommandID: request.CommandID, TransactionID: request.TransactionID,
				RequestFingerprint: request.RequestFingerprint, Remember: request.Remember,
			}
			if err != nil || binding != want || calls != 1 {
				t.Fatalf("admission did not preserve the exact trusted binding: %v", err)
			}
		})
	}
}

func TestPreviewInitiationAdmissionRejectsUntrustedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*oauthproxy.PreviewInitiationConfig)
	}{
		{"missing tenant", func(c *oauthproxy.PreviewInitiationConfig) { c.TenantID = "" }},
		{"invalid tenant", func(c *oauthproxy.PreviewInitiationConfig) { c.TenantID = " tenant" }},
		{"invalid actor", func(c *oauthproxy.PreviewInitiationConfig) { c.ActorID = "actor\n" }},
		{"missing actor", func(c *oauthproxy.PreviewInitiationConfig) { c.ActorID = "" }},
		{"missing issuer", func(c *oauthproxy.PreviewInitiationConfig) { c.Issuer = "" }},
		{"oversized issuer", func(c *oauthproxy.PreviewInitiationConfig) { c.Issuer = strings.Repeat("i", 2049) }},
		{"invalid issuer", func(c *oauthproxy.PreviewInitiationConfig) { c.Issuer = "issuer\n" }},
		{"missing audience", func(c *oauthproxy.PreviewInitiationConfig) { c.Audience = "" }},
		{"oversized audience", func(c *oauthproxy.PreviewInitiationConfig) { c.Audience = strings.Repeat("a", 2049) }},
		{"missing authenticator", func(c *oauthproxy.PreviewInitiationConfig) { c.Authentication = nil }},
		{"typed nil authenticator", func(c *oauthproxy.PreviewInitiationConfig) { c.Authentication = (*nilInitiationAuthenticator)(nil) }},
		{"missing duration", func(c *oauthproxy.PreviewInitiationConfig) { c.MaximumDuration = 0 }},
		{"negative duration", func(c *oauthproxy.PreviewInitiationConfig) { c.MaximumDuration = -time.Second }},
		{"excess duration", func(c *oauthproxy.PreviewInitiationConfig) { c.MaximumDuration = 20*time.Second + 1 }},
		{"non HTTPS target", func(c *oauthproxy.PreviewInitiationConfig) { c.Target.Origin = "http://preview.example.test" }},
		{"unregistered redirect origin", func(c *oauthproxy.PreviewInitiationConfig) { c.Target.Redirect = "https://other.example.test/complete" }},
		{"noncanonical target", func(c *oauthproxy.PreviewInitiationConfig) { c.Target.Origin += "/" }},
		{"wildcard target", func(c *oauthproxy.PreviewInitiationConfig) { c.Target.Origin = "https://*.example.test" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, _ := initiationFixture(t, session.BrowserSession)
			tc.alter(&config)
			admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
			if admission != nil || !errors.Is(err, oauthproxy.InitiationInvalid) {
				t.Fatal("invalid registration produced an admission boundary")
			}
		})
	}
}

func TestPreviewInitiationAdmissionRejectsInvalidRequestsBeforeAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*oauthproxy.InitiationRequest)
	}{
		{"missing command", func(r *oauthproxy.InitiationRequest) { r.CommandID = "" }},
		{"noncanonical command", func(r *oauthproxy.InitiationRequest) { r.CommandID += "=" }},
		{"missing transaction", func(r *oauthproxy.InitiationRequest) { r.TransactionID = "" }},
		{"noncanonical transaction", func(r *oauthproxy.InitiationRequest) { r.TransactionID += "=" }},
		{"same command and transaction", func(r *oauthproxy.InitiationRequest) { r.TransactionID = identity.PreAuthTransactionID(r.CommandID) }},
		{"missing fingerprint", func(r *oauthproxy.InitiationRequest) { r.RequestFingerprint = [32]byte{} }},
		{"unresolved remember", func(r *oauthproxy.InitiationRequest) { r.Remember = session.RememberPolicy{} }},
		{"missing credential", func(r *oauthproxy.InitiationRequest) { r.Credential = authentication.BearerCredential{} }},
		{"oversized credential", func(r *oauthproxy.InitiationRequest) {
			r.Credential = authentication.NewBearerCredential(strings.Repeat("s", 8193))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, request := initiationFixture(t, session.BrowserSession)
			config.Authentication = initiationAuthenticator(func(context.Context, authentication.Credential) (authentication.Result, error) {
				t.Fatal("invalid input reached authentication")
				return authentication.Result{}, nil
			})
			admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
			if err != nil {
				t.Fatal(err)
			}
			tc.alter(&request)
			binding, err := admission.Admit(t.Context(), request)
			assertInitiationFailure(t, binding, err, oauthproxy.InitiationInvalid)
		})
	}
}

func TestPreviewInitiationAdmissionRequiresExactAuthenticatedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*authentication.PrincipalSpec)
	}{
		{"different subject", func(p *authentication.PrincipalSpec) { p.Subject = "other-actor" }},
		{"subject case mismatch", func(p *authentication.PrincipalSpec) { p.Subject = "actor-a" }},
		{"different issuer", func(p *authentication.PrincipalSpec) { p.Issuer += "/other" }},
		{"missing audience", func(p *authentication.PrincipalSpec) { p.Audiences = nil }},
		{"different audience", func(p *authentication.PrincipalSpec) { p.Audiences = []string{"other-audience"} }},
		{"additional audience", func(p *authentication.PrincipalSpec) { p.Audiences = append(p.Audiences, "other-audience") }},
		{"duplicate audience", func(p *authentication.PrincipalSpec) { p.Audiences = append(p.Audiences, p.Audiences[0]) }},
		{"missing scope", func(p *authentication.PrincipalSpec) { p.Scopes = nil }},
		{"different scope", func(p *authentication.PrincipalSpec) { p.Scopes = []string{"identity.oauth.signin"} }},
		{"additional scope", func(p *authentication.PrincipalSpec) { p.Scopes = append(p.Scopes, "identity.oauth.signin") }},
		{"duplicate scope", func(p *authentication.PrincipalSpec) { p.Scopes = append(p.Scopes, p.Scopes[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, request := initiationFixture(t, session.BrowserSession)
			principal := authentication.PrincipalSpec{Subject: string(config.ActorID), Method: "bearer", Issuer: config.Issuer,
				Audiences: []string{config.Audience}, Scopes: []string{"identity.oauth.proxy-start"}}
			tc.alter(&principal)
			config.Authentication = initiationAuthenticator(func(context.Context, authentication.Credential) (authentication.Result, error) {
				return initiationAuthenticated(t, principal), nil
			})
			admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := admission.Admit(t.Context(), request)
			assertInitiationFailure(t, binding, err, oauthproxy.InitiationDenied)
		})
	}
}

func TestPreviewInitiationAdmissionRejectsAnonymousFailuresAndPanicsWithoutDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth initiationAuthenticator
		want oauthproxy.InitiationError
	}{
		{"anonymous", func(context.Context, authentication.Credential) (authentication.Result, error) {
			return authentication.AnonymousResult(), nil
		}, oauthproxy.InitiationDenied},
		{"zero result", func(context.Context, authentication.Credential) (authentication.Result, error) {
			return authentication.Result{}, nil
		}, oauthproxy.InitiationDenied},
		{"authentication failure", func(context.Context, authentication.Credential) (authentication.Result, error) {
			return authentication.Result{}, errors.New("sensitive-auth-diagnostic")
		}, oauthproxy.InitiationDenied},
		{"panic", func(context.Context, authentication.Credential) (authentication.Result, error) {
			panic("sensitive-auth-diagnostic")
		}, oauthproxy.InitiationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, request := initiationFixture(t, session.BrowserSession)
			config.Authentication = tc.auth
			admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
			if err != nil {
				t.Fatal(err)
			}
			// An injected context principal must never stand in for credential authentication.
			principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{Subject: string(config.ActorID), Method: "bearer",
				Issuer: config.Issuer, Audiences: []string{config.Audience}, Scopes: []string{"identity.oauth.proxy-start"}})
			if err != nil {
				t.Fatal(err)
			}
			ctx := authentication.ContextWithPrincipal(t.Context(), principal)
			binding, err := admission.Admit(ctx, request)
			assertInitiationFailure(t, binding, err, tc.want)
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("authentication diagnostic escaped")
			}
		})
	}
}

func TestPreviewInitiationAdmissionUsesEarlierDeadlineAndRejectsLateSuccess(t *testing.T) {
	config, request := initiationFixture(t, session.BrowserSession)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	config.MaximumDuration = 20 * time.Second
	config.Authentication = initiationAuthenticator(func(work context.Context, _ authentication.Credential) (authentication.Result, error) {
		deadline, _ := work.Deadline()
		if deadline != wantDeadline {
			t.Fatal("admission extended the caller deadline")
		}
		cancel()
		return initiationSuccess(t, config), nil
	})
	admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := admission.Admit(ctx, request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationUnavailable)

	config.MaximumDuration = time.Millisecond
	config.Authentication = initiationAuthenticator(func(work context.Context, _ authentication.Credential) (authentication.Result, error) {
		<-work.Done()
		return initiationSuccess(t, config), nil
	})
	admission, err = oauthproxy.NewPreviewInitiationAdmission(config)
	if err != nil {
		t.Fatal(err)
	}
	binding, err = admission.Admit(t.Context(), request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationUnavailable)
}

func TestPreviewInitiationAdmissionRejectsCanceledAndNilContextsBeforeAuthentication(t *testing.T) {
	config, request := initiationFixture(t, session.BrowserSession)
	config.Authentication = initiationAuthenticator(func(context.Context, authentication.Credential) (authentication.Result, error) {
		t.Fatal("unusable context reached authentication")
		return authentication.Result{}, nil
	})
	admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	binding, err := admission.Admit(ctx, request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationUnavailable)
	binding, err = admission.Admit(nil, request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationInvalid)
	var uninitialized oauthproxy.PreviewInitiationAdmission
	binding, err = uninitialized.Admit(t.Context(), request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationInvalid)
	var absent *oauthproxy.PreviewInitiationAdmission
	binding, err = absent.Admit(t.Context(), request)
	assertInitiationFailure(t, binding, err, oauthproxy.InitiationInvalid)
}

func TestPreviewInitiationValuesRedactFormattingAndRejectSerialization(t *testing.T) {
	config, request := initiationFixture(t, session.BrowserSession)
	admission, err := oauthproxy.NewPreviewInitiationAdmission(config)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := admission.Admit(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, request, binding, admission} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(verb, value)
			for _, private := range []string{request.Credential.Token(), string(config.TenantID), string(config.ActorID), config.Target.Origin, string(request.CommandID)} {
				if strings.Contains(formatted, private) {
					t.Fatal("formatting exposed private initiation data")
				}
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, oauthproxy.InitiationInvalid) {
			t.Fatal("initiation data was serializable")
		}
	}
}

type initiationAuthenticator func(context.Context, authentication.Credential) (authentication.Result, error)

func (f initiationAuthenticator) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	return f(ctx, credential)
}

type nilInitiationAuthenticator struct{}

func (*nilInitiationAuthenticator) Authenticate(context.Context, authentication.Credential) (authentication.Result, error) {
	panic("typed nil authenticator must not be accepted")
}

func initiationFixture(t *testing.T, choice session.RememberChoice) (oauthproxy.PreviewInitiationConfig, oauthproxy.InitiationRequest) {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession,
		AbsoluteTTL: 72 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	config := oauthproxy.PreviewInitiationConfig{TenantID: "Tenant-A", ActorID: "Actor-A", Issuer: "https://identity.example.test",
		Audience: "preview-start", Target: oauthproxy.PreviewTarget{Deployment: "preview-a", Origin: "https://preview.example.test",
			Redirect: "https://preview.example.test/complete", Recipient: "preview-client"}, MaximumDuration: time.Second}
	config.Authentication = initiationAuthenticator(func(context.Context, authentication.Credential) (authentication.Result, error) {
		return initiationSuccess(t, config), nil
	})
	return config, oauthproxy.InitiationRequest{Credential: authentication.NewBearerCredential("private-initiation-token"),
		CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TransactionID: "AgICAgICAgICAgICAgICAg", RequestFingerprint: [32]byte{1}, Remember: remember}
}

func initiationSuccess(t *testing.T, config oauthproxy.PreviewInitiationConfig) authentication.Result {
	t.Helper()
	return initiationAuthenticated(t, authentication.PrincipalSpec{Subject: string(config.ActorID), Method: "bearer", Issuer: config.Issuer,
		Audiences: []string{config.Audience}, Scopes: []string{"identity.oauth.proxy-start"}})
}

func initiationAuthenticated(t *testing.T, spec authentication.PrincipalSpec) authentication.Result {
	t.Helper()
	principal, err := authentication.NewPrincipal(spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := authentication.NewAuthenticatedResult(principal)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertInitiationFailure(t *testing.T, binding oauthproxy.InitiationBinding, err error, want oauthproxy.InitiationError) {
	t.Helper()
	if binding != (oauthproxy.InitiationBinding{}) || !errors.Is(err, want) {
		t.Fatalf("failure exposed a trusted binding or returned the wrong class: %v", err)
	}
}
