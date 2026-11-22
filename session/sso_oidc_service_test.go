package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestSSOOIDCCookieProfileRejectsTransportSwitch(t *testing.T) {
	testSSOCookieProfile(t, false, session.NewSSOOIDCCookieProfileSessionService)
}

func TestSSOOAuth2CookieProfileRejectsTransportAndUnselectedCache(t *testing.T) {
	for _, selected := range []session.EnterpriseCookieSelection{{OAuth2: true}, {OIDC: true, OAuth2: true}} {
		t.Run(map[bool]string{false: "oauth2-only", true: "both"}[selected.OIDC], func(t *testing.T) {
			testSSOCookieProfile(t, true, func(reader session.SessionReader, config session.ServiceConfig, methods []session.AuthenticationKind, profile string) (*session.SessionService, error) {
				return session.NewEnterpriseCookieProfileSessionService(reader, config, methods, profile, selected)
			})
		})
	}
}

func testSSOCookieProfile(t *testing.T, oauth2 bool, newService func(session.SessionReader, session.ServiceConfig, []session.AuthenticationKind, string) (*session.SessionService, error)) {
	t.Helper()
	issuer, prepared, command, _, clock := ssoIssuerFixture(t, true, oauth2)
	bind := issuer.BindSSOOIDC
	if oauth2 {
		bind = issuer.BindSSOOAuth2
	}
	bound, err := bind(prepared, command)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(t.Context(), bound)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := issued.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{Session: issued.Session, Current: spec.Authority, Active: true,
			ReadStartedAt: clock.Now(), ValidUntil: clock.Now().Add(20 * time.Second)}, nil
	})
	config := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: clock,
		MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}
	methods := []session.AuthenticationKind{session.AuthenticationVerified}
	profile, err := newService(reader, config, methods, "enterprise-primary")
	if err != nil {
		t.Fatal(err)
	}
	var cookieRequest, bearerRequest session.GetRequest
	var original session.GetResult
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		credential, err := session.NewCredential(mode, issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		request := session.GetRequest{TenantID: spec.TenantID, Credential: credential}
		result, err := profile.Get(t.Context(), request)
		if mode == session.CredentialCookie {
			if err != nil || !result.Authenticated {
				t.Fatal("configured enterprise cookie path was denied", err)
			}
			cookieRequest, original = request, result
		}
		if mode == session.CredentialBearer {
			if err != nil || result.Authenticated || result.Session != (session.Session{}) {
				t.Fatal("the same enterprise credential was admitted as a bearer", err)
			}
			bearerRequest = request
		}
	}
	keys, err := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	cacheConfig := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
	codec, err := session.NewEncryptedCacheCodec(profile, crypto, cacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := codec.Seal(t.Context(), original)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	unavailable := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		return session.SessionObservation{}, session.ErrUnavailable
	})
	restarted, err := newService(unavailable, config, methods, "enterprise-primary")
	if err != nil {
		t.Fatal(err)
	}
	restartedCodec, err := session.NewEncryptedCacheCodec(restarted, crypto, cacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = original.ValidUntil().Add(-time.Nanosecond)
	if warm, err := restartedCodec.Get(t.Context(), cookieRequest, blob); err != nil || !warm.Authenticated || reads != 0 || !warm.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("restart did not preserve exact cached cookie admission and deadline", err)
	}
	if got, err := restartedCodec.Get(t.Context(), bearerRequest, blob); !errors.Is(err, session.ErrUnavailable) || got.Authenticated || reads != 1 {
		t.Fatal("enterprise cached cookie was used as a bearer", err)
	}
	plain, err := session.NewOrganizationBearerProfileSessionService(unavailable, config, methods, "enterprise-primary")
	if err != nil {
		t.Fatal(err)
	}
	plainCodec, err := session.NewEncryptedCacheCodec(plain, crypto, cacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := plainCodec.Get(t.Context(), cookieRequest, blob); !errors.Is(err, session.ErrUnavailable) || got.Authenticated || reads != 2 {
		t.Fatal("enterprise cached cookie crossed into an organization-bearer profile", err)
	}
	if oauth2 {
		oidcOnly, err := session.NewSSOOIDCCookieProfileSessionService(reader, config, methods, "enterprise-primary")
		if err != nil {
			t.Fatal(err)
		}
		oidcCodec, err := session.NewEncryptedCacheCodec(oidcOnly, crypto, cacheConfig)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := oidcCodec.Get(t.Context(), cookieRequest, blob); err != nil || got.Authenticated {
			t.Fatal("OAuth2 cache or primary record crossed into an OIDC-only profile", err)
		}
	}
	clock.now = original.ValidUntil()
	if got, err := restartedCodec.Get(t.Context(), cookieRequest, blob); !errors.Is(err, session.ErrUnavailable) || got.Authenticated || reads != 3 {
		t.Fatal("encrypted cached enterprise authority survived its exact deadline", err)
	}
}
