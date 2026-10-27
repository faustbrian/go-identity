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

func TestOrganizationBearerProfileKeepsUnselectedCookiesAndFencesCaches(t *testing.T) {
	_, request, _, observed, config, reader := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(config.LookupKeys[0], string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	request.Credential, _ = session.NewCredential(session.CredentialCookie, token)
	bearer := request
	bearer.Credential, _ = session.NewCredential(session.CredentialBearer, token)
	observed.Session, _ = session.NewSession(spec)
	methods := []session.AuthenticationKind{session.AuthenticationVerified}
	owner, err := session.NewOrganizationBearerProfileSessionService(reader, config, methods, "native-password-organization-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := owner.Get(context.Background(), request); err != nil || !got.Authenticated {
		t.Fatal("unselected cookie behavior changed", err)
	}
	v, _ := spec.Authority.Bindings()
	v.ActiveOrganizationID = "organization"
	v.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:tenant-a:one", Version: 9}}
	spec.Authority, _ = session.NewAuthoritySnapshot(v)
	observed.Session, _ = session.NewSession(spec)
	observed.Current = spec.Authority
	if got, err := owner.Get(context.Background(), request); err != nil || got.Authenticated {
		t.Fatal("selected cookie admitted by bearer-only profile", err)
	}
	positive, err := owner.Get(context.Background(), bearer)
	if err != nil || !positive.Authenticated {
		t.Fatal("selected bearer denied", err)
	}
	cached, err := owner.CacheAdmission(positive, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := owner.GetCached(context.Background(), bearer, cached); err != nil || !got.Authenticated || !got.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("selected bearer cache lost original deadline", err)
	}
	if got, err := owner.GetCached(context.Background(), request, cached); err != nil || got.Authenticated {
		t.Fatal("cached bearer changed into selected cookie", err)
	}
	keys, _ := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
	codec, _ := session.NewEncryptedCacheCodec(owner, crypto, profile)
	blob, err := codec.Seal(context.Background(), positive)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := codec.Get(context.Background(), request, blob); err != nil || got.Authenticated {
		t.Fatal("encrypted bearer changed into selected cookie", err)
	}
	legacy, err := session.NewSelectedProfileSessionService(reader, config, methods, "native-password-organization-v1")
	if err != nil {
		t.Fatal(err)
	}
	legacyCookie, err := legacy.Get(context.Background(), request)
	if err != nil || !legacyCookie.Authenticated {
		t.Fatal("existing selected-reader contract changed", err)
	}
	legacyCodec, _ := session.NewEncryptedCacheCodec(legacy, crypto, profile)
	legacyBlob, err := legacyCodec.Seal(context.Background(), legacyCookie)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	unavailable := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		return session.SessionObservation{}, session.ErrUnavailable
	})
	restarted, err := session.NewOrganizationBearerProfileSessionService(unavailable, config, methods, "native-password-organization-v1")
	if err != nil {
		t.Fatal(err)
	}
	restartedCodec, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
	if got, err := restartedCodec.Get(context.Background(), request, legacyBlob); !errors.Is(err, session.ErrUnavailable) || got.Authenticated || reads != 1 {
		t.Fatal("permissive cookie cache crossed selected transport profile", err)
	}
	if got, err := restartedCodec.Get(context.Background(), bearer, blob); err != nil || !got.Authenticated || reads != 1 || !got.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("matching bearer profile could not reuse original encrypted evidence", err)
	}
	csrf, keyErr := session.NewCSRFToken()
	key, keyConfigErr := session.NewCSRFKey(1, make([]byte, 32))
	if keyErr != nil || keyConfigErr != nil {
		t.Fatal("CSRF fixture")
	}
	state, err := csrf.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	observed.Session, err = session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := owner.Get(context.Background(), bearer); err != nil || got.Authenticated {
		t.Fatal("cookie-bound selected record downgraded to bearer", err)
	}
}
