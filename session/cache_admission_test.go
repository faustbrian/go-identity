package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestCachedAdmissionCannotRenewOriginalValidity(t *testing.T) {
	_, request, clock, observed, config, _ := validationFixture(t)
	reads := 0
	outage := false
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		if outage {
			return session.SessionObservation{}, session.ErrUnavailable
		}
		return *observed, nil
	})
	service, _ := session.NewSessionService(reader, config)
	original, err := service.Get(context.Background(), request)
	if err != nil || !original.Authenticated {
		t.Fatal(err)
	}
	cached, err := service.CacheAdmission(original, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	outage = true
	clock.now = original.ValidUntil().Add(-time.Nanosecond)
	warm, err := service.GetCached(context.Background(), request, cached)
	if err != nil || !warm.Authenticated || reads != 1 || !warm.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("warm original evidence rejected/renewed", err)
	}
	promoted, err := service.CacheAdmission(warm, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = original.ValidUntil()
	denied, err := service.GetCached(context.Background(), request, promoted)
	if err != session.ErrUnavailable || denied.Authenticated || reads != 2 {
		t.Fatal("expired cached authority survived outage", err)
	}
}

func TestCachedAdmissionScopeAndTransportSubstitutionUsePrimary(t *testing.T) {
	_, request, _, observed, config, _ := validationFixture(t)
	token, _ := session.NewToken(32)
	spec, _ := observed.Session.Bindings()
	spec.Lookup, _ = token.Digest(config.LookupKeys[0], string(spec.TenantID))
	observed.Session, _ = session.NewSession(spec)
	request.Credential, _ = session.NewCredential(session.CredentialCookie, token)
	reads := 0
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		reads++
		return *observed, nil
	})
	service, _ := session.NewSessionService(reader, config)
	result, _ := service.Get(context.Background(), request)
	cache, _ := service.CacheAdmission(result, time.Minute)
	otherToken, _ := session.NewToken(32)
	otherCredential, _ := session.NewCredential(session.CredentialCookie, otherToken)
	bearer, _ := session.NewCredential(session.CredentialBearer, token)
	for _, change := range []session.GetRequest{{TenantID: "foreign", Credential: request.Credential}, {TenantID: request.TenantID, Credential: otherCredential}, {TenantID: request.TenantID, Credential: bearer}} {
		before := reads
		got, err := service.GetCached(context.Background(), change, cache)
		if err != nil || reads != before+1 || (change.Credential.Kind() != session.CredentialBearer && got.Authenticated) || (change.Credential.Kind() == session.CredentialBearer && !got.Authenticated) {
			t.Fatal("substituted cached credential used without primary", err)
		}
	}
	foreign, _ := session.NewSessionService(reader, config)
	before := reads
	got, err := foreign.GetCached(context.Background(), request, cache)
	if err != nil || !got.Authenticated || reads != before+1 {
		t.Fatal("foreign service cache bypassed primary", err)
	}
	if _, err := foreign.CacheAdmission(result, time.Minute); err != session.ErrUnauthenticated {
		t.Fatal("foreign result accepted", err)
	}
}

func TestCachedAdmissionShortAgePromotionAndMissedRevocation(t *testing.T) {
	_, request, clock, observed, config, _ := validationFixture(t)
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return *observed, nil
	})
	service, _ := session.NewSessionService(reader, config)
	result, _ := service.Get(context.Background(), request)
	cache, _ := service.CacheAdmission(result, time.Second)
	deadline := clock.now.Add(time.Second)
	observed.Active = false // Simulate revocation with a dropped invalidation event.
	clock.now = deadline.Add(-time.Nanosecond)
	warm, err := service.GetCached(context.Background(), request, cache)
	if err != nil || !warm.Authenticated || !warm.ValidUntil().Equal(deadline) {
		t.Fatal("short-age warm evidence", err)
	}
	promoted, err := service.CacheAdmission(warm, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = deadline
	got, err := service.GetCached(context.Background(), request, promoted)
	if err != nil || got.Authenticated {
		t.Fatal("promotion renewed short bound or revoked source", err)
	}
	if _, err := service.CacheAdmission(warm, time.Minute); err != session.ErrUnauthenticated {
		t.Fatal("expired promotion", err)
	}
}

func TestCachedAdmissionRejectsFabricationAndPreservesCustody(t *testing.T) {
	service, request, _, _, _, _ := validationFixture(t)
	result, _ := service.Get(context.Background(), request)
	for _, duration := range []time.Duration{0, time.Millisecond - 1, 5*time.Minute + 1} {
		if _, err := service.CacheAdmission(result, duration); err != session.ErrInvalidInput {
			t.Fatal("invalid age", err)
		}
	}
	for _, bad := range []session.GetResult{{}, {Authenticated: true, Session: result.Session}, func() session.GetResult { r := result; r.NeedsRefresh = !r.NeedsRefresh; return r }(), func() session.GetResult { r := result; r.Session = session.Session{}; return r }()} {
		if _, err := service.CacheAdmission(bad, time.Minute); err != session.ErrUnauthenticated {
			t.Fatal("fabricated result", err)
		}
	}
	cache, _ := service.CacheAdmission(result, time.Minute)
	result.Session = session.Session{}
	result.Authenticated = false
	got, err := service.GetCached(context.Background(), request, cache)
	if err != nil || !got.Authenticated {
		t.Fatal("caller mutated cached copy", err)
	}
	for _, v := range []any{cache, &cache} {
		if fmt.Sprintf("%#v", v) != "session.CachedAdmission(redacted)" {
			t.Fatal("diagnostic export")
		}
		if b, e := json.Marshal(v); e == nil || len(b) != 0 {
			t.Fatal("JSON export")
		}
	}
	if b, e := cache.MarshalText(); e != session.ErrSecretSerialization || b != nil {
		t.Fatal("text export")
	}
	if _, err := (*session.SessionService)(nil).CacheAdmission(result, time.Minute); err != session.ErrInvalidInput {
		t.Fatal("nil cache service")
	}
	if _, err := service.GetCached(nil, request, cache); err != session.ErrInvalidInput {
		t.Fatal("nil context")
	}
	if _, err := (*session.SessionService)(nil).GetCached(context.Background(), request, cache); err != session.ErrInvalidInput {
		t.Fatal("nil get service")
	}
	if _, err := service.GetCached(context.Background(), session.GetRequest{}, cache); err != session.ErrInvalidInput {
		t.Fatal("zero request")
	}
}

func TestCachedAdmissionCancellationClockAndConcurrency(t *testing.T) {
	service, request, clock, _, config, reader := validationFixture(t)
	result, _ := service.Get(context.Background(), request)
	cache, _ := service.CacheAdmission(result, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := service.GetCached(ctx, request, cache)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) || got.Authenticated {
		t.Fatal("cancelled warm acceptance", err)
	}
	clock.now = clock.now.Add(-time.Nanosecond)
	got, err = service.GetCached(context.Background(), request, cache)
	if err != session.ErrUnavailable || got.Authenticated {
		t.Fatal("backward clock accepted", err)
	}
	clock.now = clock.now.Add(time.Nanosecond)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := service.GetCached(context.Background(), request, cache)
			if e != nil || !r.Authenticated || !r.ValidUntil().Equal(result.ValidUntil()) {
				t.Error("concurrent copied admission", e)
			}
		}()
	}
	group.Wait()
	config.Clock = validationClock(func() time.Time { panic("private clock") })
	broken, _ := session.NewSessionService(reader, config)
	if r, e := broken.GetCached(context.Background(), request, cache); e != session.ErrUnavailable || r.Authenticated {
		t.Fatal("clock panic", e)
	}
	if _, e := broken.CacheAdmission(result, time.Minute); e != session.ErrUnauthenticated {
		t.Fatal("foreign proof before clock", e)
	}
}
