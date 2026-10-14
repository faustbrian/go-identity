package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type observedSession func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (f observedSession) ObserveSession(ctx context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
	return f(ctx, lookup)
}

type validationClock func() time.Time

func (f validationClock) Now() time.Time { return f() }

func validationFixture(t *testing.T) (*session.SessionService, session.GetRequest, *mutableIssueClock, *session.SessionObservation, session.ServiceConfig, observedSession) {
	t.Helper()
	spec := sessionSpec(t)
	clock := &mutableIssueClock{now: spec.IssuedAt.Add(time.Second)}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	observed := &session.SessionObservation{Session: record, Current: spec.Authority, Active: true, ReadStartedAt: clock.now, ValidUntil: clock.now.Add(20 * time.Second)}
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return *observed, nil
	})
	config := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}
	service, err := session.NewSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return service, session.GetRequest{TenantID: spec.TenantID, Credential: credential}, clock, observed, config, reader
}

func TestSessionGetCancellationDuringFinalClock(t *testing.T) {
	_, request, clock, _, config, reader := validationFixture(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	calls := 0
	config.Clock = validationClock(func() time.Time {
		calls++
		if calls == 2 {
			stop()
		}
		return clock.now
	})
	service, err := session.NewSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(ctx, request)
	var cancelled identity.CancelledError
	if !errors.As(err, &cancelled) || result.Authenticated || result.Session != (session.Session{}) {
		t.Fatal("cancelled final admission accepted", err)
	}
}

func TestSessionGetCannotRenewCopiedSourceFreshness(t *testing.T) {
	service, request, clock, observed, _, _ := validationFixture(t)
	original, err := service.Get(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(4 * time.Second)
	copied, err := service.Get(context.Background(), request)
	if err != nil || !copied.ValidUntil().Equal(original.ValidUntil()) || original.ValidateAt(clock.now) != nil {
		t.Fatal("copy/promotion renewed source validity")
	}
	clock.now = original.ValidUntil()
	if !errors.Is(original.ValidateAt(clock.now), session.ErrUnauthenticated) || !errors.Is(copied.ValidateAt(clock.now), session.ErrUnauthenticated) {
		t.Fatal("exclusive copied deadline accepted")
	}
	result, err := service.Get(context.Background(), request)
	if err != nil || result.Authenticated {
		t.Fatal("expired source reused")
	}
	if !observed.ValidUntil.Equal(observed.ReadStartedAt.Add(20 * time.Second)) {
		t.Fatal("source timestamps mutated")
	}
	forged := session.GetResult{Authenticated: true, Session: original.Session}
	if forged.ValidateAt(original.ValidUntil().Add(-time.Second)) == nil {
		t.Fatal("public reconstruction gained custody")
	}
}

func TestSessionGetRetainsRefreshAndOriginalAuthenticationPolicy(t *testing.T) {
	service, request, clock, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy, _ := spec.Remember.Bindings()
	clock.now = spec.LastActivityAt.Add(policy.RefreshAfter)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	result, err := service.Get(context.Background(), request)
	if err != nil || !result.Authenticated || !result.NeedsRefresh || !result.RefreshEligibleAt.Equal(clock.now) {
		t.Fatal("refresh policy boundary lost", err)
	}
	retained, _ := result.Session.Bindings()
	if retained != spec || !retained.Authentication.Proof.IssuedAt.Equal(spec.Authentication.Proof.IssuedAt) {
		t.Fatal("Get renewed activity or authentication")
	}
	clock.now = spec.IssuedAt.Add(policy.AbsoluteTTL - time.Second)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	result, err = service.Get(context.Background(), request)
	if err != nil || !result.Authenticated || !result.ValidUntil().Equal(spec.IssuedAt.Add(policy.AbsoluteTTL)) {
		t.Fatal("source validity outlived session", err)
	}
}

func TestSessionGetDelayedReadPreservesOriginalWindowAndOutageDenial(t *testing.T) {
	_, request, clock, observed, config, _ := validationFixture(t)
	start := clock.now
	config.MaximumDuration = 5 * time.Second
	reader := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		clock.now = start.Add(4 * time.Second)
		return *observed, nil
	})
	service, err := session.NewSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(context.Background(), request)
	if err != nil || !result.Authenticated || !result.ValidUntil().Equal(start.Add(20*time.Second-config.ClockUncertainty)) {
		t.Fatal("response delay renewed evidence", err)
	}
	clock.now = result.ValidUntil()
	if result.ValidateAt(clock.now) == nil {
		t.Fatal("delayed source outlived original deadline")
	}
	reader = observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return *observed, errors.New("private outage")
	})
	service, _ = session.NewSessionService(reader, config)
	if result, err := service.Get(context.Background(), request); !errors.Is(err, session.ErrUnavailable) || result.Authenticated || !result.ValidUntil().IsZero() {
		t.Fatal("outage reused stale admission")
	}
}

func TestSessionGetDeniesEveryCurrentAuthorityMismatch(t *testing.T) {
	for i := range 8 {
		for _, change := range []string{"version", "scope"} {
			t.Run(fmt.Sprintf("%d/%s", i, change), func(t *testing.T) {
				service, request, _, observed, _, _ := validationFixture(t)
				current, err := observed.Current.Bindings()
				if err != nil {
					t.Fatal(err)
				}
				if change == "version" {
					bindings(&current)[i].Version++
				} else {
					bindings(&current)[i].ScopeKey += ":other"
				}
				observed.Current, err = session.NewAuthoritySnapshot(current)
				if err != nil {
					t.Fatal(err)
				}
				result, err := service.Get(context.Background(), request)
				if err != nil || result.Authenticated || result.Session != (session.Session{}) {
					t.Fatal("changed authority admitted")
				}
			})
		}
	}
	for _, dimension := range []string{"organization", "factor", "passkey"} {
		service, request, _, observed, _, _ := validationFixture(t)
		current, _ := observed.Current.Bindings()
		added := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: dimension + ":other", Version: 1}}
		switch dimension {
		case "organization":
			current.ActiveOrganizationID, current.Organization = "organization", added
		case "factor":
			current.Factor = added
		case "passkey":
			current.Passkey = added
		}
		observed.Current, _ = session.NewAuthoritySnapshot(current)
		if result, err := service.Get(context.Background(), request); err != nil || result.Authenticated {
			t.Fatal("optional dimension changed")
		}
	}
}

func TestSessionGetScopeDigestExpiryAndAnonymousDenial(t *testing.T) {
	for _, mode := range []string{"inactive", "tenant", "audience", "digest", "anonymous", "idle-expired", "stale-source"} {
		t.Run(mode, func(t *testing.T) {
			service, request, clock, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			switch mode {
			case "inactive":
				observed.Active = false
			case "tenant":
				spec.TenantID, spec.Authentication.Proof.Tenant = "other", "other"
			case "audience":
				spec.Audience, spec.Authentication.Proof.Audience = "other", "other"
			case "digest":
				spec.Lookup.Sum[0] ^= 1
			case "anonymous":
				spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
			case "idle-expired":
				p, _ := spec.Remember.Bindings()
				clock.now = spec.LastActivityAt.Add(p.IdleTTL)
				observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
			case "stale-source":
				observed.ReadStartedAt, observed.ValidUntil = clock.now.Add(-30*time.Second), clock.now.Add(-10*time.Second)
			}
			var err error
			observed.Session, err = session.NewSession(spec)
			if err != nil {
				t.Fatal("invalid denial fixture", err)
			}
			if result, err := service.Get(context.Background(), request); err != nil || result.Authenticated || result.Session != (session.Session{}) {
				t.Fatal("invalid session disclosed")
			}
		})
	}
}

func TestSessionGetRejectsMalformedClockAndAuthorityEvidence(t *testing.T) {
	for _, mode := range []string{"zero-clock", "clock-panic", "zero-session", "zero-vector", "zero-start", "zero-end", "inverted", "extended", "future-source", "clock-backward"} {
		t.Run(mode, func(t *testing.T) {
			service, request, clock, observed, config, reader := validationFixture(t)
			switch mode {
			case "zero-clock":
				clock.now = time.Time{}
			case "clock-panic":
				clock.panicNow = true
			case "zero-session":
				observed.Session = session.Session{}
			case "zero-vector":
				observed.Current = session.AuthoritySnapshot{}
			case "zero-start":
				observed.ReadStartedAt = time.Time{}
			case "zero-end":
				observed.ValidUntil = time.Time{}
			case "inverted":
				observed.ValidUntil = observed.ReadStartedAt
			case "extended":
				observed.ValidUntil = observed.ValidUntil.Add(time.Nanosecond)
			case "future-source":
				observed.ReadStartedAt = clock.now.Add(time.Second)
				observed.ValidUntil = observed.ReadStartedAt.Add(time.Second)
			case "clock-backward":
				calls := 0
				config.Clock = validationClock(func() time.Time {
					calls++
					if calls > 1 {
						return clock.now.Add(-time.Second)
					}
					return clock.now
				})
				service, _ = session.NewSessionService(reader, config)
			}
			if result, err := service.Get(context.Background(), request); !errors.Is(err, session.ErrUnavailable) || result.Authenticated {
				t.Fatal("invalid evidence admitted", mode, err)
			}
		})
	}
}

func TestSessionGetRejectsUnsafeCompositionAndInput(t *testing.T) {
	_, request, _, _, config, reader := validationFixture(t)
	for _, mutate := range []func(*session.ServiceConfig){
		func(c *session.ServiceConfig) { c.Profile = session.StorageStateless }, func(c *session.ServiceConfig) { c.Profile = 0 },
		func(c *session.ServiceConfig) { c.Audience = "" }, func(c *session.ServiceConfig) { c.Clock = nil },
		func(c *session.ServiceConfig) { c.MaximumDuration = 0 }, func(c *session.ServiceConfig) { c.MaximumDuration = 5*time.Second + time.Nanosecond },
		func(c *session.ServiceConfig) { c.ClockUncertainty = 0 }, func(c *session.ServiceConfig) { c.ClockUncertainty = 5*time.Second + time.Nanosecond },
		func(c *session.ServiceConfig) { c.LookupKeys = nil }, func(c *session.ServiceConfig) { c.LookupKeys = []session.DigestKey{{}} },
		func(c *session.ServiceConfig) { c.LookupKeys = []session.DigestKey{c.LookupKeys[0], c.LookupKeys[0]} },
	} {
		c := config
		mutate(&c)
		if service, err := session.NewSessionService(reader, c); service != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("unsafe composition admitted")
		}
	}
	var nilReader observedSession
	if _, err := session.NewSessionService(nilReader, config); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("typed nil reader admitted")
	}
	if _, err := session.NewCredential(0, session.Token{}); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("zero credential accepted")
	}
	var zero *session.SessionService
	if _, err := zero.Get(context.Background(), request); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("zero service accepted")
	}
	service, _ := session.NewSessionService(reader, config)
	if _, err := service.Get(nil, request); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil context accepted")
	}
	if _, err := service.Get(context.Background(), session.GetRequest{}); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("zero request accepted")
	}
}

func TestSessionGetDependencyFailuresAreRedactedAndCancelled(t *testing.T) {
	for _, mode := range []string{"error", "panic", "absent", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			_, request, _, observed, config, _ := validationFixture(t)
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			reader := observedSession(func(ctx context.Context, _ session.SessionLookup) (session.SessionObservation, error) {
				switch mode {
				case "error":
					return *observed, errors.New("private backend detail")
				case "panic":
					panic("private backend detail")
				case "absent":
					return *observed, session.ErrUnauthenticated
				case "cancel":
					stop()
					return *observed, nil
				case "deadline":
					<-ctx.Done()
					return *observed, nil
				}
				return *observed, nil
			})
			if mode == "deadline" {
				config.MaximumDuration = time.Millisecond
			}
			service, _ := session.NewSessionService(reader, config)
			result, err := service.Get(ctx, request)
			if result.Authenticated || result.Session != (session.Session{}) {
				t.Fatal("failure exposed session")
			}
			if mode == "absent" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unredacted failure")
			}
			if mode == "cancel" {
				var e identity.CancelledError
				if !errors.As(err, &e) {
					t.Fatal("lost cancellation")
				}
			}
			if mode == "deadline" {
				var e identity.DeadlineExceededError
				if !errors.As(err, &e) {
					t.Fatal("lost deadline")
				}
			}
		})
	}
}

func TestSessionGetFreezesKeySelectionAndLookupIdentity(t *testing.T) {
	_, request, _, observed, config, _ := validationFixture(t)
	second, err := session.NewDigestKey(2, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	config.LookupKeys = append(config.LookupKeys, second)
	reader := observedSession(func(_ context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
		if len(lookup.Digests) != 2 || lookup.Digests[0].KeyVersion != 1 || lookup.Digests[1].KeyVersion != 2 {
			t.Fatal("key selection mutated")
		}
		return *observed, nil
	})
	service, err := session.NewSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	config.LookupKeys[0] = second
	if result, err := service.Get(context.Background(), request); err != nil || !result.Authenticated {
		t.Fatal("retained original key denied")
	}
	spec, _ := observed.Session.Bindings()
	spec.Lookup.Sum = [32]byte{1}
	observed.Session, _ = session.NewSession(spec)
	reader = observedSession(func(_ context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
		lookup.Digests[0] = spec.Lookup
		return *observed, nil
	})
	config.LookupKeys = []session.DigestKey{second}
	service, _ = session.NewSessionService(reader, config)
	if result, err := service.Get(context.Background(), request); err != nil || result.Authenticated {
		t.Fatal("reader changed retained input identity")
	}
}

func TestSessionGetResultCustodyRedactionAndConcurrency(t *testing.T) {
	service, request, clock, observed, config, _ := validationFixture(t)
	result, err := service.Get(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*session.GetResult){func(r *session.GetResult) { r.Authenticated = false }, func(r *session.GetResult) { r.Session = session.Session{} }, func(r *session.GetResult) { r.NeedsRefresh = !r.NeedsRefresh }, func(r *session.GetResult) { r.RefreshEligibleAt = r.RefreshEligibleAt.Add(time.Second) }} {
		copy := result
		mutate(&copy)
		if copy.ValidateAt(clock.now) == nil {
			t.Fatal("substituted public metadata retained admission")
		}
	}
	for _, value := range []any{request.Credential, request, result, *observed, config, service} {
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit session encoding permitted")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), "tenant-a") {
			t.Fatal("diagnostics disclosed scope")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := service.Get(context.Background(), request)
			if err != nil || !got.Authenticated || got.ValidateAt(clock.now) != nil {
				t.Error("concurrent admission failed")
			}
		}()
	}
	wg.Wait()
}

func TestStatefulSessionGetRequiresCurrentBoundAuthority(t *testing.T) {
	spec := sessionSpec(t)
	clock := &mutableIssueClock{now: spec.IssuedAt.Add(time.Second)}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	reader := observedSession(func(ctx context.Context, lookup session.SessionLookup) (session.SessionObservation, error) {
		if _, ok := ctx.Deadline(); !ok || lookup.TenantID != spec.TenantID || len(lookup.Digests) != 1 || lookup.Digests[0] != spec.Lookup {
			t.Fatal("unbounded or substituted lookup")
		}
		return session.SessionObservation{Session: record, Current: spec.Authority, Active: true, ReadStartedAt: clock.now, ValidUntil: clock.now.Add(20 * time.Second)}, nil
	})
	service, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(context.Background(), session.GetRequest{TenantID: identity.TenantID(spec.TenantID), Credential: credential})
	if err != nil || !result.Authenticated || result.Session != record || result.ValidateAt(clock.now) != nil {
		t.Fatal("current session denied", err)
	}
	if result.ValidUntil().After(clock.now.Add(20*time.Second - time.Millisecond)) {
		t.Fatal("source validity extended")
	}
}
