package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestAnonymousSessionConfigurationIsObservableWithoutAuthorityLookup(t *testing.T) {
	_, _, _, _, config, _ := validationFixture(t)
	service, err := session.NewAnonymousSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		t.Fatal("configuration inspection performed an authority read")
		return session.SessionObservation{}, nil
	}), config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value *session.AnonymousSessionService
		want  bool
	}{{"nil", nil, false}, {"zero", &session.AnonymousSessionService{}, false}, {"constructed", service, true}} {
		t.Run(tc.name, func(t *testing.T) {
			configured, ok := any(tc.value).(interface{ Configured() bool })
			if !ok {
				t.Fatal("anonymous reader exposes no configuration contract to its transport consumer")
			}
			if configured.Configured() != tc.want {
				t.Fatal("configuration inspection accepted an uninitialized reader or rejected the constructed owner")
			}
		})
	}
}

func TestAnonymousSessionReadIsExplicitAndCannotBecomeVerifiedAdmission(t *testing.T) {
	legacy, request, clock, observed, config, reader := validationFixture(t)
	verified := observed.Session
	spec, err := verified.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	anonymous, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	observed.Session = anonymous
	selected, err := session.NewAnonymousSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := selected.Get(context.Background(), request)
	if err != nil || !got.Recognized || got.Session != anonymous || got.ValidateAt(clock.now) != nil {
		t.Fatal("explicit anonymous credential was not recognized", err)
	}
	bindings, err := got.Session.Bindings()
	if err != nil || bindings.Authentication != spec.Authentication || bindings.Remember != spec.Remember {
		t.Fatal("anonymous read invented verified provenance or changed original remember policy")
	}
	denied, err := legacy.Get(context.Background(), request)
	if err != nil || denied.Authenticated || denied.Session != (session.Session{}) {
		t.Fatal("legacy verified reader accepted anonymous credentials", err)
	}
	observed.Session = verified
	foreign, err := selected.Get(context.Background(), request)
	if err != nil || foreign.Recognized || foreign.Session != (session.Session{}) {
		t.Fatal("anonymous profile accepted a permanent credential", err)
	}
	if _, err := session.NewMethodSessionService(reader, config, session.AuthenticationAnonymous); err == nil {
		t.Fatal("verified result API acquired anonymous admission")
	}
	if _, err := session.NewSelectedProfileSessionService(reader, config, []session.AuthenticationKind{session.AuthenticationAnonymous}, "test"); err == nil {
		t.Fatal("mixed verified result API acquired anonymous admission")
	}
}

func TestAnonymousSessionReadRetainsOriginalValidityAndRejectsSubstitution(t *testing.T) {
	_, request, clock, observed, config, reader := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: spec.IssuedAt}
	anonymous, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	observed.Session = anonymous
	selected, err := session.NewAnonymousSessionService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	original, err := selected.Get(context.Background(), request)
	if err != nil || !original.Recognized {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(4 * time.Second)
	copied, err := selected.Get(context.Background(), request)
	if err != nil || !copied.Recognized || copied.ValidUntil() != original.ValidUntil() {
		t.Fatal("anonymous copies renewed authoritative evidence", err)
	}
	forged := session.AnonymousGetResult{Recognized: true, Session: anonymous}
	if forged.ValidateAt(clock.now) == nil {
		t.Fatal("public metadata forged anonymous admission")
	}
	changed := original
	changed.Recognized = false
	if changed.ValidateAt(clock.now) == nil {
		t.Fatal("substituted result retained custody")
	}
	clock.now = original.ValidUntil()
	if !errors.Is(original.ValidateAt(clock.now), session.ErrUnauthenticated) || !errors.Is(copied.ValidateAt(clock.now), session.ErrUnauthenticated) {
		t.Fatal("anonymous evidence survived its original exclusive deadline")
	}
	expired, err := selected.Get(context.Background(), request)
	if err != nil || expired.Recognized {
		t.Fatal("expired source remained recognized", err)
	}
}
