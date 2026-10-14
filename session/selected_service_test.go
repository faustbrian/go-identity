package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func TestSelectedSessionMethodsAdmitOnlyFrozenSelection(t *testing.T) {
	_, request, _, observed, config, reader := validationFixture(t)
	methods := []session.AuthenticationKind{session.AuthenticationVerified, session.AuthenticationMagicLink}
	owner, err := session.NewSelectedProfileSessionService(reader, config, methods, "native-single-factor")
	if err != nil {
		t.Fatal(err)
	}
	methods[1] = session.AuthenticationOTP
	if got, err := owner.Get(context.Background(), request); err != nil || !got.Authenticated {
		t.Fatal("selected password", err)
	}
	base, _ := observed.Session.Bindings()
	s, p := otpSession(t)
	s.Lookup = base.Lookup
	m, _ := session.NewOTPAuthentication(p)
	observed.Session, _ = session.NewSessionWithOTP(s, m)
	if got, err := owner.Get(context.Background(), request); err != nil || got.Authenticated {
		t.Fatal("unselected OTP admitted", err)
	}
	s, magic := magicLinkSession(t)
	s.Lookup = base.Lookup
	link, _ := session.NewMagicLinkAuthentication(magic)
	observed.Session, _ = session.NewSessionWithMagicLink(s, link)
	if got, err := owner.Get(context.Background(), request); err != nil || !got.Authenticated {
		t.Fatal("selected magic-link", err)
	}
	for _, selection := range [][]session.AuthenticationKind{nil, {}, {0}, {session.AuthenticationAnonymous}, {255}, {session.AuthenticationOTP, session.AuthenticationOTP}} {
		if owner, err := session.NewSelectedProfileSessionService(reader, config, selection, "native-single-factor"); owner != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid selection", err)
		}
	}
	if owner, err := session.NewSelectedProfileSessionService(reader, config, []session.AuthenticationKind{session.AuthenticationMagicLink}, ""); owner != nil || !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("missing profile", err)
	}
}

func TestSelectedSessionWarmCacheBindsSetAndOwnerProfile(t *testing.T) {
	_, request, _, observed, config, reader := validationFixture(t)
	s, p := magicLinkSession(t)
	base, _ := observed.Session.Bindings()
	s.Lookup = base.Lookup
	metadata, _ := session.NewMagicLinkAuthentication(p)
	observed.Session, _ = session.NewSessionWithMagicLink(s, metadata)
	methods := []session.AuthenticationKind{session.AuthenticationVerified, session.AuthenticationMagicLink}
	owner, err := session.NewSelectedProfileSessionService(reader, config, methods, "native-single-factor")
	if err != nil {
		t.Fatal(err)
	}
	original, err := owner.Get(context.Background(), request)
	if err != nil || !original.Authenticated {
		t.Fatal("primary", err)
	}
	keys, _ := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
	codec, _ := session.NewEncryptedCacheCodec(owner, crypto, profile)
	blob, err := codec.Seal(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		methods []session.AuthenticationKind
		profile string
		admit   bool
	}{
		{"same-set-other-order", []session.AuthenticationKind{session.AuthenticationMagicLink, session.AuthenticationVerified}, "native-single-factor", true},
		{"smaller-set-still-includes-magic", []session.AuthenticationKind{session.AuthenticationMagicLink}, "native-single-factor", false},
		{"larger-set", []session.AuthenticationKind{session.AuthenticationVerified, session.AuthenticationOTP, session.AuthenticationMagicLink}, "native-single-factor", false},
		{"unselected-magic", []session.AuthenticationKind{session.AuthenticationVerified, session.AuthenticationOTP}, "native-single-factor", false},
		{"other-authority-profile", methods, "other-native-profile", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			reads := 0
			target, err := session.NewSelectedProfileSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
				reads++
				return session.SessionObservation{}, session.ErrUnavailable
			}), config, test.methods, test.profile)
			if err != nil {
				t.Fatal(err)
			}
			cache, _ := session.NewEncryptedCacheCodec(target, crypto, profile)
			got, err := cache.Get(context.Background(), request, blob)
			if test.admit {
				if err != nil || !got.Authenticated || reads != 0 || !got.ValidUntil().Equal(original.ValidUntil()) {
					t.Fatal("same frozen profile lost original validity", err)
				}
			} else if got.Authenticated || !errors.Is(err, session.ErrUnavailable) || reads != 1 {
				t.Fatal("foreign selection bypassed primary refresh", err)
			}
		})
	}
}
