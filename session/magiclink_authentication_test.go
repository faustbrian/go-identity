package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func magicLinkSession(t testing.TB) (session.SessionSpec, session.MagicLinkAuthenticationSpec) {
	t.Helper()
	s, otp := otpSession(t)
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}
	return s, session.MagicLinkAuthenticationSpec{CommandID: otp.CommandID, RequestCommandID: otp.SendCommandID, CapabilityID: "original-grant", IdentifierID: otp.IdentifierID, IdentifierVersion: otp.IdentifierVersion, VerificationVersion: otp.VerificationVersion, AuthenticatedAt: otp.AuthenticatedAt, ValidUntil: otp.ValidUntil}
}

func TestMagicLinkSessionRetainsHistoricalPossessionWithoutInventingCredential(t *testing.T) {
	s, p := magicLinkSession(t)
	m, err := session.NewMagicLinkAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := session.NewSessionWithMagicLink(s, m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.MagicLinkAuthentication().Bindings()
	if err != nil || got != p {
		t.Fatal("lost original grant", err)
	}
	if _, err := session.NewSession(s); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("base metadata manufactured authentication")
	}
	if _, err := session.NewSessionWithOTP(s, session.OTPAuthentication{}); err == nil {
		t.Fatal("magic link entered OTP profile")
	}
	if _, err := r.Lifetime(p.ValidUntil.Add(time.Second)); err != nil {
		t.Fatal("historical grant expiry expired session", err)
	}
	command, err := session.NewUpdateCommand(updateBinding(s), r, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := command.Update()
	got, _ = u.Successor.MagicLinkAuthentication().Bindings()
	if got != p {
		t.Fatal("update lost historical grant")
	}
	for _, v := range []any{m, r} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit serialization")
		}
		if strings.Contains(fmt.Sprintf("%+v", v), p.CapabilityID) {
			t.Fatal("diagnostic disclosure")
		}
	}
	// Legacy opaque-proof issuance cannot accept projection-only possession.
	s.Version = 1
	a, _ := s.Authority.Bindings()
	a.Session.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	r, _ = session.NewSessionWithMagicLink(s, m)
	if _, err := session.NewIssueCommand(issueBinding(s), r); err == nil {
		t.Fatal("metadata entered proof-issued session")
	}
}

func TestMagicLinkRotationCannotSubstituteOriginalGrant(t *testing.T) {
	s, p := magicLinkSession(t)
	m, _ := session.NewMagicLinkAuthentication(p)
	source, err := session.NewSessionWithMagicLink(s, m)
	if err != nil {
		t.Fatal(err)
	}
	next := s
	next.Version++
	next.Lookup.Sum[0]++
	policy, _ := s.Remember.Bindings()
	next.LastActivityAt = next.LastActivityAt.Add(policy.RefreshAfter)
	a, _ := s.Authority.Bindings()
	a.Session.Version++
	next.Authority, _ = session.NewAuthoritySnapshot(a)
	successor, err := session.NewSessionWithMagicLink(next, m)
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(s)
	op := session.RotateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	if _, err := session.NewRotateCommand(b, source, successor); err != nil {
		t.Fatal("valid rotation lost provenance", err)
	}
	p.CapabilityID = "substituted-grant"
	other, _ := session.NewMagicLinkAuthentication(p)
	changed, _ := session.NewSessionWithMagicLink(next, other)
	if _, err := session.NewRotateCommand(b, source, changed); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("rotation substituted authenticating grant")
	}
}

func TestMagicLinkAuthenticationRejectsMalformedAndMixedProvenance(t *testing.T) {
	for _, change := range []func(*session.MagicLinkAuthenticationSpec){
		func(p *session.MagicLinkAuthenticationSpec) { p.CommandID = "bad" },
		func(p *session.MagicLinkAuthenticationSpec) { p.RequestCommandID = "bad" },
		func(p *session.MagicLinkAuthenticationSpec) { p.RequestCommandID = p.CommandID },
		func(p *session.MagicLinkAuthenticationSpec) { p.CapabilityID = "" },
		func(p *session.MagicLinkAuthenticationSpec) { p.CapabilityID = strings.Repeat("x", 129) },
		func(p *session.MagicLinkAuthenticationSpec) { p.CapabilityID = "bad\n" },
		func(p *session.MagicLinkAuthenticationSpec) { p.IdentifierID = "bad\n" },
		func(p *session.MagicLinkAuthenticationSpec) { p.IdentifierVersion = 0 },
		func(p *session.MagicLinkAuthenticationSpec) { p.VerificationVersion = 0 },
		func(p *session.MagicLinkAuthenticationSpec) { p.AuthenticatedAt = time.Time{} },
		func(p *session.MagicLinkAuthenticationSpec) { p.ValidUntil = p.AuthenticatedAt },
	} {
		_, p := magicLinkSession(t)
		change(&p)
		if got, err := session.NewMagicLinkAuthentication(p); !errors.Is(err, session.ErrInvalidSession) || got != (session.MagicLinkAuthentication{}) {
			t.Fatal("malformed provenance accepted")
		}
	}
	s, p := magicLinkSession(t)
	m, _ := session.NewMagicLinkAuthentication(p)
	for _, change := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Kind = session.AuthenticationOTP },
		func(s *session.SessionSpec) { s.Authentication.CredentialID = "invented-password" },
		func(s *session.SessionSpec) { s.Authentication.ProofVersion = 1 },
		func(s *session.SessionSpec) { s.IssuedAt = p.AuthenticatedAt.Add(-time.Second) },
		func(s *session.SessionSpec) { s.IssuedAt = p.ValidUntil; s.LastActivityAt = s.IssuedAt },
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		bad := s
		change(&bad)
		if r, err := session.NewSessionWithMagicLink(bad, m); !errors.Is(err, session.ErrInvalidSession) || r != (session.Session{}) {
			t.Fatal("mixed provenance accepted")
		}
	}
	if _, err := (session.MagicLinkAuthentication{}).Bindings(); err == nil {
		t.Fatal("zero provenance accepted")
	}
	if _, err := session.NewSessionWithMagicLink(s, session.MagicLinkAuthentication{}); err == nil {
		t.Fatal("missing provenance accepted")
	}
}

func TestMagicLinkPrimaryAndEncryptedCacheRetainOriginalExpiry(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		t.Run(fmt.Sprint(csrf), func(t *testing.T) {
			service, request, clock, observed, validation, _ := validationFixture(t)
			s, p := magicLinkSession(t)
			base, _ := observed.Session.Bindings()
			s.Lookup = base.Lookup
			m, _ := session.NewMagicLinkAuthentication(p)
			var err error
			observed.Session, err = session.NewSessionWithMagicLink(s, m)
			if csrf {
				state, _ := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 1, Digest: [32]byte{7}})
				observed.Session, err = session.NewSessionWithMagicLinkAndCSRF(s, m, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.Get(context.Background(), request)
			if err != nil || !original.Authenticated {
				t.Fatal("primary denied magic-link session", err)
			}
			keys, _ := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
			crypto, _ := envelope.NewService(keys)
			profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
			codec, _ := session.NewEncryptedCacheCodec(service, crypto, profile)
			blob, err := codec.Seal(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			restarted, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
				return session.SessionObservation{}, session.ErrUnavailable
			}), validation)
			cache, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
			// Real authenticated envelopes must still reject malformed method
			// projections, rather than relying on AEAD corruption as the oracle.
			aad, _ := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": "1", "audience": validation.Audience, "tenant": string(s.TenantID), "clock-uncertainty": strconv.FormatInt(int64(validation.ClockUncertainty), 10)})
			parsed, _ := envelope.ParseEnvelope(blob)
			plain, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: parsed, Context: aad})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			schema := []byte(`"Schema":7`)
			if csrf {
				schema = []byte(`"Schema":8`)
			}
			for _, bad := range [][]byte{
				bytes.Replace(plain, schema, []byte(`"Schema":1`), 1),
				bytes.Replace(plain, []byte(`"Kind":4`), []byte(`"Kind":3`), 1),
				bytes.Replace(plain, []byte(`"MagicLink":{`), []byte(`"MagicLink":null,"MagicLink":{`), 1),
				bytes.Replace(plain, []byte(`"IdentifierVersion":3`), []byte(`"IdentifierVersion":0`), 1),
			} {
				if bytes.Equal(bad, plain) {
					t.Fatal("mutation did not change fixture")
				}
				enc, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
				if err != nil {
					t.Fatal(err)
				}
				wire, _ := enc.MarshalBinary()
				if got, err := cache.Get(context.Background(), request, wire); got.Authenticated || err != session.ErrUnavailable {
					t.Fatal("malformed magic-link cache accepted", err)
				}
			}
			clock.now = original.ValidUntil().Add(-time.Nanosecond)
			warm, err := cache.Get(context.Background(), request, blob)
			got, _ := warm.Session.MagicLinkAuthentication().Bindings()
			before, _ := original.Session.CSRFState().Bindings()
			after, _ := warm.Session.CSRFState().Bindings()
			if err != nil || !warm.Authenticated || got != p || before != after || !warm.ValidUntil().Equal(original.ValidUntil()) {
				t.Fatal("restart lost provenance or renewed validity", err)
			}
			promoted, err := cache.Seal(context.Background(), warm)
			if err != nil {
				t.Fatal(err)
			}
			clock.now = original.ValidUntil()
			if got, err := cache.Get(context.Background(), request, promoted); got.Authenticated || err != session.ErrUnavailable {
				t.Fatal("stale cache survived outage", err)
			}
		})
	}
}

func TestMethodSessionServiceRejectsForeignWarmCache(t *testing.T) {
	_, request, _, observed, config, reader := validationFixture(t)
	s, p := magicLinkSession(t)
	base, _ := observed.Session.Bindings()
	s.Lookup = base.Lookup
	m, _ := session.NewMagicLinkAuthentication(p)
	observed.Session, _ = session.NewSessionWithMagicLink(s, m)
	issuer, err := session.NewMethodSessionService(reader, config, session.AuthenticationMagicLink)
	if err != nil {
		t.Fatal(err)
	}
	result, err := issuer.Get(context.Background(), request)
	if err != nil || !result.Authenticated {
		t.Fatal("original admission", err)
	}
	keys, _ := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
	crypto, _ := envelope.NewService(keys)
	profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
	codec, _ := session.NewEncryptedCacheCodec(issuer, crypto, profile)
	blob, err := codec.Seal(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []session.AuthenticationKind{session.AuthenticationVerified, session.AuthenticationOTP, session.AuthenticationMagicLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			reads := 0
			restarted, err := session.NewMethodSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
				reads++
				return session.SessionObservation{}, session.ErrUnavailable
			}), config, kind)
			if err != nil {
				t.Fatal(err)
			}
			cache, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
			got, err := cache.Get(context.Background(), request, blob)
			if kind == session.AuthenticationMagicLink {
				if err != nil || !got.Authenticated || reads != 0 || !got.ValidUntil().Equal(result.ValidUntil()) {
					t.Fatal("same-profile restart", err)
				}
			} else if got.Authenticated || !errors.Is(err, session.ErrUnavailable) || reads != 1 {
				t.Fatal("foreign method cache admitted without authoritative refresh", err)
			}
		})
	}
	for _, kind := range []session.AuthenticationKind{0, session.AuthenticationAnonymous, 255} {
		if got, err := session.NewMethodSessionService(reader, config, kind); got != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid method", err)
		}
	}
	closed, _ := session.NewMethodSessionService(reader, config, session.AuthenticationOTP)
	if got, err := closed.Get(context.Background(), request); got.Authenticated || err != nil {
		t.Fatal("primary crossed method boundary", err)
	}
	for _, id := range []string{"", "bad\n", strings.Repeat("x", 257)} {
		if got, err := session.NewProfileSessionService(reader, config, session.AuthenticationMagicLink, id); got != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid cache profile", err)
		}
	}
	if got, err := session.NewProfileSessionService(nil, config, session.AuthenticationMagicLink, "native-profile"); got != nil || !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("invalid reader", err)
	}
	profileOwner, err := session.NewProfileSessionService(reader, config, session.AuthenticationMagicLink, "native-profile")
	if err != nil {
		t.Fatal(err)
	}
	profileResult, err := profileOwner.Get(context.Background(), request)
	if err != nil || !profileResult.Authenticated {
		t.Fatal(err)
	}
	profileCodec, _ := session.NewEncryptedCacheCodec(profileOwner, crypto, profile)
	boundBlob, err := profileCodec.Seal(context.Background(), profileResult)
	if err != nil {
		t.Fatal(err)
	}
	for _, targetProfile := range []string{"native-profile", "other-native-profile"} {
		target, _ := session.NewProfileSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
			return session.SessionObservation{}, session.ErrUnavailable
		}), config, session.AuthenticationMagicLink, targetProfile)
		cache, _ := session.NewEncryptedCacheCodec(target, crypto, profile)
		got, err := cache.Get(context.Background(), request, boundBlob)
		if targetProfile == "native-profile" {
			if err != nil || !got.Authenticated || !got.ValidUntil().Equal(profileResult.ValidUntil()) {
				t.Fatal("same authority profile", err)
			}
		} else if got.Authenticated || !errors.Is(err, session.ErrUnavailable) {
			t.Fatal("different authority profile", err)
		}
		if got, err := cache.Get(context.Background(), request, blob); got.Authenticated || !errors.Is(err, session.ErrUnavailable) {
			t.Fatal("unbound method cache entered bound profile", err)
		}
	}
}

func FuzzMagicLinkAuthenticationBounds(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "original-grant", "address")
	f.Add("bad", "\x00", "")
	f.Fuzz(func(t *testing.T, command, grant, identifier string) {
		_, p := magicLinkSession(t)
		p.CommandID, p.CapabilityID, p.IdentifierID = identity.CommandID(command), grant, identity.IdentifierID(identifier)
		v, err := session.NewMagicLinkAuthentication(p)
		if err != nil {
			if !errors.Is(err, session.ErrInvalidSession) || v != (session.MagicLinkAuthentication{}) {
				t.Fatal("invalid error/value")
			}
			return
		}
		got, err := v.Bindings()
		if err != nil || got != p {
			t.Fatal("valid bounded projection changed", err)
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit disclosure")
		}
	})
}
