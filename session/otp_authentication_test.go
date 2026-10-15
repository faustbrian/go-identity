package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func otpSession(t testing.TB) (session.SessionSpec, session.OTPAuthenticationSpec) {
	t.Helper()
	s := sessionSpec(t)
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationOTP}
	p := session.OTPAuthenticationSpec{
		CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", SendCommandID: "AgICAgICAgICAgICAgICAg",
		ChallengeID: "challenge", AttemptID: "AwMDAwMDAwMDAwMDAwMDAw",
		IdentifierID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", IdentifierKind: identity.IdentifierEmail,
		IdentifierVersion: 3, VerificationVersion: 4,
		AuthenticatedAt: s.IssuedAt.Add(-time.Second), ValidUntil: s.IssuedAt.Add(time.Minute),
	}
	return s, p
}

func TestOTPPrimaryAdmissionAndEncryptedRestartPreserveMetadata(t *testing.T) {
	for _, withCSRF := range []bool{false, true} {
		t.Run(fmt.Sprint(withCSRF), func(t *testing.T) {
			service, request, clock, observed, validation, _ := validationFixture(t)
			s, p := otpSession(t)
			base, _ := observed.Session.Bindings()
			s.Lookup = base.Lookup
			metadata, _ := session.NewOTPAuthentication(p)
			var err error
			observed.Session, err = session.NewSessionWithOTP(s, metadata)
			if withCSRF {
				key, _ := session.NewCSRFKey(1, []byte(strings.Repeat("k", 32)))
				token, _ := session.NewCSRFToken()
				state, _ := token.Digest(key, session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version})
				observed.Session, err = session.NewSessionWithOTPAndCSRF(s, metadata, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.Get(context.Background(), request)
			if err != nil || !original.Authenticated {
				t.Fatal("owned reader OTP result rejected", err)
			}
			command, err := session.NewRevokeOtherCommand(setBinding(s, false), original.Session, 100)
			if err != nil {
				t.Fatal(err)
			}
			if prepared, err := service.PrepareRevokeSet(original, command); err != nil || prepared.Validate(service, clock.now) != nil {
				t.Fatal("OTP revoke-set freshness lost", err)
			}
			keys, _ := keyring.New(map[string][]byte{"cache-v1": make([]byte, 32)})
			crypto, _ := envelope.NewService(keys)
			profile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: time.Minute, MaximumBytes: 32768}
			codec, _ := session.NewEncryptedCacheCodec(service, crypto, profile)
			blob, err := codec.Seal(context.Background(), original)
			if err != nil {
				t.Fatal(err)
			}
			restarted, _ := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
				return session.SessionObservation{}, session.ErrUnavailable
			}), validation)
			cache, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
			// Authenticate malformed inner frames with the real envelope owner;
			// failure must come from projection validation, not corrupted AEAD.
			aad, _ := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": "1", "audience": validation.Audience, "tenant": string(s.TenantID), "clock-uncertainty": strconv.FormatInt(int64(validation.ClockUncertainty), 10)})
			parsed, _ := envelope.ParseEnvelope(blob)
			plain, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: parsed, Context: aad})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			schema := []byte(`"Schema":3`)
			if withCSRF {
				schema = []byte(`"Schema":4`)
			}
			for _, bad := range [][]byte{
				bytes.Replace(plain, schema, []byte(`"Schema":1`), 1),
				bytes.Replace(plain, []byte(`"Kind":3`), []byte(`"Kind":1`), 1),
				bytes.Replace(plain, []byte(`"IdentifierVersion":3`), []byte(`"IdentifierVersion":0`), 1),
				bytes.Replace(plain, []byte(`"IdentifierKind":"email"`), []byte(`"IdentifierKind":"username"`), 1),
				bytes.Replace(plain, []byte(`"OTP":{`), []byte(`"OTP":null,"OTP":{`), 1),
			} {
				if bytes.Equal(bad, plain) {
					t.Fatal("malformed frame did not change fixture")
				}
				enc, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
				if err != nil {
					t.Fatal(err)
				}
				wire, _ := enc.MarshalBinary()
				if got, err := cache.Get(context.Background(), request, wire); got.Authenticated || err != session.ErrUnavailable {
					t.Fatal("malformed authenticated OTP frame accepted", err)
				}
			}
			clock.now = original.ValidUntil().Add(-time.Nanosecond)
			warm, err := cache.Get(context.Background(), request, blob)
			got, _ := warm.Session.OTPAuthentication().Bindings()
			beforeCSRF, _ := original.Session.CSRFState().Bindings()
			afterCSRF, _ := warm.Session.CSRFState().Bindings()
			if err != nil || !warm.Authenticated || got != p || beforeCSRF != afterCSRF || !warm.ValidUntil().Equal(original.ValidUntil()) {
				t.Fatal("OTP/cache projection lost or renewed", err)
			}
			promoted, err := cache.Seal(context.Background(), warm)
			if err != nil {
				t.Fatal(err)
			}
			clock.now = original.ValidUntil()
			if got, err := cache.Get(context.Background(), request, promoted); got.Authenticated || err != session.ErrUnavailable {
				t.Fatal("expired cache survived outage", err)
			}
		})
	}
}

func TestOTPUpdateAndRotationPreserveOriginalAuthentication(t *testing.T) {
	s, p := otpSession(t)
	metadata, _ := session.NewOTPAuthentication(p)
	source, err := session.NewSessionWithOTP(s, metadata)
	if err != nil {
		t.Fatal(err)
	}
	command, err := session.NewUpdateCommand(updateBinding(s), source, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := command.Update()
	got, _ := u.Successor.OTPAuthentication().Bindings()
	if got != p {
		t.Fatal("update discarded provenance")
	}
	policy, _ := s.Remember.Bindings()
	next := s
	next.Version++
	next.Lookup.Sum[0]++
	next.LastActivityAt = next.LastActivityAt.Add(policy.RefreshAfter)
	vector, _ := s.Authority.Bindings()
	vector.Session.Version++
	next.Authority, _ = session.NewAuthoritySnapshot(vector)
	successor, err := session.NewSessionWithOTP(next, metadata)
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(s)
	op := session.RotateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	rotation, err := session.NewRotateCommand(b, source, successor)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := rotation.Rotation()
	got, _ = r.Successor.OTPAuthentication().Bindings()
	if got != p {
		t.Fatal("rotation renewed provenance")
	}
	p.AttemptID = "BAQEBAQEBAQEBAQEBAQEBA"
	other, err := session.NewOTPAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := session.NewSessionWithOTP(next, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewRotateCommand(b, source, changed); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("rotation substituted authenticating attempt")
	}
}

func TestOTPAuthenticationIsHistoricalDisjointSessionMetadata(t *testing.T) {
	s, p := otpSession(t)
	metadata, err := session.NewOTPAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := session.NewSessionWithOTP(s, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.OTPAuthentication().Bindings(); err != nil || got != p {
		t.Fatal("lost original OTP metadata")
	}
	if _, err := session.NewSession(s); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("base alone reconstructed OTP authentication")
	}
	if _, err := r.Lifetime(p.ValidUntil.Add(time.Second)); err != nil {
		t.Fatal("historical challenge expiry expired session", err)
	}
	if _, err := r.Lifetime(p.AuthenticatedAt.Add(-time.Second)); err == nil {
		t.Fatal("future authentication accepted")
	}
	p.IdentifierVersion++
	got, _ := r.OTPAuthentication().Bindings()
	if got.IdentifierVersion != 3 {
		t.Fatal("caller mutation changed frozen metadata")
	}
	for _, value := range []any{metadata, r} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit metadata serialization")
		}
		if text := fmt.Sprintf("%+v", value); strings.Contains(text, "challenge") || strings.Contains(text, "01ARZ") {
			t.Fatal("metadata disclosure")
		}
	}
	if _, err := (session.OTPAuthentication{}).Bindings(); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("zero projection accepted")
	}
}

func TestOTPAuthenticationRejectsMalformedAndMixedProvenance(t *testing.T) {
	for _, mutate := range []func(*session.OTPAuthenticationSpec){
		func(p *session.OTPAuthenticationSpec) { p.CommandID = "bad" },
		func(p *session.OTPAuthenticationSpec) { p.SendCommandID = "bad" },
		func(p *session.OTPAuthenticationSpec) { p.CommandID = p.SendCommandID },
		func(p *session.OTPAuthenticationSpec) { p.AttemptID = "bad" },
		func(p *session.OTPAuthenticationSpec) { p.AttemptID = "AAAAAAAAAAAAAAAAAAAAAA" },
		func(p *session.OTPAuthenticationSpec) { p.ChallengeID = "" },
		func(p *session.OTPAuthenticationSpec) { p.ChallengeID = strings.Repeat("x", 257) },
		func(p *session.OTPAuthenticationSpec) { p.ChallengeID = "bad\n" },
		func(p *session.OTPAuthenticationSpec) { p.ChallengeID = string([]byte{255}) },
		func(p *session.OTPAuthenticationSpec) { p.IdentifierID = "" },
		func(p *session.OTPAuthenticationSpec) { p.IdentifierKind = identity.IdentifierUsername },
		func(p *session.OTPAuthenticationSpec) { p.IdentifierVersion = 0 },
		func(p *session.OTPAuthenticationSpec) { p.VerificationVersion = 0 },
		func(p *session.OTPAuthenticationSpec) { p.AuthenticatedAt = time.Time{} },
		func(p *session.OTPAuthenticationSpec) { p.ValidUntil = p.AuthenticatedAt },
		func(p *session.OTPAuthenticationSpec) { p.ValidUntil = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		_, p := otpSession(t)
		mutate(&p)
		if m, err := session.NewOTPAuthentication(p); !errors.Is(err, session.ErrInvalidSession) || m != (session.OTPAuthentication{}) {
			t.Fatal("invalid OTP metadata accepted")
		}
	}
	s, p := otpSession(t)
	metadata, _ := session.NewOTPAuthentication(p)
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication = sessionSpec(t).Authentication },
		func(s *session.SessionSpec) { s.Authentication.CredentialID = "invented-password" },
		func(s *session.SessionSpec) { s.Authentication.ProofVersion = 1 },
		func(s *session.SessionSpec) { s.Authentication.CredentialVersion = 1 },
		func(s *session.SessionSpec) { s.Authentication.AnonymousAt = s.IssuedAt },
		func(s *session.SessionSpec) { s.Authentication.Proof = sessionSpec(t).Authentication.Proof },
		func(s *session.SessionSpec) { s.IssuedAt = p.AuthenticatedAt.Add(-time.Second) },
		func(s *session.SessionSpec) { s.IssuedAt = p.ValidUntil; s.LastActivityAt = s.IssuedAt },
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.ActiveOrganizationID = "organization"
			a.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		bad := s
		mutate(&bad)
		if r, err := session.NewSessionWithOTP(bad, metadata); !errors.Is(err, session.ErrInvalidSession) || r != (session.Session{}) {
			t.Fatal("mixed OTP record accepted")
		}
	}
	if _, err := session.NewSessionWithOTP(s, session.OTPAuthentication{}); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("missing provenance")
	}
}

func TestOTPMetadataCannotEnterLegacyProofIssuance(t *testing.T) {
	if _, err := session.NewSessionWithOTP(sessionSpec(t), session.OTPAuthentication{}); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("explicit OTP reconstruction accepted legacy metadata")
	}
	s, p := otpSession(t)
	s.Version = 1
	a, _ := s.Authority.Bindings()
	a.Session.Version = 1
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	metadata, _ := session.NewOTPAuthentication(p)
	record, err := session.NewSessionWithOTP(s, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewIssueCommand(issueBinding(s), record); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("OTP metadata entered credential-proof issuance")
	}
}

func TestOTPRotatorReplacesCSRFWithoutRenewingAuthentication(t *testing.T) {
	service, input, clock, observed, validation, _ := validationFixture(t)
	s, p := otpSession(t)
	base, _ := observed.Session.Bindings()
	s.Lookup = base.Lookup
	metadata, _ := session.NewOTPAuthentication(p)
	key, _ := session.NewCSRFKey(1, []byte(strings.Repeat("k", 32)))
	token, _ := session.NewCSRFToken()
	oldState, _ := token.Digest(key, session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version})
	observed.Session, _ = session.NewSessionWithOTPAndCSRF(s, metadata, oldState)
	policy, _ := s.Remember.Bindings()
	clock.now = s.LastActivityAt.Add(policy.RefreshAfter)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, err := service.Get(context.Background(), input)
	if err != nil || !caller.Authenticated {
		t.Fatal(err)
	}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	executor := &rotationExecutor{}
	rotator, err := session.NewSessionRotatorWithCSRF(service, executor, session.RotationConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: validation.LookupKeys[0], TokenSize: 32, Cookie: cookie}, key)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := rotator.Prepare(caller, "BAQEBAQEBAQEBAQEBAQEBA", "rotation")
	if err != nil {
		t.Fatal(err)
	}
	// The command is structural intent; preparation cannot deliver either token.
	request, _ := prepared.Request()
	command, _ := request.Command()
	rotation, _ := command.Rotation()
	got, _ := rotation.Successor.OTPAuthentication().Bindings()
	next, _ := rotation.Successor.CSRFState().Bindings()
	old, _ := oldState.Bindings()
	if got != p || next.Digest == old.Digest || next.Binding.SessionVersion != s.Version+1 {
		t.Fatal("rotation lost OTP or reused CSRF")
	}
	update, err := session.NewUpdateCommand(updateBinding(s), caller.Session, "")
	if err != nil {
		t.Fatal(err)
	}
	changed, _ := update.Update()
	if changed.Successor.CSRFState() != (session.CSRFState{}) {
		t.Fatal("metadata update copied old-version CSRF")
	}
}

func FuzzOTPAuthenticationBounds(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "challenge", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "AwMDAwMDAwMDAwMDAwMDAw", "email")
	f.Add("bad", "\x00", "", "AAAAAAAAAAAAAAAAAAAAAA", "username")
	f.Fuzz(func(t *testing.T, command, challenge, identifier, attempt, kind string) {
		_, p := otpSession(t)
		p.CommandID, p.ChallengeID, p.IdentifierID, p.AttemptID, p.IdentifierKind = identity.CommandID(command), challenge, identity.IdentifierID(identifier), attempt, identity.IdentifierKind(kind)
		value, err := session.NewOTPAuthentication(p)
		if err != nil {
			if !errors.Is(err, session.ErrInvalidSession) || value != (session.OTPAuthentication{}) {
				t.Fatal("invalid error/value")
			}
			return
		}
		got, err := value.Bindings()
		if err != nil || got != p {
			t.Fatal("valid metadata changed")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit disclosure")
		}
	})
}
