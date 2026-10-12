package session_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

func mfaMagicLinkSession(t testing.TB) (session.SessionSpec, session.MagicLinkAuthentication, session.MFAAuthenticationSpec) {
	t.Helper()
	s, p := magicLinkSession(t)
	p.AuthenticatedAt = s.IssuedAt.Add(-4 * time.Minute)
	p.ValidUntil = s.IssuedAt.Add(time.Minute)
	primary, err := session.NewMagicLinkAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Authority.Bindings()
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor/user", Version: 7}}
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	remember, _ := s.Remember.Bindings()
	return s, primary, session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: p.CommandID, ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: s.IssuedAt, ValidUntil: p.ValidUntil}
}

func TestMFASessionPreservesOriginalPrimaryAndFreshness(t *testing.T) {
	s, primary, p := mfaMagicLinkSession(t)
	metadata, err := session.NewMFAAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := session.NewSessionWithMagicLinkMFA(s, primary, metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.MFAAuthentication().Bindings()
	if err != nil || got != p {
		t.Fatal("factor provenance lost", err)
	}
	if r.MagicLinkAuthentication() != primary {
		t.Fatal("factor replaced original primary")
	}
	policy, _ := s.Remember.Bindings()
	original, _ := primary.Bindings()
	life, err := r.Lifetime(original.AuthenticatedAt.Add(policy.FreshFor))
	if err != nil || life.Fresh {
		t.Fatal("factor completion renewed primary freshness", err)
	}
	u, err := session.NewUpdateCommand(updateBinding(s), r, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	updated, _ := u.Update()
	retained, err := updated.Successor.MFAAuthentication().Bindings()
	if err != nil || retained != p {
		t.Fatal("metadata update lost MFA", err)
	}
	if _, err := session.NewSessionWithMagicLink(s, primary); err == nil {
		t.Fatal("lossy factor reconstruction accepted")
	}
	a, _ := s.Authority.Bindings()
	a.Factor.Binding.Version++
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	if _, err := session.NewSessionWithMagicLinkMFA(s, primary, metadata); err == nil {
		t.Fatal("stale factor provenance accepted")
	}
	s, primary, p = mfaMagicLinkSession(t)
	metadata, _ = session.NewMFAAuthentication(p)
	changedPolicy := p.Remember
	changedPolicy.Choice = session.PersistentSession
	s.Remember, err = session.NewRememberPolicy(changedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewSessionWithMagicLinkMFA(s, primary, metadata); err == nil {
		t.Fatal("MFA upgraded original remember policy")
	}
}

func TestMFASessionRejectsForeignPrimaryAndMalformedProvenance(t *testing.T) {
	for _, change := range []func(*session.MFAAuthenticationSpec){
		func(p *session.MFAAuthenticationSpec) { p.CommandID = "bad" },
		func(p *session.MFAAuthenticationSpec) { p.CommandID = p.PrimaryCommandID },
		func(p *session.MFAAuthenticationSpec) { p.ContinuationID = "bad" },
		func(p *session.MFAAuthenticationSpec) { p.ContinuationScopeDigest = [32]byte{} },
		func(p *session.MFAAuthenticationSpec) { p.Method = "passkey" },
		func(p *session.MFAAuthenticationSpec) { p.FactorID = "bad" },
		func(p *session.MFAAuthenticationSpec) { p.EnrollmentVersion = 0 },
		func(p *session.MFAAuthenticationSpec) { p.FactorAuthorityVersion = 0 },
		func(p *session.MFAAuthenticationSpec) { p.ContinuationVersion = 0 },
		func(p *session.MFAAuthenticationSpec) { p.Remember = session.RememberPolicySpec{} },
		func(p *session.MFAAuthenticationSpec) { p.ValidUntil = p.VerifiedAt },
	} {
		_, _, p := mfaMagicLinkSession(t)
		change(&p)
		if _, err := session.NewMFAAuthentication(p); err == nil {
			t.Fatal("malformed factor metadata accepted")
		}
	}
	s, primary, p := mfaMagicLinkSession(t)
	p.PrimaryCommandID = identity.CommandID("BwcHBwcHBwcHBwcHBwcHBw")
	metadata, err := session.NewMFAAuthentication(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NewSessionWithMagicLinkMFA(s, primary, metadata); err == nil {
		t.Fatal("foreign primary authenticated factor session")
	}
}

func TestMFASessionRotationRejectsChangedFactorProvenance(t *testing.T) {
	s, primary, p := mfaMagicLinkSession(t)
	m, _ := session.NewMFAAuthentication(p)
	source, err := session.NewSessionWithMagicLinkMFA(s, primary, m)
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
	successor, err := session.NewSessionWithMagicLinkMFA(next, primary, m)
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(s)
	op := session.RotateOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	if _, err := session.NewRotateCommand(b, source, successor); err != nil {
		t.Fatal("rotation lost original factor metadata", err)
	}
	p.EnrollmentVersion++
	changed, _ := session.NewMFAAuthentication(p)
	substituted, _ := session.NewSessionWithMagicLinkMFA(next, primary, changed)
	if _, err := session.NewRotateCommand(b, source, substituted); err == nil {
		t.Fatal("rotation substituted factor enrollment")
	}
}

func TestMFASessionEncryptedRestartRetainsCompleteProvenanceAndDeadline(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		t.Run(fmt.Sprint(csrf), func(t *testing.T) {
			service, request, clock, observed, config, _ := validationFixture(t)
			s, primary, p := mfaMagicLinkSession(t)
			base, _ := observed.Session.Bindings()
			s.Lookup = base.Lookup
			m, _ := session.NewMFAAuthentication(p)
			var err error
			observed.Session, err = session.NewSessionWithMagicLinkMFA(s, primary, m)
			observed.Current = s.Authority
			if csrf {
				state, _ := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 1, Digest: [32]byte{7}})
				observed.Session, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, m, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := service.Get(context.Background(), request)
			if err != nil || !original.Authenticated {
				t.Fatal("current primary observation denied", err)
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
			}), config)
			cache, _ := session.NewEncryptedCacheCodec(restarted, crypto, profile)
			clock.now = original.ValidUntil().Add(-time.Nanosecond)
			warm, err := cache.Get(context.Background(), request, blob)
			got, _ := warm.Session.MFAAuthentication().Bindings()
			if err != nil || !warm.Authenticated || got != p || !warm.ValidUntil().Equal(original.ValidUntil()) {
				t.Fatal("restart lost factor or renewed validity", err)
			}
			before, _ := original.Session.CSRFState().Bindings()
			after, _ := warm.Session.CSRFState().Bindings()
			if before != after || warm.Session.MagicLinkAuthentication() == (session.MagicLinkAuthentication{}) {
				t.Fatal("restart dropped primary or synchronizer")
			}
			promoted, err := cache.Seal(context.Background(), warm)
			if err != nil {
				t.Fatal(err)
			}
			// Valid authenticated ciphertext with missing factor metadata must
			// fail closed, not degrade this full session to single-factor.
			aad, _ := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": "1", "audience": config.Audience, "tenant": string(s.TenantID), "clock-uncertainty": fmt.Sprint(int64(config.ClockUncertainty))})
			sealed, _ := envelope.ParseEnvelope(blob)
			plain, err := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: sealed, Context: aad})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			bad := bytes.Replace(plain, []byte(`"MFA":{`), []byte(`"MFA":null,"MFA":{`), 1)
			if bytes.Equal(bad, plain) {
				t.Fatal("cache omitted factor projection")
			}
			tampered, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
			clear(bad)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := tampered.MarshalBinary()
			if got, err := cache.Get(context.Background(), request, wire); got.Authenticated || err != session.ErrUnavailable {
				t.Fatal("ambiguous factor projection admitted", err)
			}
			clock.now = original.ValidUntil()
			if got, err := cache.Get(context.Background(), request, promoted); got.Authenticated || err != session.ErrUnavailable {
				t.Fatal("promoted factor cache survived authoritative expiry", err)
			}
		})
	}
}
