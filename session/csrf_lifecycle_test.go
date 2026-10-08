package session_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
)

func csrfRecord(t *testing.T, original session.Session, key session.CSRFKey) (session.Session, session.CSRFToken) {
	t.Helper()
	spec, _ := original.Bindings()
	token, _ := session.NewCSRFToken()
	state, e := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if e != nil {
		t.Fatal(e)
	}
	record, e := session.NewSessionWithCSRF(spec, state)
	if e != nil {
		t.Fatal(e)
	}
	return record, token
}

func TestCSRFRotationSourceInvalidationAndCustody(t *testing.T) {
	_, input, clock, observed, validation, backend := validationFixture(t)
	oldKey, _ := session.NewCSRFKey(2, []byte(strings.Repeat("o", 32)))
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("n", 32)))
	original, oldToken := csrfRecord(t, observed.Session, oldKey)
	observed.Session = original
	spec, _ := original.Bindings()
	clock.now = spec.LastActivityAt.Add(12 * time.Hour)
	observed.ReadStartedAt = clock.now
	observed.ValidUntil = clock.now.Add(20 * time.Second)
	lookup, _ := session.NewDigestKey(2, make([]byte, 32))
	validation.LookupKeys = append(validation.LookupKeys, lookup)
	reader, _ := session.NewSessionService(backend, validation)
	caller, e := reader.Get(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	config := session.RotationConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}
	ex := &rotationExecutor{execute: func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
		return committedRotation(r), nil
	}}
	legacy, _ := session.NewSessionRotator(reader, ex, config)
	if _, e = legacy.Prepare(caller, "AwMDAwMDAwMDAwMDAwMDAw", "downgrade"); !errors.Is(e, session.ErrInvalidInput) {
		t.Fatal("cookie CSRF silently downgraded")
	}
	rotator, _ := session.NewSessionRotatorWithCSRF(reader, ex, config, key)
	forged := caller
	forged.Session, _ = session.NewSession(spec)
	if _, e = rotator.Prepare(forged, "AwMDAwMDAwMDAwMDAwMDAw", "forged"); !errors.Is(e, session.ErrUnauthenticated) {
		t.Fatal("stripped caller state admitted")
	}
	p, e := rotator.Prepare(caller, "AwMDAwMDAwMDAwMDAwMDAw", "rotate")
	if e != nil {
		t.Fatal(e)
	}
	r, _ := p.Request()
	cmd, _ := r.Command()
	native, _ := cmd.Rotation()
	next, _ := native.Successor.Bindings()
	oldState := original.CSRFState()
	oldBound, _ := oldState.Bindings()
	copied := oldBound
	copied.Binding.SessionVersion = next.Version
	unchangedDigest, _ := session.NewCSRFState(copied)
	invalid, _ := session.NewSessionWithCSRF(next, unchangedDigest)
	if _, e = session.NewRotateCommand(native.Binding, original, invalid); !errors.Is(e, session.ErrInvalidSessionCommand) {
		t.Fatal("rotation retained old digest")
	}
	result, e := rotator.Rotate(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	newToken, e := p.CSRFToken()
	if e != nil {
		t.Fatal(e)
	}
	state := result.Session.CSRFState()
	bound, _ := state.Bindings()
	if state.Check(bound.Binding, oldToken, key) == nil || oldState.Check(oldBound.Binding, newToken, oldKey) == nil {
		t.Fatal("rotation reused credential")
	}
	if oldState.Check(oldBound.Binding, oldToken, oldKey) != nil {
		t.Fatal("preparation mutated original")
	}
}

func TestCSRFRotationWithholdsNonDeliveryOutcomes(t *testing.T) {
	for _, mode := range []string{"not-committed", "unknown", "conflict", "in-progress", "replay", "error", "cancel", "expired", "panic", "missing-state", "different-digest", "recover"} {
		t.Run(mode, func(t *testing.T) {
			_, _, ex, clock, reader, caller := rotationFixture(t)
			lookup, _ := session.NewDigestKey(2, make([]byte, 32))
			key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("c", 32)))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			rotator, _ := session.NewSessionRotatorWithCSRF(reader, ex, session.RotationConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, key)
			p, e := rotator.Prepare(caller, "BAQEBAQEBAQEBAQEBAQEBA", "non-delivery")
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ex.execute = func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
				result := committedRotation(r)
				switch mode {
				case "not-committed", "unknown", "conflict", "in-progress":
					outcomes := map[string]identity.CommitOutcome{"not-committed": identity.CommitOutcomeNotCommitted, "unknown": identity.CommitOutcomeUnknown, "conflict": identity.CommitOutcomeConflict, "in-progress": identity.CommitOutcomeInProgress}
					result.Receipt.Outcome = outcomes[mode]
					result.Receipt.AuditEventID = ""
					result.Receipt.Feature.BeforeVersion = 0
					result.Receipt.Feature.AfterVersion = 0
					result.Session = session.Session{}
					if mode == "in-progress" {
						result.Receipt.RetryAfter = time.Second
					}
				case "replay":
					result.Replayed = true
				case "error":
					return result, errors.New("private diagnostic")
				case "cancel":
					cancel()
				case "expired":
					clock.now = caller.ValidUntil()
				case "panic":
					panic("private diagnostic")
				case "missing-state":
					spec, _ := result.Session.Bindings()
					result.Session, _ = session.NewSession(spec)
				case "different-digest":
					spec, _ := result.Session.Bindings()
					s, _ := result.Session.CSRFState().Bindings()
					s.Digest[0] ^= 1
					state, _ := session.NewCSRFState(s)
					result.Session, _ = session.NewSessionWithCSRF(spec, state)
				}
				return result, nil
			}
			if mode == "recover" {
				r, _ := p.Request()
				_, _ = rotator.Recover(ctx, r)
			} else {
				_, _ = rotator.Rotate(ctx, p)
			}
			if _, e = p.CSRFToken(); !errors.Is(e, session.ErrInvalidCSRF) {
				t.Fatal("rotation disclosed non-deliverable CSRF")
			}
		})
	}
}

func TestCSRFEncryptedCacheRejectsAuthenticatedMalformedState(t *testing.T) {
	codec, request, _, observed, config, crypto, profile, _, _ := encryptedFixture(t)
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("c", 32)))
	record, token := csrfRecord(t, observed.Session, key)
	observed.Session = record
	result, e := codec.Get(context.Background(), request, nil)
	if e != nil {
		t.Fatal(e)
	}
	blob, e := codec.Seal(context.Background(), result)
	if e != nil {
		t.Fatal(e)
	}
	aad, _ := envelope.NewContext(map[string]string{"purpose": "golib.session.encrypted-cache.v1", "issuer": profile.Issuer, "environment": profile.Environment, "epoch": strconv.FormatUint(profile.DeploymentEpoch, 10), "audience": config.Audience, "tenant": string(request.TenantID), "clock-uncertainty": strconv.FormatInt(int64(config.ClockUncertainty), 10)})
	parsed, _ := envelope.ParseEnvelope(blob)
	plain, e := crypto.Decrypt(context.Background(), envelope.DecryptRequest{Envelope: parsed, Context: aad})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(plain)
	raw, _ := token.Reveal()
	if bytes.Contains(plain, []byte(raw)) {
		t.Fatal("raw CSRF persisted")
	}
	stateSpec, _ := record.CSRFState().Bindings()
	encoded, _ := json.Marshal(stateSpec)
	if !bytes.Contains(plain, encoded) {
		t.Fatal("not exercising actual state representation")
	}
	outage := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	})
	reader, _ := session.NewSessionService(outage, config)
	restored, _ := session.NewEncryptedCacheCodec(reader, crypto, profile)
	cases := [][]byte{bytes.Replace(plain, []byte(`"Schema":2`), []byte(`"Schema":1`), 1), bytes.Replace(plain, encoded, []byte(`null`), 1), bytes.Replace(plain, []byte(`,"CSRF":`+string(encoded)), nil, 1), bytes.Replace(plain, []byte(`"CSRF":`), []byte(`"CSRF":null,"CSRF":`), 1)}
	for _, change := range []func(*session.CSRFStateSpec){func(s *session.CSRFStateSpec) { s.Binding.TenantID = "other" }, func(s *session.CSRFStateSpec) { s.Binding.SessionID = "other" }, func(s *session.CSRFStateSpec) { s.Binding.SessionVersion++ }, func(s *session.CSRFStateSpec) { s.KeyVersion = 0 }, func(s *session.CSRFStateSpec) { s.Digest = [32]byte{} }} {
		bad := stateSpec
		change(&bad)
		wire, _ := json.Marshal(bad)
		cases = append(cases, bytes.Replace(plain, encoded, wire, 1))
	}
	// Canonical struct order is retained: semantically malformed full projections
	// reach native state validation, rather than merely failing JSON key ordering.
	for _, bad := range cases {
		if bytes.Equal(bad, plain) {
			t.Fatal("mutation did not reach state")
		}
		enc, e := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: bad, KeyReference: profile.KeyReference, Context: aad})
		if e != nil {
			t.Fatal(e)
		}
		wire, _ := enc.MarshalBinary()
		if got, e := restored.Get(context.Background(), request, wire); !errors.Is(e, session.ErrUnavailable) || got.Authenticated {
			t.Fatal("malformed state accepted", e)
		}
	}
}

func TestCSRFSessionReconstructionAndUpdate(t *testing.T) {
	spec := sessionSpec(t)
	legacy, e := session.NewSession(spec)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := session.NewCSRFKey(1, []byte(strings.Repeat("c", 32)))
	record, token := csrfRecord(t, legacy, key)
	state := record.CSRFState()
	bound, _ := state.Bindings()
	if state.Check(bound.Binding, token, key) != nil {
		t.Fatal("record lost state")
	}
	if _, e = legacy.CSRFState().Bindings(); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("legacy synthesized state")
	}
	for _, change := range []func(*session.CSRFStateSpec){func(s *session.CSRFStateSpec) { s.Binding.TenantID = "other" }, func(s *session.CSRFStateSpec) { s.Binding.SessionID = "other" }, func(s *session.CSRFStateSpec) { s.Binding.SessionVersion++ }} {
		b := bound
		change(&b)
		foreign, _ := session.NewCSRFState(b)
		if _, e = session.NewSessionWithCSRF(spec, foreign); !errors.Is(e, session.ErrInvalidSession) {
			t.Fatal("misbound state accepted")
		}
	}
	if _, e = session.NewSessionWithCSRF(spec, session.CSRFState{}); !errors.Is(e, session.ErrInvalidSession) {
		t.Fatal("explicit zero state accepted")
	}
	binding := updateBinding(spec)
	command, e := session.NewUpdateCommand(binding, record, "label")
	if e != nil {
		t.Fatal(e)
	}
	update, _ := command.Update()
	if _, e = update.Successor.CSRFState().Bindings(); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("metadata version retained stale state")
	}
	if record.CSRFState().Check(bound.Binding, token, key) != nil {
		t.Fatal("source mutated")
	}
}

func csrfIssuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, *issueExecutor, *mutableIssueClock, session.CSRFKey) {
	t.Helper()
	command, authority, proof, now := issueRequestFixture(t)
	issue, _ := command.Issue()
	spec, _ := issue.Session.Bindings()
	spec.Lookup = session.TokenDigest{}
	lookup, _ := session.NewDigestKey(1, make([]byte, 32))
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("c", 32)))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	clock := &mutableIssueClock{now: now}
	ex := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedIssue(r), nil
	}, recover: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedIssue(r), nil
	}}
	issuer, e := session.NewSessionIssuerWithCSRF(ex, session.IssuerConfig{Authority: authority, Clock: clock, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, key)
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := issuer.Prepare(issue.Binding, spec, proof)
	if e != nil {
		t.Fatal(e)
	}
	return issuer, prepared, ex, clock, key
}

func requireNoCSRFDelivery(t *testing.T, p session.PreparedIssuance) {
	t.Helper()
	if _, e := p.CSRFToken(); !errors.Is(e, session.ErrInvalidCSRF) {
		t.Fatal("CSRF delivery gate bypassed")
	}
}

func TestCSRFIssuanceOriginalCommitAndReconstruction(t *testing.T) {
	issuer, p, ex, _, key := csrfIssuerFixture(t)
	requireNoCSRFDelivery(t, p)
	ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		result := committedIssue(r)
		spec, _ := result.Session.Bindings()
		stateSpec, _ := result.Session.CSRFState().Bindings()
		state, _ := session.NewCSRFState(stateSpec)
		result.Session, _ = session.NewSessionWithCSRF(spec, state)
		return result, nil
	}
	result, e := issuer.Issue(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	csrf, e := p.CSRFToken()
	if e != nil {
		t.Fatal(e)
	}
	state := result.Session.CSRFState()
	bound, _ := state.Bindings()
	if state.Check(bound.Binding, csrf, key) != nil {
		t.Fatal("delivered token does not match frozen record")
	}
	raw, e := csrf.Reveal()
	if e != nil {
		t.Fatal(e)
	}
	copy, _ := p.CSRFToken()
	if _, e = copy.Reveal(); !errors.Is(e, session.ErrTokenAlreadyRevealed) {
		t.Fatal("copy delivered twice")
	}
	bearer, e := result.Token.Reveal()
	if e != nil || bearer == raw {
		t.Fatal("bearer and CSRF custody coupled")
	}
	if state.Check(bound.Binding, csrf, key) != nil {
		t.Fatal("reveal consumed validation")
	}
}

func TestCSRFIssuanceWithholdsEveryNonDeliveryOutcome(t *testing.T) {
	for _, mode := range []string{"not-committed", "unknown", "conflict", "in-progress", "replay", "error", "cancel", "expired", "panic", "missing-state", "different-digest", "recover"} {
		t.Run(mode, func(t *testing.T) {
			issuer, p, ex, clock, _ := csrfIssuerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ex.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				result := committedIssue(r)
				switch mode {
				case "not-committed", "unknown", "conflict", "in-progress":
					outcomes := map[string]identity.CommitOutcome{"not-committed": identity.CommitOutcomeNotCommitted, "unknown": identity.CommitOutcomeUnknown, "conflict": identity.CommitOutcomeConflict, "in-progress": identity.CommitOutcomeInProgress}
					result.Receipt.Outcome = outcomes[mode]
					result.Receipt.AuditEventID = ""
					result.Receipt.Feature.BeforeVersion = 0
					result.Receipt.Feature.AfterVersion = 0
					result.Session = session.Session{}
					if mode == "in-progress" {
						result.Receipt.RetryAfter = time.Second
					}
				case "replay":
					result.Replayed = true
				case "error":
					return result, errors.New("private diagnostic")
				case "cancel":
					cancel()
				case "expired":
					clock.now = clock.now.Add(30 * 24 * time.Hour)
				case "panic":
					panic("private diagnostic")
				case "missing-state":
					spec, _ := result.Session.Bindings()
					result.Session, _ = session.NewSession(spec)
				case "different-digest":
					spec, _ := result.Session.Bindings()
					s, _ := result.Session.CSRFState().Bindings()
					s.Digest[0] ^= 1
					state, _ := session.NewCSRFState(s)
					result.Session, _ = session.NewSessionWithCSRF(spec, state)
				}
				return result, nil
			}
			if mode == "recover" {
				r, _ := p.Request()
				_, _ = issuer.Recover(ctx, r)
			} else {
				_, _ = issuer.Issue(ctx, p)
			}
			requireNoCSRFDelivery(t, p)
		})
	}
}

func TestCSRFRotationReplacesStateAndPreservesBearerTransport(t *testing.T) {
	for _, transport := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		t.Run(string(rune('0'+transport)), func(t *testing.T) {
			_, _, ex, _, reader, caller := rotationTransportFixture(t, transport)
			lookup, _ := session.NewDigestKey(2, make([]byte, 32))
			key, _ := session.NewCSRFKey(4, []byte(strings.Repeat("c", 32)))
			cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
			rotator, e := session.NewSessionRotatorWithCSRF(reader, ex, session.RotationConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookie}, key)
			if e != nil {
				t.Fatal(e)
			}
			p, e := rotator.Prepare(caller, "AgICAgICAgICAgICAgICAg", "csrf-rotation")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = p.CSRFToken(); !errors.Is(e, session.ErrInvalidCSRF) {
				t.Fatal("precommit rotation disclosure")
			}
			result, e := rotator.Rotate(context.Background(), p)
			if e != nil {
				t.Fatal(e)
			}
			csrf, e := p.CSRFToken()
			if transport == session.CredentialBearer {
				if !errors.Is(e, session.ErrInvalidCSRF) || result.Cookie.Name != "" {
					t.Fatal("bearer emitted cookie/CSRF")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			state := result.Session.CSRFState()
			bound, _ := state.Bindings()
			old, _ := caller.Session.Bindings()
			if bound.Binding.SessionVersion != old.Version+1 || state.Check(bound.Binding, csrf, key) != nil {
				t.Fatal("successor CSRF binding")
			}
			prior := bound.Binding
			prior.SessionVersion = old.Version
			if !errors.Is(state.Check(prior, csrf, key), session.ErrCSRFDenied) {
				t.Fatal("rotation retained old version")
			}
		})
	}
}

func TestCSRFEncryptedCachePreservesStateAndOriginalDeadline(t *testing.T) {
	codec, request, clock, observed, config, crypto, profile, _, _ := encryptedFixture(t)
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("c", 32)))
	record, token := csrfRecord(t, observed.Session, key)
	observed.Session = record
	original, e := codec.Get(context.Background(), request, nil)
	if e != nil {
		t.Fatal(e)
	}
	blob, e := codec.Seal(context.Background(), original)
	if e != nil {
		t.Fatal(e)
	}
	outage := observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		return session.SessionObservation{}, session.ErrUnavailable
	})
	service, _ := session.NewSessionService(outage, config)
	restored, _ := session.NewEncryptedCacheCodec(service, crypto, profile)
	clock.now = original.ValidUntil().Add(-time.Nanosecond)
	result, e := restored.Get(context.Background(), request, blob)
	if e != nil || !result.ValidUntil().Equal(original.ValidUntil()) {
		t.Fatal("cache lost original validity", e)
	}
	state := result.Session.CSRFState()
	bound, e := state.Bindings()
	if e != nil || state.Check(bound.Binding, token, key) != nil {
		t.Fatal("cache dropped synchronizer state")
	}
	clock.now = original.ValidUntil()
	if _, e = restored.Get(context.Background(), request, blob); !errors.Is(e, session.ErrUnavailable) {
		t.Fatal("CSRF-bearing cache renewed authority")
	}
}
