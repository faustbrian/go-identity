package passkeyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

const sessionDeletionOptionsWire = `{"phase":"options","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":7}`
const sessionDeletionCompleteWire = `{"phase":"complete","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":7,"ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"untrusted"}}`
const sessionDeletionRecoverWire = `{"phase":"recover","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":7,"commandID":"AAAAAAAAAAAAAAAAAAAABA"}`

// Only the native IO boundary is doubled. The real SessionService creates
// positive custody from current observations and checks the actual cookie/CSRF.
// Native genuine UV/removal/recovery correctness is separate Reference PG proof.
type observedSessionDeletion struct {
	options, completions, recoveries int
	last                             passkey.SessionDeleteRequest
	completion                       passkey.SessionDeleteCompletion
	query                            identity.RecoveryQuery
	key                              identity.IdempotencyKey
	optionsResult                    passkey.KeyedAssertionOptionsResult
	result                           passkey.SessionDeleteResult
	err                              error
	after                            func()
}

func (o *observedSessionDeletion) DeleteOptions(_ context.Context, r passkey.SessionDeleteOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	o.options++
	o.last, o.key = r.SessionDeleteRequest, r.IdempotencyKey
	if o.after != nil {
		o.after()
	}
	return o.optionsResult, o.err
}

func (o *observedSessionDeletion) Delete(_ context.Context, r passkey.SessionDeleteCompletion) (passkey.SessionDeleteResult, error) {
	o.completions++
	o.completion = r
	b, err := r.Bindings()
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	o.last, o.key = b.SessionDeleteRequest, b.IdempotencyKey
	if o.after != nil {
		o.after()
	}
	return o.result, o.err
}

func (o *observedSessionDeletion) RecoverDelete(_ context.Context, r passkey.SessionDeleteRequest, q identity.RecoveryQuery) (passkey.SessionDeleteResult, error) {
	o.recoveries++
	o.last, o.query = r, q
	if o.after != nil {
		o.after()
	}
	return o.result, o.err
}

func sessionDeletionFixture(t *testing.T) (SessionDeletionConfig, *observedSessionDeletion, *deniedEnrollment, *observedSession, *http.Cookie, string) {
	t.Helper()
	c, _, proofs, reader, cookie, csrf := updateFixture(t)
	spec, err := reader.observation.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := spec.Authority.Bindings()
	vector.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor:tenant-a:user-a", Version: 2}}
	vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:tenant-a:user-a", Version: 3}}
	spec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.CredentialID = "passkey-a"
	spec.Authentication.Proof.Method = "passkey"
	spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
	record, err := session.NewSessionWithCSRF(spec, reader.observation.Session.CSRFState())
	if err != nil {
		t.Fatal(err)
	}
	reader.observation.Session, reader.observation.Current = record, spec.Authority
	owner := &observedSessionDeletion{err: identity.ForbiddenError{}}
	return SessionDeletionConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: c.Rate, Origin: c.Origin, SessionCookie: c.SessionCookie, CSRFKeys: c.CSRFKeys, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, proofs, reader, cookie, csrf
}

func sessionDeletionObservation(t *testing.T, outcome identity.CommitOutcome, options bool) passkey.DeleteResult {
	t.Helper()
	initial := outcome
	if initial == identity.CommitOutcomeInProgress {
		initial = identity.CommitOutcomeUnknown
	}
	u := updateObservation(t, initial)
	u.Outcome, u.Receipt.Outcome = outcome, outcome
	u.CommandID = "AAAAAAAAAAAAAAAAAAAABA"
	u.Receipt.Binding.CommandID = u.CommandID
	schema := "identity.passkey.delete.assertion-v1"
	if options {
		schema = "identity.passkey.delete.options-v1"
		u.Receipt.Binding.RecordID = string(u.CommandID)
	}
	u.Receipt.Binding.OperationID, u.Receipt.Binding.SchemaID = "identity.passkey.delete", schema
	u.Receipt.Feature.Operation.OperationID, u.Receipt.Feature.Operation.SchemaID = "identity.passkey.delete", schema
	if outcome == identity.CommitOutcomeCommitted {
		// Metadata expectedVersion is 7, deliberately independent of kernel3.
		u.Receipt.Feature.BeforeVersion, u.Receipt.Feature.AfterVersion = 3, 4
		if options {
			u.Receipt.Feature.BeforeVersion, u.Receipt.Feature.AfterVersion = 0, 1
		}
	} else if outcome == identity.CommitOutcomeInProgress {
		u.Receipt.RetryAfter = 2 * time.Second
	}
	if err := u.Receipt.Validate(); err != nil {
		t.Fatal("invalid native observation fixture", err)
	}
	return passkey.DeleteResult{CommandID: u.CommandID, Outcome: outcome, Receipt: u.Receipt}
}

func TestSessionDeletionForwardsOriginalSessionAndThreeDistinctPhases(t *testing.T) {
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		t.Run(wire, func(t *testing.T) {
			c, owner, proofs, reader, cookie, csrf := sessionDeletionFixture(t)
			h, err := NewSessionDeletionHandler(c)
			if err != nil || reader.reads != 0 || proofs.proofReads != 0 {
				t.Fatal("construction performed IO", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
			if w.Code != 403 || owner.options+owner.completions+owner.recoveries != 1 || proofs.proofReads != 0 {
				t.Fatal("native denial/phase/password boundary changed", w.Code)
			}
			r, err := owner.last.Bindings()
			if err != nil || r.Credential.Kind() != session.CredentialCookie || r.Caller.Request.Subject.ID != "user-a" || r.Caller.Request.Action != "identity.passkey.delete" || r.Caller.Request.Resource.ID != "user-a" || r.ReferenceID != "AAAAAAAAAAAAAAAAAAAAAg" || r.ExpectedVersion != 7 || r.Network != "198.51.100.7" || r.Origin != string(c.Origin) {
				t.Fatal("original custody or self policy changed")
			}
			if owner.recoveries == 1 {
				q := owner.query
				if q.CommandID != "AAAAAAAAAAAAAAAAAAAABA" || q.TenantID != "tenant-a" || q.UserID != "user-a" || q.ActorID != "user-a" || q.OperationID != "identity.passkey.delete" || q.RecordID != string(r.ReferenceID) || q.AnonymousFlowID != "" || q.LinkMode != 0 || owner.key != (identity.IdempotencyKey{}) {
					t.Fatal("recovery command or current scope rebound")
				}
			} else {
				want, _ := identity.NewIdempotencyKey([]byte("original-passkey-delete"))
				a, err := owner.key.Digest([32]byte{1})
				b, _ := want.Digest([32]byte{1})
				if err != nil || a != b {
					t.Fatal("original header key changed")
				}
			}
			if owner.completions == 1 {
				b, _ := owner.completion.Bindings()
				if b.CeremonyID != "AAAAAAAAAAAAAAAAAAAAAw" || string(b.Response) != `{"id":"untrusted"}` {
					t.Fatal("original assertion replaced")
				}
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("deletion issued authentication")
			}
		})
	}
}

func TestSessionDeletionSelectionAndMissingOwners(t *testing.T) {
	c, _, _, _, _, _ := sessionDeletionFixture(t)
	f, err := NewFeature(FeatureConfig{SessionDeletion: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops := f.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.passkey.delete" || ops[0].Record.RatePolicy != "rate.secret" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFSessionState {
		t.Fatal("selected canonical security contract changed")
	}
	old, _, _, _, _ := deletionFixture(t)
	if _, err := NewFeature(FeatureConfig{Delete: &old, SessionDeletion: &c}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("competing deletion profiles accepted")
	}
	for _, change := range []func(*SessionDeletionConfig){func(c *SessionDeletionConfig) { c.Service = nil }, func(c *SessionDeletionConfig) { c.Sessions = nil }, func(c *SessionDeletionConfig) { c.Rate = nil }, func(c *SessionDeletionConfig) { c.CSRFKeys = nil }, func(c *SessionDeletionConfig) { c.CSRFKeys = append(c.CSRFKeys, c.CSRFKeys[0]) }, func(c *SessionDeletionConfig) { c.Now = nil }, func(c *SessionDeletionConfig) { c.MaximumDuration = 0 }} {
		bad := c
		change(&bad)
		if _, err := NewSessionDeletionHandler(bad); err == nil {
			t.Fatal("incomplete owner selected")
		}
	}
	for _, value := range []any{c, SessionDeletionState{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private custody serialized")
		}
		if !strings.Contains(fmt.Sprintf("%+v", value), "redacted") {
			t.Fatal("private diagnostics")
		}
	}
}

func TestSessionDeletionNativeDurabilityAndIndependentVersions(t *testing.T) {
	for _, phase := range []string{"complete", "options", "recover"} {
		for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
			t.Run(fmt.Sprint(phase, "/", outcome), func(t *testing.T) {
				c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
				out := sessionDeletionObservation(t, outcome, phase == "options")
				wire := sessionDeletionCompleteWire
				if outcome != identity.CommitOutcomeCommitted {
					owner.err = errors.New("private-native-failure")
				} else {
					owner.err = nil
				}
				if phase == "options" {
					wire, out.Replayed = sessionDeletionOptionsWire, true
					owner.optionsResult = passkey.KeyedAssertionOptionsResult{CommandID: out.CommandID, Receipt: out.Receipt, Replayed: true}
				} else {
					if phase == "recover" {
						wire, out.Replayed = sessionDeletionRecoverWire, true
					}
					owner.result = passkey.NewSessionDeleteResult(out)
				}
				h, err := NewSessionDeletionHandler(c)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
				status, want := 503, "unknown"
				switch outcome {
				case identity.CommitOutcomeCommitted:
					status, want = 200, "committed"
				case identity.CommitOutcomeNotCommitted:
					want = "not_committed"
				case identity.CommitOutcomeConflict:
					status, want = 409, "conflict"
				case identity.CommitOutcomeInProgress:
					status, want = 409, "in_progress"
				}
				var got DeleteResponse
				if w.Code != status || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.CommitOutcome != want || got.CommandID != out.CommandID {
					t.Fatal("native durability changed", w.Code, w.Body.String())
				}
				if outcome == identity.CommitOutcomeInProgress && w.Header().Get("Retry-After") != "2" {
					t.Fatal("original retry metadata lost")
				}
				if strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), "credential") || strings.Contains(w.Body.String(), "options") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("durability projected credential custody")
				}
			})
		}
	}
}

// Options are generated by the actual public WebAuthn owner. This explicit
// protocol storage seam only persists its original creation, never fabricates
// browser JSON or verified authentication.
type deletionOptionsStore struct {
	webauthn.Store
	now time.Time
}

func (s deletionOptionsStore) CreateCeremony(ctx context.Context, creation webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	record, challenge, err := creation.Generate(ctx, s.now)
	return record, challenge, identity.CommitOutcomeCommitted, err
}

func deletionProtocolOptions(t *testing.T, now time.Time, allowed ...[]byte) webauthn.AssertionOptions {
	t.Helper()
	key, err := webauthn.NewChallengeDigestKey(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := webauthn.New(webauthn.Config{TenantID: "tenant-a", RelyingParty: webauthn.RelyingParty{ID: "tenant.example", Name: "Example", Origins: []string{"https://tenant.example"}, Version: 1}, ChallengeKey: key, MaximumDuration: time.Second}, webauthn.Dependencies{Store: deletionOptionsStore{now: now}})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) == 0 {
		allowed = [][]byte{{6}}
	}
	options, err := protocol.BeginAssertion(t.Context(), webauthn.BeginAssertionRequest{Context: webauthn.CeremonyContext{CommandID: "AAAAAAAAAAAAAAAAAAAABA", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", CorrelationID: "original-deletion"}, Origin: "https://tenant.example", UserHandle: bytes.Repeat([]byte{5}, 32), AllowedCredentials: allowed})
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func TestSessionDeletionFreshOptionsAndOriginalExpiryThroughHooks(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "replay-with-options", "already-expired", "post-hook-expiry", "post-hook-read-expiry", "extra-allowed-key"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			out := sessionDeletionObservation(t, identity.CommitOutcomeCommitted, true)
			owner.err = nil
			owner.optionsResult = passkey.KeyedAssertionOptionsResult{CommandID: out.CommandID, Receipt: out.Receipt, Replayed: mode == "replay" || mode == "replay-with-options"}
			if mode != "replay" {
				created := now
				if mode == "already-expired" {
					created = now.Add(-5 * time.Minute)
				} else if mode == "post-hook-expiry" {
					created = now.Add(-5*time.Minute + 500*time.Millisecond)
				}
				owner.optionsResult.Options = deletionProtocolOptions(t, created)
				if mode == "extra-allowed-key" {
					owner.optionsResult.Options = deletionProtocolOptions(t, created, []byte{6}, []byte{7})
				}
			}
			h, err := NewSessionDeletionHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				if mode == "post-hook-expiry" {
					now = now.Add(time.Second)
				} else if mode == "post-hook-read-expiry" {
					now = now.Add(21 * time.Second)
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(sessionDeletionOptionsWire, cookie, csrf))
			var got optionsResponse
			status := 503
			if mode == "fresh" || mode == "replay" {
				status = 200
			}
			if w.Code != status || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.CommandID != out.CommandID || got.CommitOutcome != "committed" {
				t.Fatal("original options/read expiry changed", w.Code)
			}
			if mode == "fresh" {
				var options struct {
					PublicKey struct {
						UV      string `json:"userVerification"`
						Allowed []any  `json:"allowCredentials"`
					} `json:"publicKey"`
				}
				if json.Unmarshal(got.Options, &options) != nil || options.PublicKey.UV != "required" || len(options.PublicKey.Allowed) != 1 {
					t.Fatal("genuine identified UV options not delivered")
				}
			} else if len(got.Options) != 0 {
				t.Fatal("retry/expired delivery disclosed challenge")
			}
		})
	}
}

func TestSessionDeletionRejectsForeignReceiptsAndInvalidLifecycle(t *testing.T) {
	for _, mode := range []string{"schema", "tenant", "user", "actor", "record", "owner", "revision", "zero-before", "invalid-after", "wrong-command", "outcome-mismatch", "recover-options-history", "recover-not-replay", "recover-wrong-command"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
			out := sessionDeletionObservation(t, identity.CommitOutcomeCommitted, false)
			wire := sessionDeletionCompleteWire
			switch mode {
			case "schema":
				out.Receipt.Binding.SchemaID = "identity.passkey.update.assertion-v1"
				out.Receipt.Feature.Operation.SchemaID = out.Receipt.Binding.SchemaID
			case "tenant":
				out.Receipt.Binding.TenantID = "tenant-b"
			case "user":
				out.Receipt.Binding.UserID = "user-b"
			case "actor":
				out.Receipt.Binding.ActorID = "user-b"
			case "record":
				out.Receipt.Binding.RecordID = "other-key"
			case "owner":
				out.Receipt.Feature.Operation.Owner = "other-owner"
			case "revision":
				out.Receipt.Binding.PolicyVersion++
			case "zero-before":
				out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 1
			case "invalid-after":
				out.Receipt.Feature.AfterVersion++
			case "wrong-command":
				out.CommandID = "AAAAAAAAAAAAAAAAAAAAAw"
			case "outcome-mismatch":
				out.Outcome = identity.CommitOutcomeUnknown
			case "recover-options-history":
				out = sessionDeletionObservation(t, identity.CommitOutcomeCommitted, true)
				wire, out.Replayed = sessionDeletionRecoverWire, true
			case "recover-not-replay":
				wire = sessionDeletionRecoverWire
			case "recover-wrong-command":
				wire, out.Replayed = sessionDeletionRecoverWire, true
				out.CommandID, out.Receipt.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAAAw", "AAAAAAAAAAAAAAAAAAAAAw"
			}
			owner.err, owner.result = nil, passkey.NewSessionDeleteResult(out)
			h, err := NewSessionDeletionHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
			if w.Code != 503 || strings.Contains(w.Body.String(), "commandID") || strings.Contains(w.Body.String(), "commitOutcome") {
				t.Fatal("invalid receipt established original durability", w.Code, w.Body.String())
			}
		})
	}
}

func TestSessionDeletionHooksCannotExtendOrAcquireAcknowledgementCustody(t *testing.T) {
	for _, mode := range []string{"expiry", "panic", "append", "cancel", "committed-error"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			out := sessionDeletionObservation(t, identity.CommitOutcomeCommitted, false)
			owner.err, owner.result = nil, passkey.NewSessionDeleteResult(out)
			if mode == "committed-error" {
				owner.err = errors.New("private-native-delivery-error")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h, err := NewSessionDeletionHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				switch mode {
				case "expiry":
					now = now.Add(21 * time.Second)
				case "panic":
					panic("private-hook-panic")
				case "append":
					_, _ = w.Write([]byte("private-hook-payload"))
				case "cancel":
					cancel()
				}
				w.Header().Set("Set-Cookie", "private-injected-cookie")
				w.Header().Set("X-CSRF-Token", "private-injected-csrf")
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			var aborted any
			func() {
				defer func() { aborted = recover() }()
				h.ServeHTTP(w, deletionRequest(sessionDeletionCompleteWire, cookie, csrf).WithContext(ctx))
			}()
			if mode == "panic" {
				if aborted != http.ErrAbortHandler || w.Body.Len() != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("panicked delivery disclosed buffered custody")
				}
				return
			}
			if aborted != nil {
				t.Fatal("unexpected transport abort")
			}
			var got DeleteResponse
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.CommandID != out.CommandID || got.CommitOutcome != "committed" || strings.Contains(w.Body.String(), "private-") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("post-hook failure changed durability or leaked custody", w.Code, w.Body.String())
			}
		})
	}
}

func TestSessionDeletionAcknowledgesOwnInvalidationButNewCallsNeedCurrentSession(t *testing.T) {
	c, owner, _, reader, cookie, csrf := sessionDeletionFixture(t)
	out := sessionDeletionObservation(t, identity.CommitOutcomeCommitted, false)
	owner.err, owner.result = nil, passkey.NewSessionDeleteResult(out)
	owner.after = func() { reader.observation.Active = false }
	h, err := NewSessionDeletionHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, deletionRequest(sessionDeletionCompleteWire, cookie, csrf))
	if w.Code != 200 || owner.completions != 1 {
		t.Fatal("original invocation could not acknowledge own session effects", w.Code)
	}
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
		if w.Code != 401 || owner.completions != 1 || owner.options != 0 || owner.recoveries != 0 {
			t.Fatal("invalidated session reused current authority", w.Code)
		}
	}
	// Install a distinct surviving-key observation. Its cookie and synchronizer
	// are read by the actual SessionService, never accepted as a body override.
	spec, _ := reader.observation.Session.Bindings()
	spec.SessionID, spec.Authentication.CredentialID = "surviving-session", "passkey-survivor"
	vector, _ := spec.Authority.Bindings()
	vector.Passkey.Binding.Version++
	vector.Session.ScopeKey = "session:surviving-session"
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	token, _ := session.NewToken(32)
	lookup, _ := session.NewDigestKey(1, make([]byte, 32))
	spec.Lookup, _ = token.Digest(lookup, string(spec.TenantID))
	newCSRF, _ := session.NewCSRFToken()
	state, _ := newCSRF.Digest(c.CSRFKeys[0], session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	record, err := session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	reader.observation.Session, reader.observation.Current, reader.observation.Active = record, spec.Authority, true
	newWire, _ := token.Reveal()
	newSynchronizer, _ := newCSRF.Reveal()
	owner.after, out.Replayed = nil, true
	owner.result = passkey.NewSessionDeleteResult(out)
	w = httptest.NewRecorder()
	r := deletionRequest(sessionDeletionRecoverWire, &http.Cookie{Name: cookie.Name, Value: newWire}, newSynchronizer)
	r.Header.Set("Idempotency-Key", "recovery-rate-admission-only")
	h.ServeHTTP(w, r)
	var got DeleteResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !got.Replayed || got.CommandID != out.CommandID || owner.recoveries != 1 || owner.completions != 1 {
		t.Fatal("current surviving session could not recover original metadata", w.Code, w.Body.String())
	}
}

func TestSessionDeletionEveryPhaseRejectsAmbiguousTransportBeforeNative(t *testing.T) {
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		for _, mode := range []string{"no-key", "duplicate-key", "no-cookie", "duplicate-cookie", "no-csrf", "duplicate-csrf", "wrong-csrf", "foreign-origin", "duplicate-origin", "bearer", "query", "foreign-host", "plaintext", "duplicate-phase", "trailing-json", "oversized-response"} {
			t.Run(mode+wire[:min(len(wire), 24)], func(t *testing.T) {
				c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
				body := wire
				switch mode {
				case "duplicate-phase":
					body = strings.Replace(body, `"phase":`, `"phase":"recover","phase":`, 1)
				case "trailing-json":
					body += `{}`
				case "oversized-response":
					body = strings.Replace(sessionDeletionCompleteWire, `"untrusted"`, `"`+strings.Repeat("A", 262144)+`"`, 1)
				}
				r := deletionRequest(body, cookie, csrf)
				switch mode {
				case "no-key":
					r.Header.Del("Idempotency-Key")
				case "duplicate-key":
					r.Header.Add("Idempotency-Key", "other")
				case "no-cookie":
					r.Header.Del("Cookie")
				case "duplicate-cookie":
					r.AddCookie(cookie)
				case "no-csrf":
					r.Header.Del("X-CSRF-Token")
				case "duplicate-csrf":
					r.Header.Add("X-CSRF-Token", csrf)
				case "wrong-csrf":
					r.Header.Set("X-CSRF-Token", strings.Repeat("A", 42)+"E")
				case "foreign-origin":
					r.Header.Set("Origin", "https://other.example")
				case "duplicate-origin":
					r.Header.Add("Origin", string(c.Origin))
				case "bearer":
					r.Header.Set("Authorization", "Bearer synthetic")
				case "query":
					r.URL.RawQuery = "commandID=untrusted"
				case "foreign-host":
					r.Host = "other.example"
				case "plaintext":
					r.TLS = nil
					r.URL.Scheme = "http"
				}
				h, err := NewSessionDeletionHandler(c)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code < 400 || owner.options+owner.completions+owner.recoveries != 0 {
					t.Fatal("ambiguous transport reached native", mode, w.Code)
				}
			})
		}
	}
}

func TestSessionDeletionClosedBody(t *testing.T) {
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		out, err := decodeBody("session-delete", bodyFields(t, wire))
		if err != nil || out.referenceID != "AAAAAAAAAAAAAAAAAAAAAg" || out.expectedVersion != 7 {
			t.Fatal("closed removal phase rejected", err)
		}
		for _, field := range []string{`"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"tenantID":"other"`, `"userID":"other"`, `"rpID":"other"`, `"sessionID":"other"`, `"network":"other"`, `"idempotencyKey":"other"`, `"name":"other"`} {
			if _, err := decodeBody("session-delete", bodyFields(t, strings.Replace(wire, "{", "{"+field+",", 1))); err == nil {
				t.Fatal("untrusted custody override accepted", field)
			}
		}
	}
	for _, wire := range []string{
		strings.Replace(sessionDeletionOptionsWire, `"phase":"options",`, "", 1),
		strings.Replace(sessionDeletionOptionsWire, `"options"`, `"unknown"`, 1),
		strings.Replace(sessionDeletionOptionsWire, `"phase":`, `"commandID":"AAAAAAAAAAAAAAAAAAAABA","phase":`, 1),
		strings.Replace(sessionDeletionOptionsWire, `"phase":`, `"response":{},"phase":`, 1),
		strings.Replace(sessionDeletionCompleteWire, `,"response":{"id":"untrusted"}`, "", 1),
		strings.Replace(sessionDeletionCompleteWire, `,"ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw"`, "", 1),
		strings.Replace(sessionDeletionRecoverWire, `,"commandID":"AAAAAAAAAAAAAAAAAAAABA"`, "", 1),
		strings.Replace(sessionDeletionRecoverWire, `"phase":`, `"ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","phase":`, 1),
	} {
		if _, err := decodeBody("session-delete", bodyFields(t, wire)); err == nil {
			t.Fatal("ambiguous removal phase accepted")
		}
	}
}
