package passkeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
)

// The double exists only at the borrowed native boundary. Reference integration
// exercises actual action-bound UV assertions and durable mutations.
type observedSessionUpdate struct {
	options, completions int
	last                 passkey.SessionUpdateRequest
	key                  identity.IdempotencyKey
	completion           passkey.SessionUpdateCompletion
	result               *passkey.UpdateResult
	optionsResult        *passkey.KeyedAssertionOptionsResult
	err                  error
	after                func()
}

func (o *observedSessionUpdate) UpdateOptions(_ context.Context, r passkey.SessionUpdateOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	o.options++
	o.last, o.key = r.SessionUpdateRequest, r.IdempotencyKey
	if o.optionsResult != nil {
		return *o.optionsResult, o.err
	}
	return passkey.KeyedAssertionOptionsResult{}, identity.ForbiddenError{}
}

func TestSessionUpdateOptionsRetryPreservesOnlyOriginalReceipt(t *testing.T) {
	c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
	receipt := updateObservation(t, identity.CommitOutcomeCommitted).Receipt
	receipt.Binding.RecordID = string(receipt.Binding.CommandID)
	receipt.Binding.SchemaID = "identity.passkey.update.options-v1"
	receipt.Feature.Operation.SchemaID = receipt.Binding.SchemaID
	receipt.Feature.BeforeVersion, receipt.Feature.AfterVersion = 0, 1
	owner.optionsResult = &passkey.KeyedAssertionOptionsResult{CommandID: receipt.Binding.CommandID, Receipt: receipt, Replayed: true}
	h, err := NewSessionUpdateHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, updateRequest(sessionUpdateOptionsWire, cookie, csrf))
	var out optionsResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Replayed || out.CommandID != receipt.Binding.CommandID || len(out.Options) != 0 {
		t.Fatal("original options retry renewed challenge", w.Code, w.Body.String())
	}
}

func TestSessionUpdateWireMatchesSelectedClosedBodiesAndMetadata(t *testing.T) {
	c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
	f, err := NewFeature(FeatureConfig{SessionUpdate: &c})
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document.JSON()), `"proofID":`) || strings.Contains(string(document.JSON()), "__Host-identity_device") {
		t.Fatal("password/device dependency advertised")
	}
	parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(document.JSON())), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	check := func(wire string, keys []string, direction validate.InstanceDirection) {
		t.Helper()
		node := parsed.Raw()
		for _, key := range keys {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("missing selected wire", key)
			}
		}
		instance, err := parse.JSON(t.Context(), strings.NewReader(wire), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: direction})
		if err != nil || !report.Valid() {
			t.Fatal("selected wire rejected actual input/result", err)
		}
	}
	for _, wire := range []string{sessionUpdateOptionsWire, sessionUpdateCompleteWire} {
		wire = strings.Replace(wire, `{"id":"untrusted"}`, `{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"AQ","authenticatorData":"AQ","signature":"AQ"}}`, 1)
		check(wire, []string{"paths", "/v1/passkey/update", "post", "requestBody", "content", "application/json", "schema"}, validate.DirectionRequest)
	}
	out := updateObservation(t, identity.CommitOutcomeCommitted)
	out.Receipt.Binding.SchemaID = "identity.passkey.update.assertion-v1"
	out.Receipt.Feature.Operation.SchemaID = out.Receipt.Binding.SchemaID
	for _, replay := range []bool{false, true} {
		out.Replayed = replay
		out.Credential = nil
		if !replay {
			out.Credential = &passkey.CredentialMetadata{ReferenceID: "AAAAAAAAAAAAAAAAAAAAAg", Version: 2, State: "active", Label: "Personal key", CreatedAt: c.Now().Add(-time.Minute)}
		}
		owner.result = &out
		w := httptest.NewRecorder()
		h.ServeHTTP(w, updateRequest(sessionUpdateCompleteWire, cookie, csrf))
		if w.Code != 200 {
			t.Fatal("selected completion failed", w.Code)
		}
		check(w.Body.String(), []string{"paths", "/v1/passkey/update", "post", "responses", "200", "content", "application/json", "schema"}, validate.DirectionResponse)
	}
}

func TestSessionUpdateRejectsMissingOwnersAndPrivateSerialization(t *testing.T) {
	c, _, _, _, _, _ := sessionUpdateFixture(t)
	for _, change := range []func(*SessionUpdateConfig){func(c *SessionUpdateConfig) { c.Service = nil }, func(c *SessionUpdateConfig) { c.Sessions = nil }, func(c *SessionUpdateConfig) { c.Rate = nil }, func(c *SessionUpdateConfig) { c.CSRFKeys = nil }, func(c *SessionUpdateConfig) { c.CSRFKeys = append(c.CSRFKeys, c.CSRFKeys[0]) }, func(c *SessionUpdateConfig) { c.Now = nil }, func(c *SessionUpdateConfig) { c.MaximumDuration = 0 }} {
		bad := c
		change(&bad)
		if _, err := NewSessionUpdateHandler(bad); err == nil {
			t.Fatal("incomplete owner selected")
		}
	}
	for _, value := range []any{c, SessionUpdateState{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private custody serialized")
		}
		if !strings.Contains(fmt.Sprintf("%+v", value), "redacted") {
			t.Fatal("private diagnostics")
		}
	}
}
func (o *observedSessionUpdate) Update(_ context.Context, r passkey.SessionUpdateCompletion) (passkey.UpdateResult, error) {
	o.completions++
	o.last, o.key, o.completion = r.SessionUpdateRequest, r.IdempotencyKey, r
	if o.after != nil {
		o.after()
	}
	if o.result != nil {
		return *o.result, o.err
	}
	return passkey.UpdateResult{}, identity.ForbiddenError{}
}

func TestSessionUpdateNativeFailureRetainsDurabilityInBothPhases(t *testing.T) {
	for _, options := range []bool{false, true} {
		for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeCommitted} {
			t.Run(fmt.Sprint(options, "/", outcome), func(t *testing.T) {
				c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
				out := updateObservation(t, outcome)
				schema := "identity.passkey.update.assertion-v1"
				body := sessionUpdateCompleteWire
				if options {
					schema = "identity.passkey.update.options-v1"
					body = sessionUpdateOptionsWire
					out.Receipt.Binding.RecordID = string(out.CommandID)
					if outcome == identity.CommitOutcomeCommitted {
						out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 0, 1
					}
				}
				out.Receipt.Binding.SchemaID = schema
				out.Receipt.Feature.Operation.SchemaID = schema
				owner.err = errors.New("private-native-error")
				if options {
					owner.optionsResult = &passkey.KeyedAssertionOptionsResult{CommandID: out.CommandID, Receipt: out.Receipt}
				} else {
					owner.result = &out
				}
				h, err := NewSessionUpdateHandler(c)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, updateRequest(body, cookie, csrf))
				var got struct {
					CommandID     identity.CommandID `json:"commandID"`
					CommitOutcome string             `json:"commitOutcome"`
				}
				want := "unknown"
				if outcome == identity.CommitOutcomeCommitted {
					want = "committed"
				}
				if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.CommandID != out.CommandID || got.CommitOutcome != want {
					t.Fatal("native error lost original durability", w.Code, w.Body.String())
				}
				for _, field := range []string{"private-native-error", "credential", "options"} {
					if strings.Contains(w.Body.String(), field) {
						t.Fatal("native error leaked private response", field)
					}
				}
				if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("failed delivery issued authentication")
				}
			})
		}
	}
}

func TestSessionUpdatePostHookCannotRenewCommittedDelivery(t *testing.T) {
	for _, mode := range []string{"expired", "panic", "append"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			out := updateObservation(t, identity.CommitOutcomeCommitted)
			out.Receipt.Binding.SchemaID = "identity.passkey.update.assertion-v1"
			out.Receipt.Feature.Operation.SchemaID = out.Receipt.Binding.SchemaID
			out.Credential = &passkey.CredentialMetadata{ReferenceID: "AAAAAAAAAAAAAAAAAAAAAg", Version: 2, State: "active", Label: "Personal key", CreatedAt: now.Add(-time.Minute)}
			owner.result = &out
			h, err := NewSessionUpdateHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				switch mode {
				case "expired":
					now = now.Add(21 * time.Second)
				case "panic":
					panic("private-hook-error")
				case "append":
					_, _ = w.Write([]byte("private-hook-bytes"))
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			var aborted any
			func() {
				defer func() { aborted = recover() }()
				h.ServeHTTP(w, updateRequest(sessionUpdateCompleteWire, cookie, csrf))
			}()
			if mode == "panic" {
				// The base pipeline intentionally aborts the connection on panic,
				// never flushing the buffered committed response to net/http.
				if aborted != http.ErrAbortHandler || w.Body.Len() != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("panic did not abort private delivery")
				}
				return
			}
			if aborted != nil {
				t.Fatal("unexpected handler abort")
			}
			var got struct {
				CommandID     identity.CommandID `json:"commandID"`
				CommitOutcome string             `json:"commitOutcome"`
			}
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.CommandID != out.CommandID || got.CommitOutcome != "committed" {
				t.Fatal("post-hook failure lost committed metadata", mode, w.Code, w.Body.String())
			}
			for _, field := range []string{"credential", "private-hook", "Personal key"} {
				if strings.Contains(w.Body.String(), field) {
					t.Fatal("post-hook delivery leaked original custody", mode, field)
				}
			}
		})
	}
}
func sessionUpdateFixture(t *testing.T) (SessionUpdateConfig, *observedSessionUpdate, *deniedEnrollment, *observedSession, *http.Cookie, string) {
	t.Helper()
	c, _, proofs, reader, cookie, csrf := updateFixture(t)
	owner := &observedSessionUpdate{}
	return SessionUpdateConfig{Network: c.Network, Sessions: c.Sessions, Service: owner, Rate: c.Rate, Origin: c.Origin, SessionCookie: c.SessionCookie, CSRFKeys: c.CSRFKeys, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, proofs, reader, cookie, csrf
}

const sessionUpdateOptionsWire = `{"phase":"options","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":1,"name":"Personal key"}`
const sessionUpdateCompleteWire = `{"phase":"complete","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":1,"name":"Personal key","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","response":{"id":"untrusted"}}`

func TestSessionUpdateForwardsOriginalSessionAndClosedPhaseWithoutPassword(t *testing.T) {
	for _, complete := range []bool{false, true} {
		c, owner, proofs, reader, cookie, csrf := sessionUpdateFixture(t)
		h, err := NewSessionUpdateHandler(c)
		if err != nil || reader.reads != 0 || proofs.proofReads != 0 {
			t.Fatal("construction IO", err)
		}
		body := sessionUpdateOptionsWire
		if complete {
			body = sessionUpdateCompleteWire
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, updateRequest(body, cookie, csrf))
		if w.Code != 403 || owner.options+owner.completions != 1 || (complete && owner.completions != 1) || proofs.proofReads != 0 {
			t.Fatal("wrong native phase or password dependency", w.Code)
		}
		r := owner.last
		if r.Credential.Kind() != session.CredentialCookie || r.Caller.Request.Subject.ID != "user-a" || r.Caller.Request.Action != "identity.passkey.update" || r.ReferenceID != "AAAAAAAAAAAAAAAAAAAAAg" || r.ExpectedVersion != 1 || r.Name != "Personal key" || r.Network != "198.51.100.7" || r.Origin != string(c.Origin) {
			t.Fatal("original custody replaced", r)
		}
		key, _ := identity.NewIdempotencyKey([]byte("original-passkey-update"))
		got, _ := owner.key.Digest([32]byte{1})
		want, _ := key.Digest([32]byte{1})
		if got != want || (complete && (owner.completion.CeremonyID != "AAAAAAAAAAAAAAAAAAAAAw" || string(owner.completion.Response) != `{"id":"untrusted"}`)) {
			t.Fatal("original key/assertion changed")
		}
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("management issued authentication")
		}
	}
}

func TestSessionUpdateRejectsAmbiguousBodyAndCustodyBeforeNative(t *testing.T) {
	for _, mode := range []string{"phase-missing", "phase-null", "phase-unknown", "proof", "options-response", "options-ceremony", "complete-no-response", "complete-no-ceremony", "duplicate-phase", "body-key", "command", "tenant", "bearer", "no-key", "duplicate-key", "no-cookie", "no-csrf", "wrong-csrf", "foreign-origin", "query"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
			h, err := NewSessionUpdateHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			body := sessionUpdateOptionsWire
			switch mode {
			case "phase-missing":
				body = strings.Replace(body, `"phase":"options",`, "", 1)
			case "phase-null":
				body = strings.Replace(body, `"options"`, `null`, 1)
			case "phase-unknown":
				body = strings.Replace(body, `"options"`, `"signin"`, 1)
			case "proof":
				body = strings.Replace(body, `"phase":`, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","phase":`, 1)
			case "options-response":
				body = strings.Replace(body, `"phase":`, `"response":{},"phase":`, 1)
			case "options-ceremony":
				body = strings.Replace(body, `"phase":`, `"ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw","phase":`, 1)
			case "complete-no-response":
				body = strings.Replace(sessionUpdateCompleteWire, `,"response":{"id":"untrusted"}`, "", 1)
			case "complete-no-ceremony":
				body = strings.Replace(sessionUpdateCompleteWire, `,"ceremonyID":"AAAAAAAAAAAAAAAAAAAAAw"`, "", 1)
			case "duplicate-phase":
				body = strings.Replace(body, `"phase":`, `"phase":"complete","phase":`, 1)
			case "body-key":
				body = strings.Replace(body, `"phase":`, `"idempotencyKey":"other","phase":`, 1)
			case "command":
				body = strings.Replace(body, `"phase":`, `"commandID":"AAAAAAAAAAAAAAAAAAAAAw","phase":`, 1)
			case "tenant":
				body = strings.Replace(body, `"phase":`, `"tenantID":"other","phase":`, 1)
			}
			r := updateRequest(body, cookie, csrf)
			switch mode {
			case "bearer":
				r.Header.Set("Authorization", "Bearer other")
			case "no-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "other")
			case "no-cookie":
				r.Header.Del("Cookie")
			case "no-csrf":
				r.Header.Del("X-CSRF-Token")
			case "wrong-csrf":
				r.Header.Set("X-CSRF-Token", strings.Repeat("A", 42)+"E")
			case "foreign-origin":
				r.Header.Set("Origin", "https://foreign.example")
			case "query":
				r.URL.RawQuery = "phase=complete"
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || owner.options+owner.completions != 0 {
				t.Fatal("ambiguous custody reached native", w.Code)
			}
		})
	}
}

func TestSessionUpdateCompletionReceiptAndDelivery(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "foreign-schema", "expired"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := sessionUpdateFixture(t)
			out := updateObservation(t, identity.CommitOutcomeCommitted)
			out.Receipt.Binding.SchemaID = "identity.passkey.update.assertion-v1"
			out.Receipt.Feature.Operation.SchemaID = out.Receipt.Binding.SchemaID
			out.Credential = &passkey.CredentialMetadata{ReferenceID: "AAAAAAAAAAAAAAAAAAAAAg", Version: 2, State: "active", Label: "Personal key", CreatedAt: c.Now().Add(-time.Minute)}
			status := 200
			switch mode {
			case "replay":
				out.Replayed = true
				out.Credential = nil
			case "foreign-schema":
				out = updateObservation(t, identity.CommitOutcomeCommitted)
				status = 503
			case "expired":
				now := c.Now()
				c.Now = func() time.Time { return now }
				owner.after = func() { now = now.Add(21 * time.Second) }
				status = 503
			}
			owner.result = &out
			h, err := NewSessionUpdateHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, updateRequest(sessionUpdateCompleteWire, cookie, csrf))
			var body UpdateResponse
			if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatal("invalid receipt/delivery admitted", w.Code, w.Body.String())
			}
			if mode == "fresh" && (body.Credential == nil || body.Credential.Label != "Personal key") {
				t.Fatal("fresh safe metadata absent")
			}
			if mode == "replay" && (!body.Replayed || body.Credential != nil) {
				t.Fatal("replay revealed credential")
			}
		})
	}
}

func TestSessionUpdateSelectionDoesNotReplacePasswordProfile(t *testing.T) {
	c, _, _, _, _, _ := sessionUpdateFixture(t)
	f, err := NewFeature(FeatureConfig{SessionUpdate: &c})
	if err != nil {
		t.Fatal(err)
	}
	ops := f.Operations()
	if len(ops) != 1 || ops[0].Record.OperationID != "identity.passkey.update" || ops[0].Record.RatePolicy != "rate.secret" || ops[0].Record.CSRFOrigin.Mode != identityhttp.CSRFSessionState {
		t.Fatal("canonical protected operation replaced")
	}
	old, _, _, _, _, _ := updateFixture(t)
	if _, err := NewFeature(FeatureConfig{Update: &old, SessionUpdate: &c}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("competing update profiles accepted", err)
	}
}
