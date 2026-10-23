package passkeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type deniedUpdate struct {
	calls  int
	last   passkey.UpdateRequest
	result *passkey.UpdateResult
	err    error
}

func (d *deniedUpdate) Update(_ context.Context, r passkey.UpdateRequest) (passkey.UpdateResult, error) {
	d.calls++
	d.last = r
	if d.result != nil {
		return *d.result, d.err
	}
	return passkey.UpdateResult{}, identity.ForbiddenError{}
}

func updateFixture(t *testing.T) (UpdateConfig, *deniedUpdate, *deniedEnrollment, *observedSession, *http.Cookie, string) {
	t.Helper()
	c, proofs, reader, cookie, _, csrf := registrationFixture(t)
	proofs.proof.Action = "identity.passkey.update"
	store, err := memory.New(memory.Options{MaxKeys: 512, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: &parserRates{store}, Namespace: "passkey-update", Key: [32]byte{3}, Now: c.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	owner := &deniedUpdate{}
	return UpdateConfig{Network: c.Network, Sessions: c.Sessions, Proofs: proofs, Service: owner, Rate: rate, Origin: c.Origin, SessionCookie: c.SessionCookie, CSRFKeys: c.CSRFKeys, PolicyRevision: c.PolicyRevision, Audience: c.Audience, Now: c.Now, MaximumDuration: c.MaximumDuration}, owner, proofs, reader, cookie, csrf
}

const updateWire = `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":1,"name":"Personal key"}`

func updateRequest(body string, cookie *http.Cookie, csrf string) *http.Request {
	r := registrationRequest("update", body, cookie, nil, csrf)
	r.Header.Set("Idempotency-Key", "original-passkey-update")
	return r
}

func TestUpdateUsesActualSessionAndOriginalProofWithoutCommandOverride(t *testing.T) {
	c, owner, proofs, reader, cookie, csrf := updateFixture(t)
	h, err := NewUpdateHandler(c)
	if err != nil || reader.reads != 0 || proofs.proofReads != 0 {
		t.Fatal("construction IO", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
	if w.Code != 403 || owner.calls != 1 || proofs.proofReads != 1 {
		t.Fatal("native denial bypassed", w.Code, owner.calls)
	}
	r := owner.last
	if r.Primary.Proof != proofs.proof || r.Primary.CommandID != "" || r.Primary.RecordID != "" || r.Primary.TargetSubjectID != "" || r.Primary.Caller.Request.Subject.ID != "user-a" || r.Primary.Caller.Request.Action != "identity.passkey.update" || r.ReferenceID != "AAAAAAAAAAAAAAAAAAAAAg" || r.ExpectedVersion != 1 || r.Name != "Personal key" || r.Network != "198.51.100.7" {
		t.Fatal("transport replaced custody or request", r)
	}
	key, _ := identity.NewIdempotencyKey([]byte("original-passkey-update"))
	got, err := r.IdempotencyKey.Digest([32]byte{1})
	want, _ := key.Digest([32]byte{1})
	if err != nil || got != want {
		t.Fatal("header key changed")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("update issued authentication")
	}
}

// This builds only a public, structurally validated observation at the borrowed
// native boundary, not a signed proof or authentication result. Real mutation
// and commit provenance are exercised by the separate Reference PG journey.
func updateObservation(t *testing.T, outcome identity.CommitOutcome) passkey.UpdateResult {
	t.Helper()
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	receipt := identity.CommandResult{Binding: identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAw", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "policy-a", PolicyVersion: 9, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation-a", RecordID: "AAAAAAAAAAAAAAAAAAAAAg"}, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}
	if outcome == identity.CommitOutcomeCommitted {
		receipt.AuditEventID = "rename-audit"
		receipt.Feature.BeforeVersion = 1
		receipt.Feature.AfterVersion = 2
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal("invalid observation fixture", err)
	}
	return passkey.UpdateResult{CommandID: receipt.Binding.CommandID, Outcome: outcome, Receipt: receipt}
}

func TestUpdateRetainsExactDurabilityAndOmitsHistoricalMetadata(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "unknown", "committed-error", "expired-delivery", "foreign-receipt", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, _, cookie, csrf := updateFixture(t)
			out := updateObservation(t, identity.CommitOutcomeCommitted)
			out.Credential = &passkey.CredentialMetadata{ReferenceID: "AAAAAAAAAAAAAAAAAAAAAg", Version: 2, State: "active", Label: "Personal key", CreatedAt: c.Now().Add(-time.Minute)}
			now := c.Now()
			c.Now = func() time.Time { return now }
			status := 200
			outcome := "committed"
			switch mode {
			case "replay":
				out.Replayed = true
				out.Credential = nil
			case "unknown":
				out = updateObservation(t, identity.CommitOutcomeUnknown)
				owner.err = errors.New("private-database-failure")
				status = 503
				outcome = "unknown"
			case "committed-error":
				owner.err = errors.New("private-delivery-failure")
				status = 503
			case "expired-delivery":
				status = 503
			case "foreign-receipt":
				out.Receipt.Binding.RecordID = "AAAAAAAAAAAAAAAAAAAABA"
				status = 503
				outcome = ""
			case "wrong-version":
				out.Credential.Version = 3
				status = 503
			}
			owner.result = &out
			h, err := NewUpdateHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				if mode == "expired-delivery" {
					now = now.Add(21 * time.Second)
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
			var body struct {
				CommandID     identity.CommandID  `json:"commandID"`
				CommitOutcome string              `json:"commitOutcome"`
				Replayed      bool                `json:"replayed"`
				Credential    *CredentialMetadata `json:"credential"`
			}
			if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.CommitOutcome != outcome || strings.Contains(w.Body.String(), "private-") {
				t.Fatal("native outcome lost or misreported", mode, w.Code, w.Body.String())
			}
			if outcome != "" && body.CommandID != out.CommandID {
				t.Fatal("original command lost")
			}
			if mode == "fresh" {
				if body.Credential == nil || body.Credential.Version != 2 || body.Replayed {
					t.Fatal("fresh safe projection lost")
				}
			} else if body.Credential != nil {
				t.Fatal("failed/historical response exposed credential projection")
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("rename issued authentication")
			}
		})
	}
}

func TestUpdateFeatureSelectsOnlyItsRouteAndClosedWire(t *testing.T) {
	c, owner, _, _, cookie, csrf := updateFixture(t)
	f, err := NewFeature(FeatureConfig{Update: &c})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 || document.Paths["/v1/passkey/update"] == nil || strings.Contains(string(doc.JSON()), "__Host-identity_device") {
		t.Fatal("update selected unrelated capability or device ceremony")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
	if w.Code != 403 || owner.calls != 1 {
		t.Fatal("selected feature bypassed native denial", w.Code)
	}
	parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(doc.JSON())), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, replay := range []bool{false, true} {
		out := updateObservation(t, identity.CommitOutcomeCommitted)
		out.Replayed = replay
		if !replay {
			out.Credential = &passkey.CredentialMetadata{ReferenceID: "AAAAAAAAAAAAAAAAAAAAAg", Version: 2, State: "active", Label: "Personal key", CreatedAt: c.Now().Add(-time.Minute)}
		}
		owner.result = &out
		w := httptest.NewRecorder()
		h.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
		if w.Code != 200 {
			t.Fatal("safe projection not served", w.Code, w.Body.String())
		}
		node := parsed.Raw()
		for _, key := range []string{"paths", "/v1/passkey/update", "post", "responses", "200", "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("actual response has no wire", key)
			}
		}
		instance, err := parse.JSON(t.Context(), strings.NewReader(w.Body.String()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("actual response rejected by selected wire", err)
		}
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	off.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "identity.passkey.update") || owner.calls != 3 {
		t.Fatal("disabled update retained capability")
	}
}

func TestUpdateRejectsAlternateAuthorityAndAmbiguousInputsBeforeNative(t *testing.T) {
	c, owner, proofs, _, cookie, csrf := updateFixture(t)
	h, err := NewUpdateHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") },
		func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43)) },
		func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrf) },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.URL.RawQuery = "userID=other" },
		func(r *http.Request) { r.Header.Add("Cookie", cookie.Name+"="+cookie.Value) },
	} {
		r := updateRequest(updateWire, cookie, csrf)
		mutate(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.calls != 0 {
			t.Fatal("invalid custody reached native", w.Code)
		}
	}
	for _, body := range []string{
		strings.Replace(updateWire, `"expectedVersion":1`, `"expectedVersion":0`, 1),
		strings.Replace(updateWire, `"expectedVersion":1`, `"expectedVersion":1.0`, 1),
		strings.Replace(updateWire, `"name":"Personal key"`, `"name":" "`, 1),
		strings.Replace(updateWire, `"name":"Personal key"`, `"name":"bad\nlabel"`, 1),
		strings.Replace(updateWire, `"name":"Personal key"`, `"name":null`, 1),
		strings.TrimSuffix(updateWire, "}") + `,"commandID":"AAAAAAAAAAAAAAAAAAAAAw"}`,
		strings.TrimSuffix(updateWire, "}") + `,"idempotencyKey":"other"}`,
		strings.TrimSuffix(updateWire, "}") + `,"tenantID":"other"}`,
		strings.TrimSuffix(updateWire, "}") + `,"name":"other"}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, updateRequest(body, cookie, csrf))
		if w.Code != 400 || owner.calls != 0 {
			t.Fatal("unbounded or overridden input reached native", w.Code)
		}
	}
	original := proofs.proof
	for _, partition := range []string{"action", "session", "session-version", "tenant", "subject"} {
		proofs.proof = original
		switch partition {
		case "action":
			proofs.proof.Action = "identity.passkey.register-verify"
		case "session":
			proofs.proof.SessionID = "another-session"
		case "session-version":
			proofs.proof.SessionVersion++
		case "tenant":
			proofs.proof.Proof.Tenant = "another-tenant"
		case "subject":
			proofs.proof.Proof.Subject = "another-user"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, updateRequest(updateWire, cookie, csrf))
		if w.Code != 403 || owner.calls != 0 {
			t.Fatal("foreign original proof reached native update", partition, w.Code)
		}
	}
}
