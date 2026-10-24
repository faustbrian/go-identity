package passkeyhttp

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

func TestSessionDeletionWireMatchesSelectedPhasesAndActualResponses(t *testing.T) {
	c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
	f, err := NewFeature(FeatureConfig{SessionDeletion: &c})
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"proofID":`, "__Host-identity_device", "/v1/passkey/recover", "identity.passkey.update"} {
		if strings.Contains(string(document.JSON()), forbidden) {
			t.Fatal("unselected dependency or route advertised", forbidden)
		}
	}
	parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(document.JSON())), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	check := func(wire string, direction validate.InstanceDirection, valid bool) {
		t.Helper()
		node := parsed.Raw()
		keys := []string{"paths", "/v1/passkey/delete", "post"}
		if direction == validate.DirectionRequest {
			keys = append(keys, "requestBody", "content", "application/json", "schema")
		} else {
			keys = append(keys, "responses", "200", "content", "application/json", "schema")
		}
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
		if err != nil || report.Valid() != valid {
			t.Fatal("wire disagreed with selected request/result", err)
		}
	}
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		genuineWire := strings.Replace(wire, `{"id":"untrusted"}`, `{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"AQ","authenticatorData":"AQ","signature":"AQ"}}`, 1)
		check(genuineWire, validate.DirectionRequest, true)
		for _, override := range []string{`"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"idempotencyKey":"other"`, `"tenantID":"other"`, `"rpID":"other"`, `"name":"other"`} {
			check(strings.Replace(genuineWire, "{", "{"+override+",", 1), validate.DirectionRequest, false)
		}
	}
	check(strings.Replace(sessionDeletionRecoverWire, `"recover"`, `"options"`, 1), validate.DirectionRequest, false)
	check(strings.Replace(sessionDeletionRecoverWire, `"recover"`, `"complete"`, 1), validate.DirectionRequest, false)
	owner.err = nil
	for _, phase := range []string{"options", "options-replay", "complete", "complete-replay", "recover"} {
		wire := sessionDeletionCompleteWire
		out := sessionDeletionObservation(t, identity.CommitOutcomeCommitted, strings.HasPrefix(phase, "options"))
		if strings.HasPrefix(phase, "options") {
			wire = sessionDeletionOptionsWire
			owner.optionsResult = passkey.KeyedAssertionOptionsResult{CommandID: out.CommandID, Receipt: out.Receipt, Replayed: phase == "options-replay"}
			if phase == "options" {
				owner.optionsResult.Options = deletionProtocolOptions(t, c.Now())
			}
		} else {
			if phase == "recover" {
				wire = sessionDeletionRecoverWire
			}
			out.Replayed = phase != "complete"
			owner.result = passkey.NewSessionDeleteResult(out)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
		if w.Code != 200 {
			t.Fatal("actual selected wire failed", phase, w.Code)
		}
		check(w.Body.String(), validate.DirectionResponse, true)
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	off.ServeHTTP(w, deletionRequest(sessionDeletionOptionsWire, cookie, csrf))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "identity.passkey.delete") {
		t.Fatal("disabled deletion retained route or metadata")
	}
	legacy, _, _, _, _ := deletionFixture(t)
	legacyFeature, err := NewFeature(FeatureConfig{Delete: &legacy})
	if err != nil {
		t.Fatal(err)
	}
	_, legacyDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{legacyFeature}})
	if err != nil || !strings.Contains(string(legacyDoc.JSON()), `"proofID":`) || strings.Contains(string(legacyDoc.JSON()), `"phase":`) {
		t.Fatal("legacy deletion profile changed")
	}
}

func TestSessionDeletionEveryPhaseRetainsSharedSecretRateDenial(t *testing.T) {
	for _, wire := range []string{sessionDeletionOptionsWire, sessionDeletionCompleteWire, sessionDeletionRecoverWire} {
		for _, unavailable := range []bool{false, true} {
			c, owner, _, _, cookie, csrf := sessionDeletionFixture(t)
			store, err := memory.New(memory.Options{MaxKeys: 32, Shards: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			backend := &deletionRateBackend{parserRates: &parserRates{store}, unavailable: unavailable}
			c.Rate, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "session-delete-denial", Key: [32]byte{9}, Now: c.Now, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Rate.Close() })
			h, err := NewSessionDeletionHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(wire, cookie, csrf))
			want := 429
			if unavailable {
				want = 503
			}
			if w.Code != want || owner.options+owner.completions+owner.recoveries != 0 || backend.calls != 1 {
				t.Fatal("shared secret admission bypassed", w.Code)
			}
			if !unavailable && w.Header().Get("Retry-After") != "60" {
				t.Fatal("rate retry metadata changed")
			}
		}
	}
}

func TestSessionDeletionStateNestedDiagnosticsCannotTraverseCustody(t *testing.T) {
	s := SessionDeletionState{value: func() *sessionDeletionState {
		return &sessionDeletionState{body: requestBody{response: json.RawMessage(`{"private-assertion":"do-not-print"}`)}}
	}}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		// fmt skips nested Formatter methods for unexported enclosing fields.
		if strings.Contains(fmt.Sprintf(verb, struct{ state SessionDeletionState }{s}), "private-assertion") {
			t.Fatal("nested diagnostics traversed original custody")
		}
	}
}
