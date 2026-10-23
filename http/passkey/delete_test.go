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
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This double observes only the transport's borrowed native call. Genuine
// proof consumption/removal/session effects require the separate PG journey.
type observedDeletion struct {
	calls int
	last  passkey.DeleteRequest
	out   passkey.DeleteResult
	err   error
}

func (d *observedDeletion) Delete(_ context.Context, r passkey.DeleteRequest) (passkey.DeleteResult, error) {
	d.calls++
	d.last = r
	return d.out, d.err
}

func deletionFixture(t *testing.T) (DeleteConfig, *observedDeletion, *deniedEnrollment, *http.Cookie, string) {
	t.Helper()
	u, _, proofs, _, cookie, csrf := updateFixture(t)
	proofs.proof.Action = "identity.passkey.delete"
	d := &observedDeletion{err: identity.ForbiddenError{}}
	return DeleteConfig{Network: u.Network, Sessions: u.Sessions, Proofs: proofs, Service: d, Rate: u.Rate, Origin: u.Origin, SessionCookie: u.SessionCookie, CSRFKeys: u.CSRFKeys, PolicyRevision: u.PolicyRevision, Audience: u.Audience, Now: u.Now, MaximumDuration: u.MaximumDuration}, d, proofs, cookie, csrf
}

const deleteWire = `{"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","referenceID":"AAAAAAAAAAAAAAAAAAAAAg","expectedVersion":1}`

func deletionRequest(body string, cookie *http.Cookie, csrf string) *http.Request {
	r := registrationRequest("delete", body, cookie, nil, csrf)
	r.Header.Set("Idempotency-Key", "original-passkey-delete")
	return r
}

func TestDeletePreservesOriginalSessionProofAndKey(t *testing.T) {
	c, owner, proofs, cookie, csrf := deletionFixture(t)
	h, err := NewDeleteHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, deletionRequest(deleteWire, cookie, csrf))
	if w.Code != 403 || owner.calls != 1 {
		t.Fatal("native denial bypassed", w.Code, owner.calls)
	}
	r := owner.last
	if r.Primary.Proof != proofs.proof || r.Primary.CommandID != "" || r.Primary.RecordID != "" || r.Primary.TargetSubjectID != "" || r.Primary.Caller.Request.Subject.ID != "user-a" || r.Primary.Caller.Request.Action != "identity.passkey.delete" || r.ReferenceID != "AAAAAAAAAAAAAAAAAAAAAg" || r.ExpectedVersion != 1 || r.Network != "198.51.100.7" {
		t.Fatal("original deletion custody changed", r)
	}
	want, _ := identity.NewIdempotencyKey([]byte("original-passkey-delete"))
	a, err := r.IdempotencyKey.Digest([32]byte{1})
	b, _ := want.Digest([32]byte{1})
	if err != nil || a != b {
		t.Fatal("original key replaced")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("deletion changed authentication transport")
	}
	// Imported canonical references remain exact owner locators; they are not
	// newly allocated command IDs or raw authenticator credential bytes.
	body := strings.Replace(deleteWire, "AAAAAAAAAAAAAAAAAAAAAg", "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, deletionRequest(body, cookie, csrf))
	if w.Code != 403 || owner.calls != 2 || owner.last.ReferenceID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatal("imported canonical reference changed", w.Code)
	}
}

func TestDeleteRejectsAlternateAuthorityAndAmbiguousInput(t *testing.T) {
	c, owner, proofs, cookie, csrf := deletionFixture(t)
	h, err := NewDeleteHandler(c)
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
		r := deletionRequest(deleteWire, cookie, csrf)
		mutate(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || owner.calls != 0 {
			t.Fatal("invalid custody reached deletion", w.Code)
		}
	}
	for _, body := range []string{
		strings.Replace(deleteWire, `:1`, `:0`, 1), strings.Replace(deleteWire, `:1`, `:1.0`, 1),
		strings.Replace(deleteWire, `:1`, `:18446744073709551615`, 1), strings.Replace(deleteWire, `:1`, `:null`, 1),
		strings.Replace(deleteWire, `"referenceID":"AAAAAAAAAAAAAAAAAAAAAg"`, `"referenceID":"invalid\nreference"`, 1),
		strings.TrimSuffix(deleteWire, "}") + `,"expectedVersion":2}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(body, cookie, csrf))
		if w.Code != 400 || owner.calls != 0 {
			t.Fatal("malformed deletion reached owner", w.Code)
		}
	}
	for _, field := range []string{"name", "userID", "tenantID", "actorID", "rpID", "commandID", "idempotencyKey", "recoveryAllowed"} {
		body := strings.TrimSuffix(deleteWire, "}") + `,"` + field + `":"untrusted"}`
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(body, cookie, csrf))
		if w.Code != 400 || owner.calls != 0 {
			t.Fatal("body supplied authority", field, w.Code)
		}
	}
	original := proofs.proof
	for _, partition := range []string{"action", "session", "version", "tenant", "subject", "purpose", "id"} {
		proofs.proof = original
		switch partition {
		case "action":
			proofs.proof.Action = "identity.passkey.update"
		case "session":
			proofs.proof.SessionID = "other"
		case "version":
			proofs.proof.SessionVersion++
		case "tenant":
			proofs.proof.Proof.Tenant = "other"
		case "subject":
			proofs.proof.Proof.Subject = "other"
		case "purpose":
			proofs.proof.Proof.Purpose = "other"
		case "id":
			proofs.proof.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAw"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(deleteWire, cookie, csrf))
		if w.Code != 403 || owner.calls != 0 {
			t.Fatal("foreign proof admitted", partition, w.Code)
		}
	}
}

func deletionObservation(t *testing.T, outcome identity.CommitOutcome) passkey.DeleteResult {
	t.Helper()
	seedOutcome := outcome
	if outcome == identity.CommitOutcomeInProgress {
		seedOutcome = identity.CommitOutcomeUnknown
	}
	u := updateObservation(t, seedOutcome)
	u.Outcome, u.Receipt.Outcome = outcome, outcome
	if outcome == identity.CommitOutcomeInProgress {
		u.Receipt.RetryAfter = time.Second
	}
	u.Receipt.Binding.OperationID = "identity.passkey.delete"
	u.Receipt.Binding.SchemaID = "identity.passkey.delete.native-v1"
	u.Receipt.Feature.Operation.OperationID = "identity.passkey.delete"
	u.Receipt.Feature.Operation.SchemaID = "identity.passkey.delete.native-v1"
	if err := u.Receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	return passkey.DeleteResult{CommandID: u.CommandID, Outcome: u.Outcome, Receipt: u.Receipt}
}

func TestDeleteProjectsOnlyBoundOriginalDurability(t *testing.T) {
	for _, mode := range []string{"fresh", "independent-versions", "replay", "unknown", "not-committed", "conflict", "in-progress", "committed-error", "expired-delivery", "foreign-receipt", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, cookie, csrf := deletionFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			out := deletionObservation(t, identity.CommitOutcomeCommitted)
			status, outcome := 200, "committed"
			owner.err = nil
			switch mode {
			case "independent-versions":
				out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = 5, 6
			case "replay":
				out.Replayed = true
			case "unknown":
				out = deletionObservation(t, identity.CommitOutcomeUnknown)
				owner.err = identity.UnknownCommitError{CommandID: out.CommandID}
				status, outcome = 503, "unknown"
			case "not-committed":
				out = deletionObservation(t, identity.CommitOutcomeNotCommitted)
				owner.err = identity.NotCommittedError{CommandID: out.CommandID}
				status, outcome = 503, "not_committed"
			case "conflict":
				out = deletionObservation(t, identity.CommitOutcomeConflict)
				owner.err = identity.ConflictError{CommandID: out.CommandID}
				status, outcome = 409, "conflict"
			case "in-progress":
				out = deletionObservation(t, identity.CommitOutcomeInProgress)
				out.Receipt.RetryAfter = time.Second
				owner.err = identity.InProgressError{CommandID: out.CommandID, RetryAfter: time.Second}
				status, outcome = 409, "in_progress"
			case "committed-error":
				owner.err = identity.UnavailableError{}
				status = 503
			case "expired-delivery":
				status = 503
			case "foreign-receipt":
				out.Receipt.Binding.UserID = "other"
				status, outcome = 503, ""
			case "wrong-version":
				out.Receipt.Feature.AfterVersion++
				status, outcome = 503, ""
			}
			owner.out = out
			h, err := NewDeleteHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				if mode == "expired-delivery" {
					now = now.Add(21 * time.Second)
				}
			})})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(deleteWire, cookie, csrf))
			var body struct {
				CommandID     identity.CommandID `json:"commandID"`
				CommitOutcome string             `json:"commitOutcome"`
				Replayed      bool               `json:"replayed"`
			}
			if w.Code != status || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.CommitOutcome != outcome {
				t.Fatal("durability changed", mode, w.Code, w.Body.String())
			}
			if outcome != "" && body.CommandID != out.CommandID {
				t.Fatal("original command lost")
			}
			if status == 200 && body.Replayed != out.Replayed {
				t.Fatal("replay changed")
			}
			if strings.Contains(w.Body.String(), "credential") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("deletion exposed material or changed session")
			}
		})
	}
}

func TestDeleteFeatureClosedWireAndDefaultOff(t *testing.T) {
	c, owner, _, cookie, csrf := deletionFixture(t)
	f, err := NewFeature(FeatureConfig{Delete: &c})
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
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 || document.Paths["/v1/passkey/delete"] == nil || strings.Contains(string(doc.JSON()), "__Host-identity_device") {
		t.Fatal("deletion exposed unselected capability")
	}
	parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(doc.JSON())), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	wireRequest := strings.Replace(deleteWire, "AAAAAAAAAAAAAAAAAAAAAg", "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1)
	for _, replay := range []bool{false, true} {
		owner.out = deletionObservation(t, identity.CommitOutcomeCommitted)
		owner.out.Receipt.Binding.RecordID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
		owner.out.Replayed = replay
		owner.err = nil
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deletionRequest(wireRequest, cookie, csrf))
		if w.Code != 200 {
			t.Fatal("selected deletion did not project", w.Code, w.Body.String())
		}
		for _, part := range []string{"requestBody", "responses"} {
			node := parsed.Raw()
			path := []string{"paths", "/v1/passkey/delete", "post", part}
			if part == "responses" {
				path = append(path, "200")
			}
			path = append(path, "content", "application/json", "schema")
			for _, key := range path {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("missing concrete deletion schema", key)
				}
			}
			wire := wireRequest
			if part == "responses" {
				wire = w.Body.String()
			}
			instance, err := parse.JSON(t.Context(), strings.NewReader(wire), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
			if err != nil || !report.Valid() {
				t.Fatal("actual deletion wire rejected", part, err)
			}
			for _, field := range []string{"credential", "name", "session", "recoveryAllowed"} {
				bad := strings.TrimSuffix(strings.TrimSpace(wire), "}") + `,"` + field + `":"untrusted"}`
				instance, err := parse.JSON(t.Context(), strings.NewReader(bad), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire accepts unowned payload", part, field)
				}
			}
		}
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	off.ServeHTTP(w, deletionRequest(deleteWire, cookie, csrf))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "identity.passkey.delete") || owner.calls != 2 {
		t.Fatal("disabled deletion retained capability")
	}
}

func TestDeleteRejectsMissingOwnersAndPrivateExport(t *testing.T) {
	c, _, _, _, _ := deletionFixture(t)
	for _, mutate := range []func(*DeleteConfig){
		func(c *DeleteConfig) { c.Sessions = nil }, func(c *DeleteConfig) { c.Proofs = nil }, func(c *DeleteConfig) { c.Service = nil },
		func(c *DeleteConfig) { c.Rate = nil }, func(c *DeleteConfig) { c.Now = nil }, func(c *DeleteConfig) { c.PolicyRevision = 0 },
		func(c *DeleteConfig) { c.Audience = "" }, func(c *DeleteConfig) { c.MaximumDuration = 0 }, func(c *DeleteConfig) { c.MaximumDuration = 31 * time.Second },
		func(c *DeleteConfig) { c.CSRFKeys = nil }, func(c *DeleteConfig) { c.CSRFKeys = []session.CSRFKey{{}} },
		func(c *DeleteConfig) { c.CSRFKeys = append(c.CSRFKeys, c.CSRFKeys[0]) },
	} {
		bad := c
		mutate(&bad)
		if h, err := NewDeleteHandler(bad); err == nil || h != nil {
			t.Fatal("invalid owner enabled deletion")
		}
	}
	for _, v := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{c, DeleteState{}} {
		if _, err := v.MarshalJSON(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("private JSON exported")
		}
		if _, err := v.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("private text exported")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, v), "tenant-a") {
				t.Fatal("diagnostic exported scope")
			}
		}
	}
}

// The strict backend is the external rate-authority seam. Its decision must
// flow through the actual shared limiter before this route can invoke native.
type deletionRateBackend struct {
	*parserRates
	unavailable bool
	calls       int
}

func (b *deletionRateBackend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	b.calls++
	if b.unavailable {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, request := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: false, Remaining: 0, Limit: request.Policy.Limit(), Reset: request.Now.Add(request.Policy.Period()), Reason: ratelimit.ReasonLimited, RetryAfter: time.Minute}
	}
	if err := ctx.Err(); err != nil {
		return ratelimit.AtomicBatchDecision{}, err
	}
	return out, ratelimit.ErrRejected
}

func TestDeleteRateDenialAndOutageNeverReachNative(t *testing.T) {
	for _, mode := range []string{"denied", "unavailable", "closed"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, _, cookie, csrf := deletionFixture(t)
			store, err := memory.New(memory.Options{MaxKeys: 32, Shards: 1})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			backend := &deletionRateBackend{parserRates: &parserRates{store}, unavailable: mode == "unavailable"}
			c.Rate, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "delete-denial", Key: [32]byte{9}, Now: c.Now, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Rate.Close() })
			h, err := NewDeleteHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "closed" {
				if err := c.Rate.Close(); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deletionRequest(deleteWire, cookie, csrf))
			want := 503
			if mode == "denied" {
				want = 429
			}
			calls := 1
			if mode == "closed" {
				calls = 0
			}
			if w.Code != want || owner.calls != 0 || backend.calls != calls {
				t.Fatal("failed shared admission reached removal", mode, w.Code, owner.calls, backend.calls)
			}
			if mode == "denied" && w.Header().Get("Retry-After") != "60" {
				t.Fatal("shared denial lost retry bound")
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("rate denial changed authentication")
			}
		})
	}
}
