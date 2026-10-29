package apikeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

// This owner proves transport mapping/projection, not durable authorization or
// mutation. Native and Reference PostgreSQL consumers prove those contracts.
type updateWireOwner struct {
	request apikey.UpdateRequest
	result  apikey.UpdateResult
	err     error
	calls   int
	after   func()
}

func (o *updateWireOwner) Update(_ context.Context, r apikey.UpdateRequest) (apikey.UpdateResult, error) {
	o.calls++
	o.request = r
	if o.after != nil {
		o.after()
	}
	return o.result, o.err
}

const updateJSON = `{"keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":["read"]}`

func updateFixture(t *testing.T) (fixture, *updateWireOwner) {
	t.Helper()
	f := newFixture(t)
	o := &updateWireOwner{err: apikey.ErrDenied}
	f.config.Create, f.config.Rotate, f.config.Revoke = false, false, false
	f.config.Update, f.config.Updater = true, o
	return f, o
}

func TestUpdateMapsOriginalKeyAndTrustedAuthority(t *testing.T) {
	f, o := updateFixture(t)
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
	if w.Code != 403 || o.calls != 1 || f.native.calls != 0 || f.rate.calls != 1 || f.sessions.calls != 1 {
		t.Fatal("selected update did not reach exactly its native owner", w.Code)
	}
	r := o.request
	if r.Validate() != nil || r.KeyID != "key-a" || r.ExpectedVersion != 1 || r.Name != "renamed" || len(r.Permissions) != 1 || r.Permissions[0] != "read" || r.Network != "198.51.100.1" || r.Authentication.TenantID != "tenant-a" || r.Authentication.Bearer.Token() != f.token {
		t.Fatal("update lost exact intent or trusted transport mapping")
	}
	key, _ := identity.NewIdempotencyKey([]byte("original-apikey-command"))
	want, _ := key.Digest([32]byte{1})
	actual, digestErr := r.IdempotencyKey.Digest([32]byte{1})
	if digestErr != nil || actual != want {
		t.Fatal("HTTP replaced the original request key")
	}
}

func TestUpdateClosedInputAndSelection(t *testing.T) {
	for _, body := range []string{
		`{"keyID":"key-a","expectedVersion":1,"name":"renamed"}`,
		`{"keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":null}`,
		`{"keyID":"key-a","expectedVersion":1,"name":"","permissions":[]}`,
		`{"keyID":"key-a","expectedVersion":1e0,"name":"renamed","permissions":[]}`,
		`{"keyID":"key-a","expectedVersion":18446744073709551615,"name":"renamed","permissions":[]}`,
		`{"keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":["write","read"]}`,
		`{"keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":["read","read"]}`,
		`{"keyID":"key-a","expectedVersion":1,"name":"renamed","name":"other","permissions":[]}`,
		`{"KeyID":"key-a","expectedVersion":1,"name":"renamed","permissions":[]}`,
		strings.TrimSuffix(updateJSON, "}") + `,"expiresAt":"2027-01-01T00:00:00Z"}`,
		strings.TrimSuffix(updateJSON, "}") + `,"ownerID":"other"}`,
		strings.TrimSuffix(updateJSON, "}") + `,"organizationID":"org-a"}`,
	} {
		f, o := updateFixture(t)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("update", body))
		if w.Code != 400 || o.calls != 0 || f.sessions.calls != 0 || f.rate.calls != 0 {
			t.Fatal("invalid update reached authority", w.Code)
		}
	}
	f, o := updateFixture(t)
	f.config.Update, f.config.Create = false, true
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
	if w.Code != 404 || o.calls != 0 || f.sessions.calls != 0 {
		t.Fatal("disabled update acquired authority", w.Code)
	}
	for _, absent := range []apikey.Updater{nil, (*updateWireOwner)(nil)} {
		f, _ := updateFixture(t)
		f.config.Updater = absent
		if _, err := NewFeature(f.config); err == nil {
			t.Fatal("selected update accepted missing native owner")
		}
	}
}

func committedUpdate(t *testing.T, f fixture, organization bool) apikey.UpdateResult {
	t.Helper()
	_, receipt := wireFixtureResult(t, f, "delete", identity.CommitOutcomeCommitted, false)
	receipt.Binding.OperationID = "identity.apikey.update"
	receipt.Binding.SchemaID = "apikey-update-v1"
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	if organization {
		receipt.Binding.SchemaID = "apikey-update-organization-v1"
		owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-a", Version: 1})
	}
	receipt.Feature.Operation.OperationID, receipt.Feature.Operation.SchemaID = receipt.Binding.OperationID, receipt.Binding.SchemaID
	record := &apikey.Record{ID: "key-a", Owner: owner, Version: 2, AuthorityVersion: 1, ConfigurationID: "automation", ConfigurationRevision: 1, Name: "renamed", Status: apikey.KeyActive, Grant: []string{"read"}, CreatedAt: f.clock.now.Add(-time.Hour), RootID: "key-a", RootVersion: 1, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api"}
	return apikey.UpdateResult{Receipt: receipt, Record: record, ConfigurationAuthority: &apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: "automation", Version: 1}}
}

func TestUpdateProjectsOnlyCommittedOriginalMetadata(t *testing.T) {
	for _, organization := range []bool{false, true} {
		f, o := updateFixture(t)
		o.result, o.err = committedUpdate(t, f, organization), nil
		f.config.OrganizationOwned = organization
		body := updateJSON
		if organization {
			body = strings.TrimSuffix(body, "}") + `,"organizationID":"org-a"}`
		}
		for range 2 {
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, f.request("update", body))
			var out struct {
				Committed bool            `json:"committed"`
				Key       metadataKeyView `json:"key"`
				Recovery  *recoveryScope  `json:"recovery"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.Key.ID != "key-a" || out.Key.Version != 2 || out.Key.Name != "renamed" || out.Key.ExpiresAt != nil || out.Recovery == nil || out.Recovery.CommandID != o.result.Receipt.Binding.CommandID {
				t.Fatal("update lost original committed snapshot", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), `"secret"`) || strings.Contains(w.Body.String(), `"digest"`) || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("metadata mutation disclosed material or ambient credential")
			}
		}
		if o.request.OrganizationID != "" && !organization || organization && o.request.OrganizationID != "org-a" {
			t.Fatal("explicit organization target lost")
		}
	}
}

func TestUpdateUnknownPreservesOriginalRecoveryWithoutSnapshot(t *testing.T) {
	f, o := updateFixture(t)
	o.result = committedUpdate(t, f, false)
	o.result.Receipt.Outcome = identity.CommitOutcomeUnknown
	o.result.Receipt.Feature.BeforeVersion, o.result.Receipt.Feature.AfterVersion = 0, 0
	o.result.Receipt.AuditEventID = ""
	o.result.Record, o.result.ConfigurationAuthority = nil, nil
	o.err = errors.New("private-update-diagnostic")
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
	var out commandResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.Recovery == nil || out.Recovery.CommandID != o.result.Receipt.Binding.CommandID || out.Key != nil || out.Secret != "" || strings.Contains(w.Body.String(), "private-update") {
		t.Fatal("unknown update lost custody", w.Code)
	}
}

func TestUpdateRejectsContradictoryCommittedOwnerAndVersion(t *testing.T) {
	for _, mutate := range []func(*apikey.UpdateResult){
		func(r *apikey.UpdateResult) {
			r.Receipt.Binding.SchemaID = "apikey-create-v1"
			r.Receipt.Feature.Operation.SchemaID = r.Receipt.Binding.SchemaID
		},
		func(r *apikey.UpdateResult) { r.Receipt.Binding.RecordID = "other" },
		func(r *apikey.UpdateResult) {
			r.Receipt.Binding.SchemaVersion = 2
			r.Receipt.Feature.Operation.SchemaVersion = 2
		},
		func(r *apikey.UpdateResult) { r.Receipt.Feature.BeforeVersion, r.Receipt.Feature.AfterVersion = 7, 8 },
		func(r *apikey.UpdateResult) { r.Record.Version = 3 },
		func(r *apikey.UpdateResult) { r.Record.Name = "another intent" },
		func(r *apikey.UpdateResult) { r.Record.Grant = []string{"write"} },
		func(r *apikey.UpdateResult) { r.Record.Status = apikey.KeyRevoked },
		func(r *apikey.UpdateResult) { r.Record = nil },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority = nil },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority.Version = 0 },
		func(r *apikey.UpdateResult) { r.ConfigurationAuthority.TenantID = "other" },
		func(r *apikey.UpdateResult) {
			r.Record.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-b", Version: 1})
		},
	} {
		f, o := updateFixture(t)
		o.result, o.err = committedUpdate(t, f, false), nil
		mutate(&o.result)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
		var out commandResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.Key != nil || out.Secret != "" {
			t.Fatal("contradictory snapshot escaped boundary", w.Code)
		}
	}
}

func TestUpdateRequiresOriginalBearerKeyAndFreshAdmission(t *testing.T) {
	for _, change := range []func(*fixture){
		func(f *fixture) { f.sessions.value.Active = false },
		func(f *fixture) { f.clock.now = f.clock.now.Add(21 * time.Second) },
		func(f *fixture) { f.rate.mode = 1 },
		func(f *fixture) { f.rate.mode = 2 },
	} {
		f, o := updateFixture(t)
		change(&f)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
		if w.Code < 400 || o.calls != 0 {
			t.Fatal("unavailable authority/rate reached update", w.Code)
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Cookie", "session=ambient") },
		func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", r.Header.Get("Idempotency-Key")) },
		func(r *http.Request) { r.URL.RawQuery = "tenantID=other" },
		func(r *http.Request) { r.Host = "other.example" },
		func(r *http.Request) { r.TLS = nil },
	} {
		f, o := updateFixture(t)
		r := f.request("update", updateJSON)
		change(r)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, r)
		if w.Code < 400 || o.calls != 0 || f.sessions.calls != 0 || f.rate.calls != 0 {
			t.Fatal("untrusted update reached authority", w.Code)
		}
	}
}

func TestUpdateExplicitEmptyGrantAndOriginalResponseDeadline(t *testing.T) {
	f, o := updateFixture(t)
	o.result, o.err = committedUpdate(t, f, false), nil
	o.result.Record.Grant = []string{}
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("update", strings.Replace(updateJSON, `["read"]`, `[]`, 1)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"permissions":[]`) {
		t.Fatal("explicit deny-all became omitted or null", w.Code)
	}
	o.result = committedUpdate(t, f, false)
	o.after = func() { f.clock.now = f.clock.now.Add(21 * time.Second) }
	w = httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("update", updateJSON))
	var out commandResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.Key != nil || out.Recovery == nil || out.Recovery.CommandID != o.result.Receipt.Binding.CommandID {
		t.Fatal("expired response evidence disclosed snapshot or lost recovery", w.Code)
	}
}

func FuzzUpdateBody(f *testing.F) {
	f.Add(false, updateJSON)
	f.Add(true, `{"organizationID":"org-a","keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":[]}`)
	f.Add(false, `{"keyID":"key-a","expectedVersion":1,"name":"renamed","permissions":null}`)
	f.Add(false, `{"keyID":"key-a","expectedVersion":1e0,"name":"renamed","permissions":[]}`)
	f.Fuzz(func(t *testing.T, organization bool, body string) {
		if len(body) > 65536 {
			return
		}
		fixture, owner := updateFixture(t)
		fixture.config.OrganizationOwned = organization
		w := httptest.NewRecorder()
		fixtureHandler(t, fixture).ServeHTTP(w, fixture.request("update", body))
		if w.Code != 400 && w.Code != 403 || owner.calls > 1 || fixture.native.calls != 0 || fixture.sessions.calls > 1 || fixture.rate.calls > 1 || strings.Contains(w.Body.String(), fixture.token) || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("hostile update escaped bounded native-denial contract", w.Code)
		}
	})
}
