package apikeyhttp

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func wireFixtureResult(t *testing.T, f fixture, action string, outcome identity.CommitOutcome, empty bool) (apikey.IssuanceResult, identity.CommandResult) {
	t.Helper()
	c, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "automation", Revision: 1, State: apikey.ConfigurationActive, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api", PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: time.Second, ClockUncertainty: time.Second, DecisionRaceBudget: time.Second, Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	command, _ := identity.NewCommandID()
	schema := "apikey-" + action + "-v1"
	if action == "delete" {
		schema = "apikey-revoke-v1"
	}
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey." + action, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	id := apikey.KeyID("issued-key")
	if action == "delete" {
		id = "key-a"
	}
	r := identity.CommandResult{Binding: identity.CommandBinding{CommandID: command, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(id), SchemaID: schema, SchemaVersion: 1, PolicyID: "api-key", PolicyVersion: 1, CorrelationID: "native-correlation"}, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}
	if outcome == identity.CommitOutcomeCommitted {
		r.Feature.AfterVersion = 1
		r.AuditEventID = "audit"
		if action == "delete" {
			r.Feature.BeforeVersion, r.Feature.AfterVersion = 1, 2
		}
	}
	if r.Validate() != nil {
		t.Fatal("wire test receipt malformed")
	}
	if action == "delete" {
		return apikey.IssuanceResult{}, r
	}
	var record *apikey.Record
	if outcome == identity.CommitOutcomeCommitted {
		record = &apikey.Record{ID: id, Owner: owner, Version: 1, AuthorityVersion: 1, ConfigurationID: "automation", ConfigurationRevision: 1, Name: "consumer key", Status: apikey.KeyActive, Grant: []string{"read"}, CreatedAt: f.clock.now, ExpiresAt: f.clock.now.Add(24 * time.Hour), RootID: id, RootVersion: 1, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api"}
		if empty {
			record.Grant = nil
		}
		if action == "rotate" {
			record.PreviousID = "key-a"
		}
	}
	secret, _ := apikey.GenerateSecret()
	out, err := apikey.NewIssuanceResult(c, r, record, secret)
	if err != nil {
		t.Fatal("wire test issuance projection malformed", err)
	}
	return out, r
}

func TestCommittedIssuanceRevealsOnlyInvocationLocalMaterial(t *testing.T) {
	for _, action := range []string{"create", "rotate"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t)
			result, receipt := wireFixtureResult(t, f, action, identity.CommitOutcomeCommitted, false)
			f.native.issued = &result
			h := fixtureHandler(t, f)
			body := `{"keyID":"key-a","expectedVersion":1}`
			if action == "create" {
				body = `{"name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`
			}
			for attempt := range 2 {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, f.request(action, body))
				var out commandResponse
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.CommandID != receipt.Binding.CommandID || out.Recovery == nil || out.Key == nil || out.Key.ID != "issued-key" {
					t.Fatal("committed original outcome lost", w.Code)
				}
				if attempt == 0 {
					if _, err := apikey.ParseSecret(out.Secret); err != nil {
						t.Fatal("original committed material not delivered")
					}
				} else if out.Secret != "" {
					t.Fatal("copied/replayed result revealed again")
				}
			}
			if result.DeliveryOutcome() != apikey.IssuanceCommittedAndRevealed {
				t.Fatal("response bypassed sole reveal owner")
			}
		})
	}
}

func TestUnknownIssuancePreservesRecoveryWithoutPlaintext(t *testing.T) {
	f := newFixture(t)
	result, receipt := wireFixtureResult(t, f, "create", identity.CommitOutcomeUnknown, false)
	f.native.issued, f.native.err = &result, errors.New("private-provider-diagnostic")
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`))
	var out commandResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.Recovery == nil || out.Recovery.CommandID != receipt.Binding.CommandID || out.Key != nil || out.Secret != "" || strings.Contains(w.Body.String(), "private-provider") {
		t.Fatal("unknown became success/disclosure or lost original recovery", w.Code)
	}
}

func TestEmptyCommittedGrantRemainsAnArrayOnWire(t *testing.T) {
	f := newFixture(t)
	result, _ := wireFixtureResult(t, f, "create", identity.CommitOutcomeCommitted, true)
	f.native.issued = &result
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"name":"consumer key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`))
	var out struct {
		Key struct {
			Permissions json.RawMessage `json:"permissions"`
		} `json:"key"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || string(out.Key.Permissions) != "[]" {
		t.Fatal("empty native grant violated actual array wire contract", w.Code)
	}
}

func TestRevocationRejectsForeignReceiptWithoutDisclosingIt(t *testing.T) {
	for _, mutate := range []func(*identity.CommandResult){
		func(r *identity.CommandResult) { r.Binding.TenantID = "foreign" },
		func(r *identity.CommandResult) { r.Binding.UserID = "foreign" },
		func(r *identity.CommandResult) { r.Binding.RecordID = "foreign" },
		func(r *identity.CommandResult) { r.Feature.AfterVersion = 99 },
		func(r *identity.CommandResult) { r.Feature.BeforeVersion, r.Feature.AfterVersion = 7, 8 },
	} {
		f := newFixture(t)
		_, r := wireFixtureResult(t, f, "delete", identity.CommitOutcomeCommitted, false)
		mutate(&r)
		f.native.receipt = &r
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("delete", `{"keyID":"key-a","expectedVersion":1}`))
		if w.Code != 503 || strings.Contains(w.Body.String(), "foreign") || strings.Contains(w.Body.String(), string(r.Binding.CommandID)) {
			t.Fatal("foreign/contradictory receipt advertised commitment", w.Code)
		}
	}
}
