package impersonationhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestDenialResponseRequiresExactNativeReceipt(t *testing.T) {
	operation := identity.FeatureOperation{
		Owner: "identity/impersonation", OperationID: "identity.impersonation.deny", SchemaID: "impersonation-deny",
		SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
	}
	correlation := identity.CommandBinding{
		CommandID: "AgICAgICAgICAgICAgICAg", TenantID: "tenant-a", UserID: "target", ActorID: "admin",
		ActorKind: authorization.SubjectUser, OperationID: operation.OperationID,
		PolicyID: "policy", PolicyVersion: 1, SchemaID: operation.SchemaID, SchemaVersion: 1,
		CorrelationID: "AgICAgICAgICAgICAgICAg", RecordID: "AAAAAAAAAAAAAAAAAAAAAQ",
	}
	for _, tc := range []struct {
		name     string
		change   func(*identity.CommandResult)
		status   int
		outcome  string
		disclose bool
	}{
		{"exact", func(*identity.CommandResult) {}, 200, "committed", true},
		{"other-actor", func(r *identity.CommandResult) { r.Binding.ActorID = "other" }, 503, "none", false},
		{"other-tenant", func(r *identity.CommandResult) { r.Binding.TenantID = "other" }, 503, "none", false},
		{"other-grant", func(r *identity.CommandResult) { r.Binding.RecordID = "AAAAAAAAAAAAAAAAAAAABA" }, 503, "none", false},
		{"wrong-transition", func(r *identity.CommandResult) { r.Feature.AfterVersion = 3 }, 503, "none", false},
		{"unknown", func(r *identity.CommandResult) {
			r.Outcome, r.AuditEventID = identity.CommitOutcomeUnknown, ""
			r.Feature.BeforeVersion, r.Feature.AfterVersion = 0, 0
		}, 503, "unknown", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := identity.CommandResult{Binding: correlation, Outcome: identity.CommitOutcomeCommitted,
				AuditEventID: "denial-audit", Feature: &identity.FeatureReceipt{Operation: operation, BeforeVersion: 1, AfterVersion: 2}}
			tc.change(&r)
			w := httptest.NewRecorder()
			writeDenial(t.Context(), w, correlation, r, nil)
			var body struct {
				Denied  bool
				Outcome string `json:"commitOutcome"`
				Command string `json:"commandID"`
				Grant   string `json:"grantID"`
			}
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != tc.status || body.Outcome != tc.outcome ||
				body.Denied != (tc.status == http.StatusOK) || (body.Command != "") != tc.disclose ||
				(body.Grant != "") != (tc.status == http.StatusOK) || len(w.Result().Cookies()) != 0 {
				t.Fatal("response disclosed a different, nonterminal, or unbound denial", w.Code, body)
			}
		})
	}
}
