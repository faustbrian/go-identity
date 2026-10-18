package username_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/username"
)

func renameRequest(t *testing.T) username.RenameRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-username-rename"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	return username.RenameRequest{TenantID: "tenant", IdentifierID: "username", ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 3, Username: "Straße", IdempotencyKey: key, Session: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"), Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant", Subject: "user", Purpose: "identity.password.verify", Audience: "username-rename", Method: "password", Assurance: auth.AssuranceSingleFactor, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}, SessionID: "session", SessionVersion: 1, Action: "identity.username.update"}, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.username.update", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}}, Network: "192.0.2.1"}
}

func TestRenameRequestBindsOriginalSelfProofAndVersions(t *testing.T) {
	r := renameRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid original self rename denied", err)
	}
	for name, change := range map[string]func(*username.RenameRequest){
		"tenant":       func(r *username.RenameRequest) { r.TenantID = "foreign" },
		"actor":        func(r *username.RenameRequest) { r.Caller.Request.Subject.ID = "other" },
		"service":      func(r *username.RenameRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
		"resource":     func(r *username.RenameRequest) { r.Caller.Request.Resource.ID = "other" },
		"identifier":   func(r *username.RenameRequest) { r.IdentifierID = "" },
		"version":      func(r *username.RenameRequest) { r.ExpectedIdentifierVersion = 0 },
		"verification": func(r *username.RenameRequest) { r.ExpectedVerificationVersion = ^uint64(0) },
		"name":         func(r *username.RenameRequest) { r.Username = "" },
		"size":         func(r *username.RenameRequest) { r.Username = strings.Repeat("a", 129) },
		"key":          func(r *username.RenameRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"bearer":       func(r *username.RenameRequest) { r.Session = auth.BearerCredential{} },
		"proof":        func(r *username.RenameRequest) { r.Proof.Action = "identity.password.change" },
		"mfa":          func(r *username.RenameRequest) { r.Proof.Proof.Assurance = auth.AssuranceMultiFactor },
		"network":      func(r *username.RenameRequest) { r.Network = "spoofed" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			bad.Caller = r.Caller.Clone()
			change(&bad)
			if bad.Validate() == nil {
				t.Fatal("unbound original rename admitted")
			}
		})
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("implicit rename export")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, r); !strings.Contains(out, "redacted") || strings.Contains(out, r.Username) {
			t.Fatal("rename diagnostic disclosed input")
		}
	}
}
