package magiclink_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/magiclink"
)

func requestInput(t *testing.T) magiclink.RequestRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("synthetic-magiclink-request"))
	if err != nil {
		t.Fatal(err)
	}
	return magiclink.RequestRequest{TenantID: "tenant-one", CommandID: id, Email: " MixedCase@example.test ", Intent: magiclink.SignInOnly, Callback: "https://app.example.test/return", IdempotencyKey: key, PreAuthID: flow, Cookie: auth.NewBearerCredential("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"), Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant-one", Action: "identity.magic-link.request", Subject: authorization.Subject{ID: "public-ingress", Kind: authorization.SubjectServiceAccount}}}, Origin: "https://app.example.test", Network: "192.0.2.1", Device: "synthetic-device"}
}

func TestRequestPreservesOriginalUnnormalizedIntent(t *testing.T) {
	r := requestInput(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if string(r.Email) != " MixedCase@example.test " || r.Cookie.Token() != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB" {
		t.Fatal("structural admission modified input")
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("request serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "example.test") {
		t.Fatal("request diagnostics disclosed input")
	}
	for name, change := range map[string]func(*magiclink.RequestRequest){
		"zero tenant":     func(r *magiclink.RequestRequest) { r.TenantID = "" },
		"foreign caller":  func(r *magiclink.RequestRequest) { r.Caller.Request.Tenant = "foreign" },
		"purpose":         func(r *magiclink.RequestRequest) { r.Caller.Request.Action = "identity.password.reset-request" },
		"zero command":    func(r *magiclink.RequestRequest) { r.CommandID = "" },
		"zero key":        func(r *magiclink.RequestRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"zero flow":       func(r *magiclink.RequestRequest) { r.PreAuthID = "" },
		"zero cookie":     func(r *magiclink.RequestRequest) { r.Cookie = auth.BearerCredential{} },
		"zero intent":     func(r *magiclink.RequestRequest) { r.Intent = magiclink.IntentUnspecified },
		"unknown intent":  func(r *magiclink.RequestRequest) { r.Intent = 99 },
		"oversized email": func(r *magiclink.RequestRequest) { r.Email = email.AddressInput(strings.Repeat("a", 4097)) },
		"userinfo":        func(r *magiclink.RequestRequest) { r.Callback = "https://user@app.example.test/return" },
		"fragment":        func(r *magiclink.RequestRequest) { r.Callback += "#" },
		"invalid origin":  func(r *magiclink.RequestRequest) { r.Origin += "/path" },
	} {
		t.Run(name, func(t *testing.T) {
			rr := r
			rr.Caller = r.Caller.Clone()
			change(&rr)
			if err := rr.Validate(); err == nil {
				t.Fatal("invalid request admitted")
			}
		})
	}
}

func TestRequestAcknowledgementDoesNotClaimDelivery(t *testing.T) {
	r := requestInput(t)
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		out := magiclink.RequestResult{CommandID: r.CommandID, Outcome: outcome, Accepted: outcome == identity.CommitOutcomeCommitted}
		if err := out.Validate(); err != nil {
			t.Fatal(err)
		}
		out.Accepted = !out.Accepted
		if out.Validate() == nil {
			t.Fatal("invented acceptance admitted")
		}
	}
}
