package postgres

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

func TestRPStartIntentDoesNotTreatNewAdmissionTimeAsNewIntent(t *testing.T) {
	p, now, _ := rpOutputFixture(t)
	s := p.service
	cfg := s.config()
	cfg.IntentKey = [32]byte{29}
	s.config = func() LinkServiceConfig { return cfg }
	var err error
	s.intentKey, err = session.NewDigestKey(1, bytes.Repeat([]byte{25}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.intentCSRF, err = session.NewCSRFKey(1, bytes.Repeat([]byte{26}, 32))
	if err != nil {
		t.Fatal(err)
	}
	callback, err := oauth.NewValidatedCallbackURL("https://app.example/complete", []string{"https://app.example/complete"})
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{27}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeSet([]string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-key"))
	if err != nil {
		t.Fatal(err)
	}
	r := oauth.LinkStartRequest{TenantID: "tenant", Provider: oauth.ProviderID(p.input.Provider), Session: authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{28}, 32))), CSRFToken: csrf, Callback: callback, ErrorCallback: callback, Scopes: scopes, SignupDisabled: true, Origin: "https://app.example", Network: "192.0.2.9", IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.account.link-start", Resource: authorization.Resource{Type: "identity.user", ID: "user"}, Environment: authorization.Environment{Time: *now}}}}
	if err := r.Validate(); err != nil {
		t.Fatal("valid original intent fixture", err)
	}
	original, err := s.startIntent(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Caller.Request.Environment.Time = now.Add(time.Second)
	retry, err := s.startIntent(r)
	want, _ := original.Fields()
	got, _ := retry.Fields()
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("admission clock rewrote original retry intent", err)
	}
	r.Caller.Request.Subject.ID, r.Caller.Request.Resource.ID = "other", "other"
	foreign, err := s.startIntent(r)
	changed, _ := foreign.Fields()
	if err != nil || reflect.DeepEqual(want, changed) {
		t.Fatal("another subject reused original intent")
	}
}
