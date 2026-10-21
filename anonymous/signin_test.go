package anonymous_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	"github.com/faustbrian/go-identity/session"
)

func signinRequest(t testing.TB) anonymous.SigninRequest {
	t.Helper()
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 5 * time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("synthetic-anonymous-attempt"))
	if err != nil {
		t.Fatal(err)
	}
	return anonymous.SigninRequest{TenantID: "tenant", PreAuthID: flow, Cookie: auth.NewBearerCredential(raw), Remember: remember, Origin: "https://example.test", Network: "192.0.2.1", Device: "device", IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "public-ingress"}, Action: "identity.anonymous.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.anonymous.signin"}}}}
}

func TestSigninRequestPreservesOriginalCustody(t *testing.T) {
	r := signinRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid original request", err)
	}
	originalCookie, originalRemember, originalKey := r.Cookie.Token(), r.Remember, r.IdempotencyKey
	for _, mutate := range []func(*anonymous.SigninRequest){
		func(r *anonymous.SigninRequest) { r.TenantID = "foreign" },
		func(r *anonymous.SigninRequest) { r.PreAuthID = "invalid" },
		func(r *anonymous.SigninRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *anonymous.SigninRequest) { r.Cookie = auth.NewBearerCredential(originalCookie + "=") },
		func(r *anonymous.SigninRequest) { r.Remember = session.RememberPolicy{} },
		func(r *anonymous.SigninRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *anonymous.SigninRequest) { r.Caller.Request.Action = "identity.password.signup" },
		func(r *anonymous.SigninRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectGroup },
		func(r *anonymous.SigninRequest) { r.Caller.PolicyRevision = 0 },
		func(r *anonymous.SigninRequest) {
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
		func(r *anonymous.SigninRequest) {
			r.Caller.Request.Attributes = authorization.Attributes{"oversize": authorization.StringValue(strings.Repeat("a", 4097))}
		},
		func(r *anonymous.SigninRequest) { r.Origin = "https://example.test\n" },
		func(r *anonymous.SigninRequest) { r.Origin = strings.Repeat("x", 2049) },
		func(r *anonymous.SigninRequest) { r.CallbackURL = strings.Repeat("x", 2049) },
		func(r *anonymous.SigninRequest) { r.Network = "192.0.2.001" },
		func(r *anonymous.SigninRequest) { r.Network = "fe80::1%en0" },
		func(r *anonymous.SigninRequest) { r.Device = "device\n" },
	} {
		changed := r
		changed.Caller = r.Caller.Clone()
		mutate(&changed)
		if changed.Validate() == nil {
			t.Fatal("invalid request admitted")
		}
	}
	if r.Cookie.Token() != originalCookie || r.Remember != originalRemember || r.IdempotencyKey != originalKey {
		t.Fatal("validation replaced original custody")
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("request implicitly serialized")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d"} {
		if text := fmt.Sprintf(format, r); strings.Contains(text, originalCookie) || strings.Contains(text, string(r.PreAuthID)) || strings.Contains(text, "192.0.2.1") {
			t.Fatal("request diagnostics leaked original input")
		}
	}
}

func TestSigninRecoveryRetainsAnonymousScope(t *testing.T) {
	r := signinRequest(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.anonymous.signin"}
	recovery, err := anonymous.NewSigninRecovery(q, r.PreAuthID)
	if err != nil {
		t.Fatal(err)
	}
	got, flow, err := recovery.Bindings()
	if err != nil || got != q || flow != r.PreAuthID {
		t.Fatal("original recovery correlation lost")
	}
	request := anonymous.SigninRecoveryRequest{Recovery: recovery, Cookie: r.Cookie, Caller: r.Caller.Clone(), Origin: r.Origin, Network: r.Network, Device: r.Device}
	if request.Validate() != nil {
		t.Fatal("original recovery denied")
	}
	changed := request
	changed.Caller = request.Caller.Clone()
	changed.Caller.Request.Subject.ID = "other-ingress"
	if changed.Validate() == nil {
		t.Fatal("different actor admitted to original recovery")
	}
	for _, mutate := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.UserID = "selected-user" },
		func(q *identity.RecoveryQuery) { q.OperationID = "identity.anonymous.upgrade" },
		func(q *identity.RecoveryQuery) { q.RecordID = "record" },
		func(q *identity.RecoveryQuery) { q.AnonymousFlowID = "foreign-flow" },
	} {
		other := q
		mutate(&other)
		if _, err := anonymous.NewSigninRecovery(other, r.PreAuthID); err == nil {
			t.Fatal("foreign recovery scope accepted")
		}
	}
	if _, _, err := (anonymous.SigninRecovery{}).Bindings(); err == nil {
		t.Fatal("zero recovery admitted")
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("recovery request serialized")
	}
	if _, err := json.Marshal(recovery); err == nil {
		t.Fatal("recovery correlation serialized implicitly")
	}
}
