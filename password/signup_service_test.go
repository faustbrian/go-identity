package password_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

func signupRecovery(t testing.TB) password.SignupRecovery {
	t.Helper()
	r := signupInput(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.password.signup", AnonymousFlowID: string(r.PreAuthID)}
	recovery, err := password.NewSignupRecovery(q, r.PreAuthID)
	if err != nil {
		t.Fatal("valid original anonymous signup recovery denied", err)
	}
	return recovery
}

func TestSignupRecoveryPreservesAnonymousOriginal(t *testing.T) {
	r := signupRecovery(t)
	q, flow, err := r.Bindings()
	if err != nil || q.UserID != "" || q.AnonymousFlowID != string(flow) || q.CommandID == "" {
		t.Fatal("signup retargeted original anonymous recovery", err)
	}
	q.UserID = "created-user"
	original, _, err := r.Bindings()
	if err != nil || original.UserID != "" {
		t.Fatal("recovery mutated through projection")
	}
}

func signupResult(t testing.TB, outcome identity.CommitOutcome) password.SignupResult {
	t.Helper()
	return password.SignupResult{Recovery: signupRecovery(t), Outcome: outcome}
}

func TestSignupResultVerificationAcknowledgementDoesNotAuthenticate(t *testing.T) {
	r := signupResult(t, identity.CommitOutcomeCommitted)
	r.VerificationRequired = true
	if err := r.Validate(); err != nil {
		t.Fatal("enumeration-safe verification acknowledgement denied", err)
	}
	r.VerificationRequired = false // Explicit session suppression also permits acknowledgement.
	if err := r.Validate(); err != nil {
		t.Fatal("session-suppressed acknowledgement denied", err)
	}
}

func TestSignupRecoveryRejectsRetargetedHistory(t *testing.T) {
	r := signupRecovery(t)
	q, flow, _ := r.Bindings()
	for _, mutate := range []func(*identity.RecoveryQuery){
		func(q *identity.RecoveryQuery) { q.CommandID = "bad" },
		func(q *identity.RecoveryQuery) { q.TenantID = "" },
		func(q *identity.RecoveryQuery) { q.ActorID = "" },
		func(q *identity.RecoveryQuery) { q.ActorKind = "unknown" },
		func(q *identity.RecoveryQuery) { q.OperationID = "identity.password.signin" },
		func(q *identity.RecoveryQuery) { q.RecordID = string(q.CommandID) },
		func(q *identity.RecoveryQuery) { q.LinkMode = 1 },
		func(q *identity.RecoveryQuery) { q.UserID = "created-user" },
		func(q *identity.RecoveryQuery) { q.AnonymousFlowID = "" },
		func(q *identity.RecoveryQuery) { q.AnonymousFlowID = "foreign" },
	} {
		bad := q
		mutate(&bad)
		if got, err := password.NewSignupRecovery(bad, flow); !errors.Is(err, password.ErrPasswordWork) || got != (password.SignupRecovery{}) {
			t.Fatal("invalid original recovery accepted")
		}
	}
	if _, err := password.NewSignupRecovery(q, "bad"); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("invalid flow accepted")
	}
	if _, _, err := (password.SignupRecovery{}).Bindings(); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero recovery accepted")
	}
}

func TestSignupRecoveryRequiresOriginalPossessionProvenance(t *testing.T) {
	r := signupInput(t)
	request := password.SignupRecoveryRequest{Recovery: signupRecovery(t), Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	if err := request.Validate(); err != nil {
		t.Fatal("valid recovery structure denied", err)
	}
	for _, mutate := range []func(*password.SignupRecoveryRequest){
		func(r *password.SignupRecoveryRequest) { r.Recovery = password.SignupRecovery{} },
		func(r *password.SignupRecoveryRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *password.SignupRecoveryRequest) { r.Caller.Request.Subject.ID = "foreign" },
		func(r *password.SignupRecoveryRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectUser },
		func(r *password.SignupRecoveryRequest) { r.Caller.Request.Action = "identity.password.signin" },
		func(r *password.SignupRecoveryRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *password.SignupRecoveryRequest) { r.Origin = "" },
		func(r *password.SignupRecoveryRequest) { r.Network = "192.000.2.1" },
		func(r *password.SignupRecoveryRequest) { r.Device = strings.Repeat("x", 129) },
	} {
		bad := request
		bad.Caller = request.Caller.Clone()
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("foreign/absent original recovery structure admitted")
		}
	}
}

func TestSignupResultClosedOutcomes(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeInvalid, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, 255} {
		r := signupResult(t, outcome)
		want := outcome != identity.CommitOutcomeInvalid && outcome != 255
		if (r.Validate() == nil) != want {
			t.Fatalf("outcome %d", outcome)
		}
		if !want {
			continue
		}
		for _, mutate := range []func(*password.SignupResult){
			func(r *password.SignupResult) { r.Recovery = password.SignupRecovery{} },
			func(r *password.SignupResult) { r.RetryAfter = -time.Second },
			func(r *password.SignupResult) { r.CSRFToken, _ = session.NewCSRFToken() },
			func(r *password.SignupResult) { r.SessionID = "orphan-session" },
			func(r *password.SignupResult) { r.Session.Replayed = true },
			func(r *password.SignupResult) { r.Session.Cookie.Name = "orphan-cookie" },
		} {
			bad := r
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("incoherent result accepted")
			}
		}
		r.RetryAfter = time.Second
		if (r.Validate() == nil) != (outcome == identity.CommitOutcomeInProgress) {
			t.Fatal("retry-after changed outcome semantics")
		}
		if outcome != identity.CommitOutcomeCommitted {
			r.RetryAfter = 0
			r.VerificationRequired = true
			if r.Validate() == nil {
				t.Fatal("unknown/denied registration asserted verification success")
			}
			r.VerificationRequired = false
			r.SubjectID = "user"
			if r.Validate() == nil {
				t.Fatal("noncommitted subject disclosure")
			}
		}
	}
	if (password.SignupResult{}).Validate() == nil {
		t.Fatal("zero result admitted")
	}
	r := signupResult(t, identity.CommitOutcomeCommitted)
	r.VerificationRequired = true
	r.SubjectID = "user"
	if r.Validate() == nil {
		t.Fatal("pending verification enumerated registered identity")
	}
}

func signupSessionResult(t testing.TB) password.SignupResult {
	t.Helper()
	r := signupResult(t, identity.CommitOutcomeCommitted)
	q, _, _ := r.Recovery.Bindings()
	r.SubjectID, r.SessionID = "user", "session"
	r.Session = session.IssueResult{CommandID: q.CommandID, CommitOutcome: r.Outcome, Session: signinSession(t)}
	return r
}

func TestSignupSessionUsesNativeCustodyAndSecretFreeHistory(t *testing.T) {
	r := signupSessionResult(t)
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	r.Session.Token, r.CSRFToken = token, csrf
	r.Session.Cookie.Name = "__Host-session"
	r.Session.Cookie.Path = "/"
	r.Session.Cookie.Secure = true
	r.Session.Cookie.HttpOnly = true
	if err := r.Validate(); err != nil {
		t.Fatal("fresh original session denied", err)
	}
	copy := r
	if _, err := copy.Session.Token.Reveal(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Session.Token.Reveal(); err == nil {
		t.Fatal("signup reconstructed bearer permission")
	}
	if _, err := copy.CSRFToken.Reveal(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CSRFToken.Reveal(); err == nil {
		t.Fatal("signup reconstructed csrf permission")
	}
	if r.Validate() != nil {
		t.Fatal("shape validation became reveal authority")
	}
	for _, mutate := range []func(*password.SignupResult){
		func(r *password.SignupResult) { r.Outcome = identity.CommitOutcomeUnknown },
		func(r *password.SignupResult) { r.VerificationRequired = true },
		func(r *password.SignupResult) { r.SubjectID = "foreign" },
		func(r *password.SignupResult) { r.SessionID = "foreign" },
		func(r *password.SignupResult) { r.Session.CommandID = "bad" },
		func(r *password.SignupResult) { r.Session.CommitOutcome = identity.CommitOutcomeUnknown },
		func(r *password.SignupResult) { r.Session.Replayed = true },
		func(r *password.SignupResult) { r.Session.RetryAfter = time.Second },
		func(r *password.SignupResult) { r.Session.Cookie.Value = "synthetic-secret" },
		func(r *password.SignupResult) { r.Session.Cookie.Raw = "synthetic-secret" },
		func(r *password.SignupResult) { r.Session.Cookie.Unparsed = []string{"synthetic-secret"} },
		func(r *password.SignupResult) { r.Session.Session = session.Session{} },
		func(r *password.SignupResult) { r.Session.Token = session.Token{} },
		func(r *password.SignupResult) { r.CSRFToken = session.CSRFToken{} },
		func(r *password.SignupResult) { r.Replayed = true },
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid session delivery accepted")
		}
	}
	history := signupSessionResult(t)
	history.Replayed = true
	history.Session.Replayed = true
	history.Session.Session = session.Session{}
	if err := history.Validate(); err != nil {
		t.Fatal("deleted-session history denied", err)
	}
	history.Session.Cookie.Name = "__Host-session"
	if history.Validate() == nil {
		t.Fatal("historical credential metadata returned")
	}
}

func TestSignupServiceDiagnosticsDenyExport(t *testing.T) {
	r := signupSessionResult(t)
	input := signupInput(t)
	request := password.SignupRecoveryRequest{Recovery: r.Recovery, Cookie: input.Cookie, Caller: input.Caller, Origin: input.Origin, Network: input.Network}
	q, flow, _ := r.Recovery.Bindings()
	for _, value := range []interface{ MarshalText() ([]byte, error) }{r.Recovery, request, r} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			out := fmt.Sprintf(verb, value)
			for _, sentinel := range []string{string(q.CommandID), string(flow), string(q.TenantID), input.Cookie.Token(), "public-ingress"} {
				if strings.Contains(out, sentinel) {
					t.Fatal("signup diagnostic disclosed custody/scope")
				}
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("JSON export accepted")
		}
		if _, err := value.MarshalText(); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("text export accepted")
		}
	}
}

type signupPort struct{}

func (signupPort) Signup(context.Context, password.SignupRequest) (password.SignupResult, error) {
	return password.SignupResult{}, password.ErrPasswordWork
}
func (signupPort) RecoverSignup(context.Context, password.SignupRecoveryRequest) (password.SignupResult, error) {
	return password.SignupResult{}, password.ErrPasswordWork
}

var _ password.SignupService = signupPort{}

func FuzzSignupRecoveryScope(f *testing.F) {
	f.Add("tenant", "public-ingress", "AgICAgICAgICAgICAgICAg")
	f.Add("", "", "")
	f.Add("\xff", "unsafe\n", strings.Repeat("x", 129))
	f.Fuzz(func(t *testing.T, tenant, actor, flow string) {
		q := identity.RecoveryQuery{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: identity.TenantID(tenant), ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signup", AnonymousFlowID: flow}
		r, err := password.NewSignupRecovery(q, identity.PreAuthTransactionID(flow))
		if err != nil {
			if r != (password.SignupRecovery{}) {
				t.Fatal("invalid recovery retained projection")
			}
			return
		}
		got, id, err := r.Bindings()
		if err != nil || got != q || string(id) != flow {
			t.Fatal("reconstructed scope changed")
		}
	})
}
