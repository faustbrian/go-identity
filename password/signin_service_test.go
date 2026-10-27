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

func signinRecovery(t testing.TB, anonymous bool) password.SigninRecovery {
	t.Helper()
	request := signinInput(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: request.TenantID, UserID: "user", ActorID: "public-ingress", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signin"}
	if anonymous {
		q.UserID = ""
		q.AnonymousFlowID = string(request.PreAuthID)
	}
	r, err := password.NewSigninRecovery(q, request.PreAuthID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSigninRecoveryKeepsOriginalNamespace(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		r := signinRecovery(t, anonymous)
		q, flow, err := r.Bindings()
		if err != nil || flow == "" || (q.UserID == "") != anonymous || (q.AnonymousFlowID != "") != anonymous {
			t.Fatal("lost original scope", err)
		}
		for _, mutate := range []func(*identity.RecoveryQuery){
			func(q *identity.RecoveryQuery) { q.CommandID = "bad" },
			func(q *identity.RecoveryQuery) { q.TenantID = "" },
			func(q *identity.RecoveryQuery) { q.ActorID = "" },
			func(q *identity.RecoveryQuery) { q.ActorKind = "unknown" },
			func(q *identity.RecoveryQuery) { q.OperationID = "identity.password.verify" },
			func(q *identity.RecoveryQuery) { q.RecordID = string(q.CommandID) },
			func(q *identity.RecoveryQuery) { q.LinkMode = 1 },
			func(q *identity.RecoveryQuery) { q.UserID = "user"; q.AnonymousFlowID = string(flow) },
			func(q *identity.RecoveryQuery) { q.UserID = ""; q.AnonymousFlowID = "" },
			func(q *identity.RecoveryQuery) { q.UserID = ""; q.AnonymousFlowID = "foreign" },
		} {
			bad := q
			mutate(&bad)
			if got, err := password.NewSigninRecovery(bad, flow); !errors.Is(err, password.ErrPasswordWork) || got != (password.SigninRecovery{}) {
				t.Fatal("invalid correlation accepted")
			}
		}
		q.TenantID = "foreign" // Mutating a projection must not mutate the opaque original.
		original, _, _ := r.Bindings()
		if original.TenantID == q.TenantID {
			t.Fatal("mutable recovery")
		}
	}
	if _, _, err := (password.SigninRecovery{}).Bindings(); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("zero recovery accepted")
	}
}

func TestPhonePasswordSigninRecoveryRetainsDistinctOriginalOperation(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		original := signinRecovery(t, anonymous)
		query, flow, _ := original.Bindings()
		query.OperationID = "identity.phone.password-signin"
		recovery, err := password.NewSigninRecovery(query, flow)
		if err != nil {
			t.Fatal("phone password signin lost original recovery namespace", err)
		}
		got, gotFlow, err := recovery.Bindings()
		if err != nil || got != query || gotFlow != flow {
			t.Fatal("phone password recovery was relabeled or retargeted")
		}
		for _, operation := range []string{"identity.phone.signin", "identity.phone.verify", "identity.phone.password-reset-complete"} {
			changed := query
			changed.OperationID = operation
			if _, err := password.NewSigninRecovery(changed, flow); err == nil {
				t.Fatal("another phone workflow became password-signin recovery")
			}
		}
	}
}

// Compile the consuming port from an external package without importing SQL.
type signinPort struct{}

func (signinPort) Signin(context.Context, password.SigninRequest) (password.SigninResult, error) {
	return password.SigninResult{}, password.ErrPasswordWork
}
func (signinPort) RecoverSignin(context.Context, password.SigninRecoveryRequest) (password.SigninResult, error) {
	return password.SigninResult{}, password.ErrPasswordWork
}

var _ password.SigninService = signinPort{}

func signinSession(t testing.TB) session.Session {
	t.Helper()
	now := time.Date(2026, 10, 10, 5, 0, 0, 0, time.UTC)
	r := signinInput(t)
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global:        session.AuthorityBinding{ScopeKey: "global:deployment", Version: 1},
		Tenant:        session.AuthorityBinding{ScopeKey: "tenant:tenant", Version: 2},
		User:          session.AuthorityBinding{ScopeKey: "user:tenant:user", Version: 3},
		Identifier:    session.AuthorityBinding{ScopeKey: "identifier:tenant:user", Version: 4},
		Credential:    session.AuthorityBinding{ScopeKey: "credential:tenant:user", Version: 5},
		SessionFamily: session.AuthorityBinding{ScopeKey: "family:tenant:family", Version: 6},
		Session:       session.AuthorityBinding{ScopeKey: "session:tenant:session", Version: 7},
		Authorization: session.AuthorityBinding{ScopeKey: "authorization:tenant:user", Version: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: r.TenantID, UserID: "user", Audience: "identity-service", Version: 7, FamilyVersion: 6, Remember: r.Remember, Authority: authority, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signinResult(t testing.TB, outcome identity.CommitOutcome) password.SigninResult {
	t.Helper()
	recovery := signinRecovery(t, false)
	q, _, _ := recovery.Bindings()
	r := password.SigninResult{State: auth.SignInStateRejected, Recovery: recovery, Issuance: session.IssueResult{CommandID: q.CommandID, CommitOutcome: outcome}}
	if outcome == identity.CommitOutcomeCommitted {
		r.State = auth.SignInStateAuthenticated
		r.SessionID = "session"
		r.Issuance.Session = signinSession(t)
	}
	return r
}

func TestSigninResultClosedStateAndOutcome(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeInvalid, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, 255} {
		for _, state := range []auth.SignInState{auth.SignInStateUnspecified, auth.SignInStateAuthenticated, auth.SignInStateChallengeRequired, auth.SignInStateRejected, 255} {
			r := signinResult(t, outcome)
			r.State = state
			want := outcome == identity.CommitOutcomeCommitted && state == auth.SignInStateAuthenticated || (outcome == identity.CommitOutcomeNotCommitted || outcome == identity.CommitOutcomeUnknown || outcome == identity.CommitOutcomeConflict || outcome == identity.CommitOutcomeInProgress) && state == auth.SignInStateRejected
			if (r.Validate() == nil) != want {
				t.Fatalf("state %d outcome %d", state, outcome)
			}
		}
	}
	if (password.SigninResult{}).Validate() == nil {
		t.Fatal("zero means authenticated observation")
	}
}

func TestSigninResultNativeCustodyAndHistoricalReplay(t *testing.T) {
	r := signinResult(t, identity.CommitOutcomeCommitted)
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	r.Issuance.Token, r.CSRFToken = token, csrf
	r.Issuance.Cookie.Name = "__Host-session"
	r.Issuance.Cookie.Path = "/"
	r.Issuance.Cookie.Secure = true
	r.Issuance.Cookie.HttpOnly = true
	if err := r.Validate(); err != nil {
		t.Fatal("fresh original denied", err)
	}
	copy := r
	if _, err := copy.Issuance.Token.Reveal(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Issuance.Token.Reveal(); err == nil {
		t.Fatal("password reconstructed bearer delivery")
	}
	if _, err := copy.CSRFToken.Reveal(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CSRFToken.Reveal(); err == nil {
		t.Fatal("password reconstructed synchronizer delivery")
	}
	// Validation never consumes or renews the owner's permission, even once spent.
	if r.Validate() != nil {
		t.Fatal("structural validation became a token authority")
	}
	for _, mutate := range []func(*password.SigninResult){
		func(r *password.SigninResult) { r.Issuance.CommandID = "bad" },
		func(r *password.SigninResult) { r.Recovery = password.SigninRecovery{} },
		func(r *password.SigninResult) { r.SessionID = "other" },
		func(r *password.SigninResult) { r.Issuance.Session = session.Session{} },
		func(r *password.SigninResult) { r.Issuance.Cookie.Value = "synthetic-secret" },
		func(r *password.SigninResult) { r.Issuance.Cookie.Raw = "synthetic-secret" },
		func(r *password.SigninResult) { r.Issuance.Cookie.Unparsed = []string{"synthetic-secret"} },
		func(r *password.SigninResult) { r.Issuance.Replayed = true },
		func(r *password.SigninResult) { r.Issuance.Token = session.Token{} },
		func(r *password.SigninResult) { r.CSRFToken = session.CSRFToken{} },
		func(r *password.SigninResult) { r.Issuance.RetryAfter = time.Second },
		func(r *password.SigninResult) { r.Issuance.RetryAfter = -time.Second },
		func(r *password.SigninResult) {
			q, flow, _ := r.Recovery.Bindings()
			q.TenantID = "foreign"
			r.Recovery, _ = password.NewSigninRecovery(q, flow)
		},
		func(r *password.SigninResult) {
			q, flow, _ := r.Recovery.Bindings()
			q.UserID = "foreign"
			r.Recovery, _ = password.NewSigninRecovery(q, flow)
		},
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid delivery accepted")
		}
	}
	history := signinResult(t, identity.CommitOutcomeCommitted)
	history.Issuance.Replayed = true
	history.Issuance.Session = session.Session{}
	if err := history.Validate(); err != nil {
		t.Fatal("retained history lost after payload removal", err)
	}
	history.Issuance.Cookie.Name = "__Host-session"
	if history.Validate() == nil {
		t.Fatal("recovery retained credential delivery metadata")
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		denied := signinResult(t, outcome)
		for _, mutate := range []func(*password.SigninResult){
			func(r *password.SigninResult) { r.SessionID = "session" },
			func(r *password.SigninResult) { r.Issuance.Session = signinSession(t) },
			func(r *password.SigninResult) { r.Issuance.Token = token; r.CSRFToken = csrf },
		} {
			bad := denied
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("noncommitted authentication arm")
			}
		}
	}
	inProgress := signinResult(t, identity.CommitOutcomeInProgress)
	inProgress.Issuance.RetryAfter = time.Second
	if inProgress.Validate() != nil {
		t.Fatal("in-progress correlation denied")
	}
}

func TestSigninResultBearerTransport(t *testing.T) {
	r := signinResult(t, identity.CommitOutcomeCommitted)
	r.Transport = password.BearerSignin
	var err error
	r.Issuance.Token, err = session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal("explicit bearer original denied", err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*password.SigninResult){
		func(r *password.SigninResult) { r.Transport = password.CookieSignin },
		func(r *password.SigninResult) { r.Transport = 255 },
		func(r *password.SigninResult) { r.CSRFToken = csrf },
		func(r *password.SigninResult) { r.Issuance.Cookie.Name = "__Host-session" },
		func(r *password.SigninResult) { r.Issuance.Cookie.Secure = true },
		func(r *password.SigninResult) { r.Issuance.Replayed = true },
		func(r *password.SigninResult) {
			spec, _ := r.Issuance.Session.Bindings()
			state, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, KeyVersion: 1, Digest: [32]byte{1}})
			if err != nil {
				t.Fatal(err)
			}
			r.Issuance.Session, err = session.NewSessionWithCSRF(spec, state)
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("mixed or malformed bearer delivery accepted")
		}
	}
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		history := signinResult(t, outcome)
		history.Transport = password.BearerSignin
		history.Issuance.Replayed = true
		if outcome == identity.CommitOutcomeCommitted {
			history.Issuance.Session = session.Session{}
		}
		if history.Validate() != nil {
			t.Fatal("credential-free bearer outcome denied")
		}
	}
	challenge := signinResult(t, identity.CommitOutcomeCommitted)
	challenge.Transport, challenge.State, challenge.SessionID = password.BearerSignin, auth.SignInStateChallengeRequired, ""
	challenge.Issuance.Session = session.Session{}
	challenge.Challenge = password.MFAChallengeResult{ID: challenge.Issuance.CommandID, Method: "totp", ExpiresAt: time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)}
	if challenge.Validate() == nil {
		t.Fatal("unsupported bearer MFA continuation accepted")
	}
}

func TestSigninRecoveryRequestRequiresOriginalActorAndCustody(t *testing.T) {
	input := signinInput(t)
	r := password.SigninRecoveryRequest{Recovery: signinRecovery(t, true), Cookie: input.Cookie, Caller: input.Caller, Origin: input.Origin, Network: input.Network, Device: input.Device}
	if r.Validate() != nil {
		t.Fatal("valid historical request denied")
	}
	for _, mutate := range []func(*password.SigninRecoveryRequest){
		func(r *password.SigninRecoveryRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *password.SigninRecoveryRequest) { r.Recovery = password.SigninRecovery{} },
		func(r *password.SigninRecoveryRequest) { r.Caller.Request.Subject.ID = "foreign" },
		func(r *password.SigninRecoveryRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectUser },
		func(r *password.SigninRecoveryRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *password.SigninRecoveryRequest) {
			r.Caller.Request.Subject.Groups = []authorization.SubjectID{authorization.SubjectID(strings.Repeat("x", 129))}
		},
		func(r *password.SigninRecoveryRequest) { r.Origin = "" },
		func(r *password.SigninRecoveryRequest) { r.Network = "192.000.2.1" },
		func(r *password.SigninRecoveryRequest) { r.Device = strings.Repeat("x", 129) },
	} {
		bad := r
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("foreign recovery admitted")
		}
	}
}

func TestSigninRecoveryAndResultDiagnosticsDenyExport(t *testing.T) {
	r := signinResult(t, identity.CommitOutcomeCommitted)
	input := signinInput(t)
	request := password.SigninRecoveryRequest{Recovery: r.Recovery, Cookie: input.Cookie, Caller: input.Caller, Origin: input.Origin, Network: input.Network}
	q, flow, _ := r.Recovery.Bindings()
	for _, value := range []interface{ MarshalText() ([]byte, error) }{r.Recovery, request, r} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			text := fmt.Sprintf(verb, value)
			for _, secret := range []string{string(q.CommandID), string(flow), string(q.TenantID), input.Cookie.Token(), "public-ingress"} {
				if strings.Contains(text, secret) {
					t.Fatal("diagnostic correlation leak")
				}
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("JSON export")
		}
		if _, err := value.MarshalText(); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("text export")
		}
	}
}

func FuzzSigninRecoveryScope(f *testing.F) {
	f.Add("tenant", "user", "public-ingress")
	f.Add("", "", "")
	f.Add("\xff", "unsafe\n", strings.Repeat("x", 129))
	f.Fuzz(func(t *testing.T, tenant, user, actor string) {
		q := identity.RecoveryQuery{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: identity.TenantID(tenant), UserID: identity.UserID(user), ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signin"}
		r, err := password.NewSigninRecovery(q, "AgICAgICAgICAgICAgICAg")
		if err != nil {
			if r != (password.SigninRecovery{}) {
				t.Fatal("denied output")
			}
			return
		}
		got, flow, err := r.Bindings()
		if err != nil || got != q || flow != "AgICAgICAgICAgICAgICAg" {
			t.Fatal("scope changed")
		}
	})
}
