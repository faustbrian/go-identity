package email_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/session"
)

func verificationRecoveryQuery(t *testing.T) identity.RecoveryQuery {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return identity.RecoveryQuery{CommandID: id, TenantID: "tenant", UserID: "verification-user", RecordID: "verification-address", ActorID: "confirmation-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.email.verification-confirm"}
}

func verifiedProjection(t *testing.T, q identity.RecoveryQuery) identity.IdentifierProjection {
	t.Helper()
	now := time.Unix(1791637500, 0).UTC()
	state := identity.IdentifierState{User: identity.User{ID: q.UserID, TenantID: q.TenantID, Status: identity.StatusActive, Version: 7}, AuthorityVersion: 9, Identifiers: []identity.Identifier{{ID: identity.IdentifierID(q.RecordID), UserID: q.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "synthetic@example.test", Verified: true, Primary: true, Version: 2}}, Verifications: []identity.Verification{{IdentifierID: identity.IdentifierID(q.RecordID), State: identity.VerificationVerified, VerifiedAt: now, Version: 2}}}
	p, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: q.TenantID, UserID: q.UserID, IdentifierID: identity.IdentifierID(q.RecordID), State: state, ObservedAt: now, Values: identity.IdentifierValuesIncluded})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerificationRecoveryOwnsExactOriginalScope(t *testing.T) {
	q := verificationRecoveryQuery(t)
	r, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	original := q
	q.RecordID = "changed"
	got, err := r.Bindings()
	if err != nil || got != original {
		t.Fatal("recovery retargeted original command")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := r.Bindings()
			if err != nil || got != original {
				t.Error("copied recovery changed")
			}
		}()
	}
	wg.Wait()
	for name, change := range map[string]func(*identity.RecoveryQuery){
		"command":            func(q *identity.RecoveryQuery) { q.CommandID = "" },
		"tenant":             func(q *identity.RecoveryQuery) { q.TenantID = "" },
		"subject":            func(q *identity.RecoveryQuery) { q.UserID = "" },
		"address":            func(q *identity.RecoveryQuery) { q.RecordID = "" },
		"actor":              func(q *identity.RecoveryQuery) { q.ActorID = "" },
		"actor kind":         func(q *identity.RecoveryQuery) { q.ActorKind = "unknown" },
		"anonymous retarget": func(q *identity.RecoveryQuery) { q.AnonymousFlowID = "signup-origin" },
		"operation":          func(q *identity.RecoveryQuery) { q.OperationID = "identity.password.reset" },
		"link profile":       func(q *identity.RecoveryQuery) { q.LinkMode = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := original
			change(&bad)
			if _, err := email.NewVerificationRecovery(bad); !errors.Is(err, email.ErrInvalidVerification) {
				t.Fatal("invalid recovery admitted")
			}
		})
	}
	if _, err := (email.VerificationRecovery{}).Bindings(); !errors.Is(err, email.ErrInvalidVerification) {
		t.Fatal("zero recovery admitted")
	}
}

func TestVerificationConfirmResultConservesObservedOutcome(t *testing.T) {
	q := verificationRecoveryQuery(t)
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	address := verifiedProjection(t, q)
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		r := email.VerificationConfirmResult{Outcome: outcome, Recovery: recovery}
		if outcome == identity.CommitOutcomeInProgress {
			r.RetryAfter = time.Second
		}
		if err := r.Validate(); err != nil {
			t.Fatal("receipt-only outcome lost", outcome, err)
		}
		r.Address = address
		if (r.Validate() == nil) != (outcome == identity.CommitOutcomeCommitted) {
			t.Fatal("address disclosed before commitment")
		}
	}
	r := email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Address: address}
	r.Replayed = true
	if r.Validate() == nil {
		t.Fatal("replay disclosed an address snapshot")
	}
	r.Replayed = false
	foreign := q
	foreign.RecordID = "foreign-address"
	r.Address = verifiedProjection(t, foreign)
	if r.Validate() == nil {
		t.Fatal("foreign address admitted")
	}
	r.Address = address
	r.Session = session.IssueResult{Cookie: http.Cookie{Name: "session"}}
	if r.Validate() == nil {
		t.Fatal("initial no-session profile admitted cookie")
	}
	r.Session = session.IssueResult{}
	r.Outcome = identity.CommitOutcomeInvalid
	if r.Validate() == nil {
		t.Fatal("invalid outcome admitted")
	}
	r.Outcome = identity.CommitOutcomeCommitted
	r.RetryAfter = time.Second
	if r.Validate() == nil {
		t.Fatal("retry on terminal outcome admitted")
	}
	r.Outcome = identity.CommitOutcomeInProgress
	r.Address = identity.IdentifierProjection{}
	if err := r.Validate(); err != nil {
		t.Fatal("bounded in-progress delay denied", err)
	}
}

func TestVerificationRecoveryRequestAndMetadataResult(t *testing.T) {
	r := confirmationRequest(t)
	q := verificationRecoveryQuery(t)
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	request := email.VerificationRecoveryRequest{Recovery: recovery, Caller: r.Caller}
	if err := request.Validate(); err != nil {
		t.Fatal("metadata recovery input denied", err)
	}
	request.Caller.Request.Resource.ID = "foreign-user"
	if request.Validate() == nil {
		t.Fatal("foreign recovery resource admitted")
	}
	request.Caller.Request.Resource.ID = ""
	request.Caller.Request.Subject.ID = "foreign-actor"
	if request.Validate() == nil {
		t.Fatal("foreign recovery actor admitted")
	}
	result := email.VerificationRecoveryResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationResultDiagnosticsDenyPrivateReflection(t *testing.T) {
	q := verificationRecoveryQuery(t)
	r, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{r, struct{ private email.VerificationRecovery }{r}, email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: r, Address: verifiedProjection(t, q)}, email.VerificationRecoveryResult{Outcome: identity.CommitOutcomeCommitted, Recovery: r}}
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(verb, v)
			if strings.Contains(text, "verification-user") || strings.Contains(text, "synthetic@example.test") {
				t.Fatal("private recovery or result disclosed")
			}
		}
	}
	for _, v := range values {
		if _, private := v.(struct{ private email.VerificationRecovery }); private {
			continue
		}
		if _, err := json.Marshal(v); !errors.Is(err, email.ErrSensitiveSerialization) {
			t.Fatal("implicit metadata export admitted", err)
		}
	}
}

func TestVerificationResultRejectsEverySessionEffect(t *testing.T) {
	q := verificationRecoveryQuery(t)
	recovery, err := email.NewVerificationRecovery(q)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	for name, effect := range map[string]session.IssueResult{
		"command": {CommandID: q.CommandID}, "outcome": {CommitOutcome: identity.CommitOutcomeCommitted},
		"token": {Token: token}, "replay": {Replayed: true}, "delay": {RetryAfter: time.Second},
		"name": {Cookie: http.Cookie{Name: "session"}}, "value": {Cookie: http.Cookie{Value: "synthetic"}},
		"path": {Cookie: http.Cookie{Path: "/"}}, "domain": {Cookie: http.Cookie{Domain: "example.test"}},
		"expires": {Cookie: http.Cookie{Expires: time.Unix(1, 0)}}, "raw expires": {Cookie: http.Cookie{RawExpires: "synthetic"}},
		"max age": {Cookie: http.Cookie{MaxAge: -1}}, "secure": {Cookie: http.Cookie{Secure: true}},
		"http only": {Cookie: http.Cookie{HttpOnly: true}}, "same site": {Cookie: http.Cookie{SameSite: http.SameSiteStrictMode}},
		"partitioned": {Cookie: http.Cookie{Partitioned: true}}, "raw": {Cookie: http.Cookie{Raw: "synthetic"}},
		"unparsed": {Cookie: http.Cookie{Unparsed: []string{"synthetic"}}},
	} {
		t.Run(name, func(t *testing.T) {
			r := email.VerificationConfirmResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Session: effect}
			if !errors.Is(r.Validate(), email.ErrInvalidVerification) {
				t.Fatal("unrequested session effect admitted")
			}
		})
	}
	if _, err := token.Reveal(); err != nil {
		t.Fatal("validation changed bearer custody", err)
	}
}

func TestVerificationRecoveryDelayAndZeroBoundaries(t *testing.T) {
	recovery, err := email.NewVerificationRecovery(verificationRecoveryQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, delay := range []time.Duration{-1, 0, 1, time.Minute, time.Minute + 1} {
		r := email.VerificationRecoveryResult{Outcome: identity.CommitOutcomeInProgress, Recovery: recovery, RetryAfter: delay}
		if (r.Validate() == nil) != (delay > 0 && delay <= time.Minute) {
			t.Fatal("wrong retry boundary", delay)
		}
	}
	if (email.VerificationConfirmResult{}).Validate() == nil || (email.VerificationRecoveryResult{}).Validate() == nil || (email.VerificationRecoveryRequest{}).Validate() == nil {
		t.Fatal("zero admitted")
	}
}
