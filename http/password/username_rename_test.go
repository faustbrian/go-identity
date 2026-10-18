package passwordhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
)

type renameWork struct {
	f                      *changeFixture
	reads, calls           int
	last                   username.RenameRequest
	sourceErr, errorResult error
	result                 identity.CommandResult
}

func (w *renameWork) RenameRateSource(ctx context.Context, r username.RenameRequest) (identity.UserID, error) {
	w.reads++
	w.last = r
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded rename source")
	}
	if w.f.rate.calls != 0 {
		panic("rate charged unvalidated subject")
	}
	if w.sourceErr != nil {
		return "", w.sourceErr
	}
	return "user-a", nil
}
func (w *renameWork) Rename(ctx context.Context, r username.RenameRequest) (identity.CommandResult, error) {
	w.calls++
	w.last = r
	if _, ok := ctx.Deadline(); !ok || w.f.rate.calls != 1 {
		panic("rename before bounded admission")
	}
	return w.result, w.errorResult
}
func (w *renameWork) RenameRecover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (identity.CommandResult, error) {
	return identity.CommandResult{}, errors.New("not selected")
}

func renameFixture(t *testing.T) (*changeFixture, *renameWork, passwordhttp.UsernameRenameConfig, *http.Request) {
	f := newChange(t, session.CredentialCookie)
	f.work.proof.Action = "identity.username.update"
	owner := &renameWork{f: f, errorResult: identity.ForbiddenError{}}
	c := passwordhttp.UsernameRenameConfig{Network: f.config.Network, Service: owner, Proofs: f.work, Rate: f.config.Rate, Cookie: f.config.Cookie, TrustedOrigins: f.config.TrustedOrigins, PolicyRevision: f.config.PolicyRevision, MaximumDuration: f.config.MaximumDuration}
	r := changeRequest(f)
	r.URL.Path, r.RequestURI = "/v1/username/update", "/v1/username/update"
	r.Body = signupBody(r, `{"proofID":"abcdefghijklmnopqrstuv","identifierID":"username-a","expectedIdentifierVersion":1,"expectedVerificationVersion":1,"username":"Straße"}`)
	return f, owner, c, r
}

func TestUsernameRenameAuthenticatesOriginalBeforeRateWithoutCurrentSessionRead(t *testing.T) {
	f, owner, c, r := renameFixture(t)
	h, err := passwordhttp.NewUsernameRenameHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || owner.reads != 1 || owner.calls != 1 || f.work.proofReads != 1 || f.reader.calls != 0 || f.rate.calls != 1 {
		t.Fatal("original custody was replaced by current session or unvalidated rate subject", w.Code)
	}
	q := owner.last
	if q.Validate() != nil || q.Username != "Straße" || q.IdentifierID != "username-a" || q.Caller.Request.Subject.ID != "user-a" || q.Caller.Request.Resource.ID != "user-a" || q.Session.Token() != f.wire || q.CSRFToken == (session.CSRFToken{}) || q.Proof != f.work.proof {
		t.Fatal("rename lost original input/authority custody")
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "Straße") {
		t.Fatal("rename disclosed sensitive input or renewed credentials")
	}
}

func TestUsernameRenameDeniesOriginalCustodyBeforeSharedRate(t *testing.T) {
	f, owner, c, r := renameFixture(t)
	owner.sourceErr = identity.ForbiddenError{}
	h, err := passwordhttp.NewUsernameRenameHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || owner.reads != 1 || owner.calls != 0 || f.rate.calls != 0 {
		t.Fatal("rejected original custody invoked mutation or subject rate", w.Code)
	}
}

func TestUsernameRenameRejectsAlternateAuthorityBeforeOwners(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"origin": func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		"csrf":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic") },
		"key":    func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		"user": func(r *http.Request) {
			r.Body = signupBody(r, `{"proofID":"abcdefghijklmnopqrstuv","identifierID":"username-a","expectedIdentifierVersion":1,"expectedVerificationVersion":1,"username":"new","userID":"foreign"}`)
		},
		"fraction": func(r *http.Request) {
			r.Body = signupBody(r, `{"proofID":"abcdefghijklmnopqrstuv","identifierID":"username-a","expectedIdentifierVersion":1.5,"expectedVerificationVersion":1,"username":"new"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, owner, c, r := renameFixture(t)
			mutate(r)
			h, err := passwordhttp.NewUsernameRenameHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || owner.reads != 0 || owner.calls != 0 || f.work.proofReads != 0 || f.rate.calls != 0 {
				t.Fatal("malformed authority reached owners", w.Code)
			}
		})
	}
}

func renameReceipt(t *testing.T, outcome identity.CommitOutcome) identity.CommandResult {
	t.Helper()
	op := identity.FeatureOperation{Owner: "identity/username", OperationID: "identity.username.update", SchemaID: "identity.username.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	r := identity.CommandResult{Binding: identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: "policy-a", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "correlation-a", RecordID: "username-a"}, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: op}}
	if outcome == identity.CommitOutcomeCommitted {
		r.AuditEventID = "event-a"
		r.Feature.BeforeVersion = 1
		r.Feature.AfterVersion = 2
	}
	if err := r.Validate(); err != nil {
		t.Fatal("invalid native receipt fixture", err)
	}
	return r
}

func TestUsernameRenameProjectsOnlyOriginalSafeOutcome(t *testing.T) {
	for _, row := range []struct {
		name    string
		outcome identity.CommitOutcome
		err     error
		status  int
		changed bool
	}{
		{"committed", identity.CommitOutcomeCommitted, nil, 200, true},
		{"unknown", identity.CommitOutcomeUnknown, errors.New("private-database-diagnostic"), 503, false},
		{"committed-error", identity.CommitOutcomeCommitted, errors.New("private-delivery-diagnostic"), 503, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, owner, c, r := renameFixture(t)
			owner.result = renameReceipt(t, row.outcome)
			owner.errorResult = row.err
			h, err := passwordhttp.NewUsernameRenameHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out passwordhttp.UsernameRenameResponse
			if w.Code != row.status || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Changed != row.changed || out.CommandID != owner.result.Binding.CommandID || out.Recovery == nil || out.Recovery.RecordID != "username-a" || out.Recovery.OperationID != "identity.username.update" || strings.Contains(w.Body.String(), "private-") {
				t.Fatal("native original metadata or ambiguity lost", w.Code)
			}
			if row.changed && out.IdentifierVersion != 2 || !row.changed && out.IdentifierVersion != 0 {
				t.Fatal("failed attempt asserted successful version")
			}
		})
	}
}

func TestUsernameRenameForeignReceiptDisclosesNoCorrelation(t *testing.T) {
	_, owner, c, r := renameFixture(t)
	owner.result = renameReceipt(t, identity.CommitOutcomeCommitted)
	owner.result.Binding.UserID = "foreign-user"
	owner.result.Binding.ActorID = "foreign-user"
	owner.errorResult = nil
	h, err := passwordhttp.NewUsernameRenameHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || strings.Contains(w.Body.String(), "commandID") || strings.Contains(w.Body.String(), "foreign-user") || strings.Contains(w.Body.String(), `"changed":true`) {
		t.Fatal("unrelated owner output escaped scope", w.Code)
	}
}

func TestUsernameRenameFeatureSelectsOriginalCookieWire(t *testing.T) {
	_, owner, c, r := renameFixture(t)
	owner.result = renameReceipt(t, identity.CommitOutcomeCommitted)
	owner.errorResult = nil
	feature, err := passwordhttp.NewUsernameFeature(passwordhttp.UsernameFeatureConfig{Rename: &c})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	selected.ServeHTTP(w, r)
	if w.Code != 200 || owner.calls != 1 {
		t.Fatal("selected rename route did not execute", w.Code)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || len(ops) != 1 || ops[0].Record.OperationID != "identity.username.update" || ops[0].Wire == nil || !strings.Contains(string(ops[0].Wire.Definition), `"identifierVersion"`) || strings.Contains(string(ops[0].Wire.Definition), `"newPassword"`) {
		t.Fatal("rename metadata aliases password mutation", err)
	}
}

func FuzzUsernameRenameClosedInput(f *testing.F) {
	f.Add(`{"proofID":"abcdefghijklmnopqrstuv","identifierID":"username-a","expectedIdentifierVersion":1,"expectedVerificationVersion":1,"username":"Straße"}`)
	f.Add(`{"proofID":"abcdefghijklmnopqrstuv","identifierID":"username-a","expectedIdentifierVersion":18446744073709551616,"expectedVerificationVersion":1,"username":"next"}`)
	f.Add(`{"proofID":"abcdefghijklmnopqrstuv","proofID":"duplicate","username":"next"}`)
	f.Add(`{"username":"\ud800"}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			t.Skip()
		}
		fixture, owner, c, r := renameFixture(t)
		r.Body = signupBody(r, body)
		h, err := passwordhttp.NewUsernameRenameHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if owner.calls > 1 || owner.reads > 1 || fixture.rate.calls > 1 || fixture.reader.calls != 0 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("hostile rename input repeated owner or escaped custody")
		}
		if owner.calls == 1 && owner.last.Validate() != nil {
			t.Fatal("malformed request reached native mutation")
		}
	})
}
