package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type csrfRevokeExecutor struct{ revokeExecutor }

func (csrfRevokeExecutor) ExecuteRevokeOne(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
	return identity.CommandResult{}, errors.New("wrong legacy execution profile")
}

func (f csrfRevokeExecutor) ExecuteRevokeOneWithCSRF(ctx context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
	return f.revokeExecutor(ctx, r)
}

func TestCookieSignOutRejectsLegacyExecutorBeforeAdmission(t *testing.T) {
	reader, _, _, _, _, key := cookieSignOutFixture(t)
	base, err := session.NewSignOutService(reader, revokeExecutor(func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
		t.Fatal("legacy executor entered strict cookie profile")
		return identity.CommandResult{}, nil
	}), signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if service, err := session.NewCookieSignOutService(base, []session.CSRFKey{key}); err == nil || service != nil {
		t.Fatal("legacy executor accepted without explicit transactional CSRF contract")
	}
}

func cookieSignOutFixture(t *testing.T) (*session.SessionService, session.GetRequest, *mutableIssueClock, *session.SessionObservation, session.CSRFToken, session.CSRFKey) {
	t.Helper()
	reader, get, clock, observation, _, _ := validationFixture(t)
	spec, _ := observation.Session.Bindings()
	key, err := session.NewCSRFKey(3, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseCSRFToken(tokenFixture(32))
	if err != nil {
		t.Fatal(err)
	}
	state, err := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	observation.Session, err = session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	return reader, get, clock, observation, token, key
}

func TestCookieSignOutNamedKeysAndImmutableSelection(t *testing.T) {
	reader, get, _, observation, token, key := cookieSignOutFixture(t)
	spec, _ := observation.Session.Bindings()
	b := issueBinding(spec)
	request := session.SignOutRequest{TenantID: get.TenantID, CommandID: b.CommandID, CorrelationID: b.CorrelationID, Transport: session.CredentialCookie, Credential: get.Credential}
	executions := 0
	base, err := session.NewSignOutService(reader, csrfRevokeExecutor{revokeExecutor(func(_ context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
		executions++
		return signOutReceipt(t, r, identity.CommitOutcomeCommitted), nil
	})}, signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	newer, _ := session.NewCSRFKey(4, []byte(strings.Repeat("n", 32)))
	wrong, _ := session.NewCSRFKey(3, []byte(strings.Repeat("z", 32)))
	for _, keys := range [][]session.CSRFKey{{newer}, {wrong}} {
		service, err := session.NewCookieSignOutService(base, keys)
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.SignOut(context.Background(), request, token)
		if !errors.Is(err, session.ErrCSRFDenied) || result.ClearCookie || result.SignedOut || executions != 0 {
			t.Fatal("unknown or wrong named key granted logout")
		}
	}
	keys := []session.CSRFKey{newer, key}
	service, err := session.NewCookieSignOutService(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	keys[1] = wrong
	if result, err := service.SignOut(context.Background(), request, token); err != nil || !result.ClearCookie || executions != 1 {
		t.Fatal("retained named key lost to caller slice mutation", err)
	}
	for _, keys := range [][]session.CSRFKey{nil, {}, {{}}, {key, key}, {key, wrong}, {key, newer, key, newer, key}} {
		if _, err := session.NewCookieSignOutService(base, keys); err == nil {
			t.Fatal("ambiguous key profile accepted")
		}
	}
	if _, err := session.NewCookieSignOutService(nil, []session.CSRFKey{key}); err == nil {
		t.Fatal("nil base accepted")
	}
	if (session.CSRFKey{}).Version() != 0 || key.Version() != 3 {
		t.Fatal("key routing metadata lost")
	}
	if _, err := json.Marshal(service); err == nil {
		t.Fatal("service serialized")
	}
	if _, err := service.MarshalText(); err == nil {
		t.Fatal("service text serialized")
	}
	if got := fmt.Sprintf("%#v", service); !strings.Contains(got, "redacted") || strings.Contains(got, "kkkk") {
		t.Fatal("service exposed key composition")
	}
}

func TestCookieSignOutInactiveSuccessAndNoTransportDowngrade(t *testing.T) {
	reader, get, _, observation, token, key := cookieSignOutFixture(t)
	spec, _ := observation.Session.Bindings()
	b := issueBinding(spec)
	request := session.SignOutRequest{TenantID: get.TenantID, CommandID: b.CommandID, CorrelationID: b.CorrelationID, Transport: session.CredentialCookie, Credential: get.Credential}
	base, _ := session.NewSignOutService(reader, csrfRevokeExecutor{revokeExecutor(func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
		t.Fatal("inactive/invalid request executed")
		return identity.CommandResult{}, nil
	})}, signOutConfig(t))
	service, _ := session.NewCookieSignOutService(base, []session.CSRFKey{key})
	observation.Active = false
	for _, absent := range []bool{false, true} {
		r := request
		if absent {
			r.Credential = session.Credential{}
		}
		result, err := service.SignOut(context.Background(), r, session.CSRFToken{})
		if err != nil || !result.SignedOut || !result.ClearCookie || result.ClearBearer || result.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("idempotent inactive/absent logout lost", err)
		}
	}
	observation.Active = true
	observation.Session, _ = session.NewSession(spec)
	if result, err := service.SignOut(context.Background(), request, token); !errors.Is(err, session.ErrCSRFDenied) || result.ClearCookie {
		t.Fatal("active legacy session bypassed CSRF")
	}
	request.Transport = session.CredentialBearer
	if result, err := service.SignOut(context.Background(), request, token); !errors.Is(err, session.ErrInvalidInput) || result.ClearCookie || result.ClearBearer {
		t.Fatal("cookie service acquired bearer mode")
	}
	for _, invalid := range []*session.CookieSignOutService{nil, {}} {
		if _, err := invalid.SignOut(context.Background(), request, token); !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid service accepted")
		}
	}
	request.Transport = session.CredentialCookie
	if _, err := service.SignOut(nil, request, token); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("nil context accepted")
	}
}

func TestCookieSignOutNeverClearsOnFailedExecution(t *testing.T) {
	for _, mode := range []string{"unknown", "denied", "cancelled", "committed-error"} {
		t.Run(mode, func(t *testing.T) {
			reader, get, _, observation, token, key := cookieSignOutFixture(t)
			spec, _ := observation.Session.Bindings()
			b := issueBinding(spec)
			request := session.SignOutRequest{TenantID: get.TenantID, CommandID: b.CommandID, CorrelationID: b.CorrelationID, Transport: session.CredentialCookie, Credential: get.Credential}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base, _ := session.NewSignOutService(reader, csrfRevokeExecutor{revokeExecutor(func(_ context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
				switch mode {
				case "denied":
					return identity.CommandResult{}, identity.ForbiddenError{}
				case "cancelled":
					cancel()
					return signOutReceipt(t, r, identity.CommitOutcomeCommitted), nil
				case "committed-error":
					return signOutReceipt(t, r, identity.CommitOutcomeCommitted), errors.New("private dependency failure")
				default:
					return signOutReceipt(t, r, identity.CommitOutcomeUnknown), errors.New("private dependency failure")
				}
			})}, signOutConfig(t))
			service, _ := session.NewCookieSignOutService(base, []session.CSRFKey{key})
			result, err := service.SignOut(ctx, request, token)
			if err == nil || result.SignedOut || result.ClearCookie || result.ClearBearer || result.Cookie.Name != "" || strings.Contains(err.Error(), "private") {
				t.Fatal("failed logout cleared or disclosed")
			}
			if result.CommandID != request.CommandID || result.Recovery.RecordID != spec.SessionID || result.Recovery.TenantID != spec.TenantID {
				t.Fatal("original recovery scope lost")
			}
			if mode == "unknown" && result.CommitOutcome != identity.CommitOutcomeUnknown {
				t.Fatal("unknown outcome rewritten")
			}
		})
	}
}

func TestCookieSignOutPreparedRequestPreservesOriginalCustody(t *testing.T) {
	reader, get, clock, observation, token, key := cookieSignOutFixture(t)
	caller, err := reader.Get(context.Background(), get)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := observation.Session.Bindings()
	b := issueBinding(spec)
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := session.NewRevokeOneCommand(b, observation.Session)
	if err != nil {
		t.Fatal(err)
	}
	request, err := reader.PrepareRevokeOneWithCSRF(caller, command, token, key)
	if err != nil {
		t.Fatal(err)
	}
	if !request.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("CSRF preparation renewed authority")
	}
	for _, absent := range []session.RevokeOneRequest{{}, func() session.RevokeOneRequest { r, _ := reader.PrepareRevokeOne(caller, command); return r }()} {
		if _, present := absent.CSRFToken(); present {
			t.Fatal("legacy request invented token custody")
		}
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("CSRF request serialized")
	}
	if _, err := request.MarshalText(); err == nil {
		t.Fatal("CSRF request text serialized")
	}
	if got := fmt.Sprintf("%#v", request); !strings.Contains(got, "redacted") {
		t.Fatal("request exposed credential")
	}
	copied := request
	clock.now = caller.ValidUntil()
	if !errors.Is(copied.Validate(reader, clock.now), session.ErrUnauthenticated) {
		t.Fatal("copied CSRF request extended original expiry")
	}
	if _, err := reader.PrepareRevokeOneWithCSRF(caller, command, token, key); !errors.Is(err, session.ErrUnauthenticated) {
		t.Fatal("expired caller prepared CSRF mutation")
	}
}

func TestCookieSignOutRetainsOpaqueCSRFBeforeExecution(t *testing.T) {
	reader, get, clock, observation, _, _ := validationFixture(t)
	spec, _ := observation.Session.Bindings()
	key, _ := session.NewCSRFKey(3, []byte(strings.Repeat("k", 32)))
	token, _ := session.ParseCSRFToken(tokenFixture(32))
	state, err := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	observation.Session, err = session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	executions := 0
	executor := revokeExecutor(func(ctx context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
		admitted, present := r.CSRFToken()
		if !present || r.Validate(reader, clock.now) != nil || r.Caller() != observation.Session {
			t.Fatal("original CSRF/caller custody lost")
		}
		if state.Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, admitted, key) != nil {
			t.Fatal("wrong token reached durable executor")
		}
		executions++
		return signOutReceipt(t, r, identity.CommitOutcomeCommitted), nil
	})
	base, err := session.NewSignOutService(reader, csrfRevokeExecutor{executor}, signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	service, err := session.NewCookieSignOutService(base, []session.CSRFKey{key})
	if err != nil {
		t.Fatal(err)
	}
	b := issueBinding(spec)
	request := session.SignOutRequest{TenantID: get.TenantID, CommandID: b.CommandID, CorrelationID: b.CorrelationID, Transport: session.CredentialCookie, Credential: get.Credential}
	for _, bad := range []session.CSRFToken{{}, func() session.CSRFToken { v, _ := session.NewCSRFToken(); return v }()} {
		result, err := service.SignOut(context.Background(), request, bad)
		if !errors.Is(err, session.ErrCSRFDenied) || result.SignedOut || result.ClearCookie || result.ClearBearer || executions != 0 {
			t.Fatal("CSRF denial caused protected execution or clearing")
		}
	}
	result, err := service.SignOut(context.Background(), request, token)
	if err != nil || !result.SignedOut || !result.ClearCookie || result.ClearBearer || executions != 1 || result.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("correct cookie logout failed", err)
	}
}
