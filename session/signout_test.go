package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type revokeExecutor func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error)

func (f revokeExecutor) ExecuteRevokeOne(ctx context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
	return f(ctx, r)
}

func signOutConfig(t *testing.T) session.SignOutConfig {
	t.Helper()
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	return session.SignOutConfig{Cookie: cookie, PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second}
}

func TestSignOutRevokesOnlyOriginalCallerAndClearsSelectedTransport(t *testing.T) {
	for _, transport := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		t.Run(map[session.CredentialKind]string{session.CredentialCookie: "cookie", session.CredentialBearer: "bearer"}[transport], func(t *testing.T) {
			reader, get, clock, observed, _, _ := validationFixture(t)
			// Change only transport; authentication and token custody are identical.
			if transport == session.CredentialBearer {
				// The public fixture's original token is not exposed; obtain a separate
				// canonical token and bind the trusted observation to its digest.
				token, err := session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
				key, _ := session.NewDigestKey(1, make([]byte, 32))
				spec, _ := observed.Session.Bindings()
				spec.Lookup, _ = token.Digest(key, string(spec.TenantID))
				observed.Session, err = session.NewSession(spec)
				if err != nil {
					t.Fatal(err)
				}
				get.Credential, err = session.NewCredential(transport, token)
				if err != nil {
					t.Fatal(err)
				}
			}
			spec, _ := observed.Session.Bindings()
			binding := issueBinding(spec)
			request := session.SignOutRequest{TenantID: get.TenantID, CommandID: binding.CommandID, CorrelationID: binding.CorrelationID, Credential: get.Credential, Transport: transport}
			executions := 0
			executor := revokeExecutor(func(ctx context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
				if err := r.Validate(reader, clock.now); err != nil {
					t.Fatal(err)
				}
				command, ok := r.Command()
				one, target := command.RevokeOne()
				if !ok || !target || r.Caller() != observed.Session || one.Session != observed.Session || one.Binding.CommandID != request.CommandID || one.Binding.TenantID != request.TenantID || one.Binding.UserID != spec.UserID || one.Binding.RecordID != spec.SessionID || one.Binding.PolicyID != "session-policy" {
					t.Fatal("caller or original command substituted")
				}
				executions++
				observed.Active = false
				return identity.CommandResult{Binding: one.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-signout", Feature: &identity.FeatureReceipt{Operation: session.RevokeOneOperation(), BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}}, nil
			})
			service, err := session.NewSignOutService(reader, executor, signOutConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.SignOut(context.Background(), request)
			if err != nil || !result.SignedOut || result.CommitOutcome != identity.CommitOutcomeCommitted || executions != 1 || result.CommandID != request.CommandID || result.Recovery.RecordID != spec.SessionID {
				t.Fatal("active logout outcome", err)
			}
			if result.ClearCookie != (transport == session.CredentialCookie) || result.ClearBearer != (transport == session.CredentialBearer) {
				t.Fatal("transport crossed")
			}
			if transport == session.CredentialCookie && (result.Cookie.Value != "" || result.Cookie.Name != "__Host-session" || result.Cookie.MaxAge != -1 || !result.Cookie.Secure || !result.Cookie.HttpOnly || result.Cookie.Domain != "" || result.Cookie.Path != "/") {
				t.Fatal("cookie deletion profile changed")
			}
			if transport == session.CredentialBearer && !reflect.DeepEqual(result.Cookie, http.Cookie{}) {
				t.Fatal("bearer cleared unrelated cookie")
			}
			repeated, err := service.SignOut(context.Background(), request)
			if err != nil || !repeated.SignedOut || repeated.CommitOutcome != identity.CommitOutcomeInvalid || executions != 1 {
				t.Fatal("already absent logout repeated mutation", err)
			}
		})
	}
}

func TestSignOutAbsentCredentialDoesNotExecuteOrRead(t *testing.T) {
	reader, get, _, _, config, _ := validationFixture(t)
	reader, _ = session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
		t.Fatal("absent credential read")
		return session.SessionObservation{}, nil
	}), config)
	executor := revokeExecutor(func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
		t.Fatal("absent credential executed")
		return identity.CommandResult{}, nil
	})
	service, err := session.NewSignOutService(reader, executor, signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignOut(context.Background(), session.SignOutRequest{TenantID: get.TenantID, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "correlation-a", Transport: session.CredentialCookie})
	if err != nil || !result.SignedOut || !result.ClearCookie || result.ClearBearer || result.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("absent logout", err)
	}
}

func signOutReceipt(t *testing.T, r session.RevokeOneRequest, outcome identity.CommitOutcome) identity.CommandResult {
	t.Helper()
	command, ok := r.Command()
	one, valid := command.RevokeOne()
	if !ok || !valid {
		t.Fatal("missing original target")
	}
	spec, _ := one.Session.Bindings()
	result := identity.CommandResult{Binding: one.Binding, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: session.RevokeOneOperation()}}
	if outcome == identity.CommitOutcomeCommitted {
		result.AuditEventID = "audit-signout"
		result.Feature.BeforeVersion = spec.Version
		result.Feature.AfterVersion = spec.Version + 1
	}
	if outcome == identity.CommitOutcomeInProgress {
		result.RetryAfter = time.Second
	}
	if err := result.Validate(); err != nil {
		t.Fatal("invalid test receipt", err)
	}
	return result
}

func TestSignOutPreservesOutcomesAndNeverClearsOnFailure(t *testing.T) {
	for _, mode := range []string{"not-committed", "unknown", "conflict", "in-progress", "denied", "unavailable", "panic", "invalid", "wrong-scope", "wrong-version", "committed-error", "committed-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			reader, get, _, observed, _, _ := validationFixture(t)
			spec, _ := observed.Session.Bindings()
			b := issueBinding(spec)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := identity.CommitOutcomeUnknown
			executor := revokeExecutor(func(_ context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
				switch mode {
				case "not-committed":
					want = identity.CommitOutcomeNotCommitted
					return signOutReceipt(t, r, want), nil
				case "unknown":
					return signOutReceipt(t, r, want), errors.New("private database details")
				case "conflict":
					want = identity.CommitOutcomeConflict
					return signOutReceipt(t, r, want), nil
				case "in-progress":
					want = identity.CommitOutcomeInProgress
					return signOutReceipt(t, r, want), nil
				case "denied":
					want = identity.CommitOutcomeInvalid
					return identity.CommandResult{}, identity.ForbiddenError{}
				case "unavailable":
					return identity.CommandResult{}, errors.New("private database details")
				case "panic":
					panic("private database details")
				case "invalid":
					return identity.CommandResult{}, nil
				case "wrong-scope":
					receipt := signOutReceipt(t, r, identity.CommitOutcomeCommitted)
					receipt.Binding.RecordID = "foreign"
					return receipt, nil
				case "wrong-version":
					receipt := signOutReceipt(t, r, identity.CommitOutcomeCommitted)
					receipt.Feature.BeforeVersion++
					receipt.Feature.AfterVersion++
					return receipt, nil
				case "committed-error":
					want = identity.CommitOutcomeCommitted
					return signOutReceipt(t, r, want), errors.New("private database details")
				case "committed-cancelled":
					want = identity.CommitOutcomeCommitted
					cancel()
					return signOutReceipt(t, r, want), nil
				default:
					panic("unreachable fixture")
				}
			})
			service, err := session.NewSignOutService(reader, executor, signOutConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.SignOut(ctx, session.SignOutRequest{TenantID: get.TenantID, CommandID: b.CommandID, CorrelationID: b.CorrelationID, Credential: get.Credential, Transport: session.CredentialCookie})
			if err == nil || strings.Contains(err.Error(), "private") || out.CommitOutcome != want || out.CommandID != b.CommandID || out.Recovery.RecordID != spec.SessionID || out.SignedOut || out.ClearCookie || out.ClearBearer || !reflect.DeepEqual(out.Cookie, http.Cookie{}) {
				t.Fatal("failure became successful logout or lost outcome", err)
			}
			if want == identity.CommitOutcomeUnknown {
				var unknown identity.UnknownCommitError
				if !errors.As(err, &unknown) || unknown.CommandID != b.CommandID {
					t.Fatal("ambiguity lost", err)
				}
			}
			if mode == "denied" {
				var denied identity.ForbiddenError
				if !errors.As(err, &denied) {
					t.Fatal("denial lost", err)
				}
			}
			if mode == "committed-cancelled" {
				var cancelled identity.CancelledError
				if !errors.As(err, &cancelled) {
					t.Fatal("cancellation lost", err)
				}
			}
			if mode == "in-progress" && out.RetryAfter != time.Second {
				t.Fatal("retry metadata lost")
			}
		})
	}
}

func TestSignOutReaderFailuresAndInvalidInputNeverExecute(t *testing.T) {
	for _, mode := range []string{"reader-error", "reader-panic", "cancelled", "transport", "tenant", "command", "correlation", "nil-context"} {
		t.Run(mode, func(t *testing.T) {
			_, get, _, observed, config, _ := validationFixture(t)
			reader, err := session.NewSessionService(observedSession(func(context.Context, session.SessionLookup) (session.SessionObservation, error) {
				if mode == "reader-panic" {
					panic("private reader state")
				}
				if mode == "reader-error" {
					return session.SessionObservation{}, errors.New("private reader state")
				}
				return *observed, nil
			}), config)
			if err != nil {
				t.Fatal(err)
			}
			service, err := session.NewSignOutService(reader, revokeExecutor(func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
				t.Fatal("failure executed")
				return identity.CommandResult{}, nil
			}), signOutConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			r := session.SignOutRequest{TenantID: get.TenantID, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "correlation-a", Credential: get.Credential, Transport: session.CredentialCookie}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "cancelled":
				cancel()
			case "transport":
				r.Transport = session.CredentialBearer
			case "tenant":
				r.TenantID = ""
			case "command":
				r.CommandID = "invalid"
			case "correlation":
				r.CorrelationID = ""
			case "nil-context":
				ctx = nil
			}
			out, err := service.SignOut(ctx, r)
			if err == nil || strings.Contains(err.Error(), "private") || out.SignedOut || out.ClearCookie || out.ClearBearer || out.CommitOutcome != identity.CommitOutcomeInvalid {
				t.Fatal("pre-execution failure fabricated result", err)
			}
		})
	}
}

func TestSignOutConfigurationAndSerialization(t *testing.T) {
	reader, _, _, _, _, _ := validationFixture(t)
	executor := revokeExecutor(func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error) {
		t.Fatal("construction performed IO")
		return identity.CommandResult{}, nil
	})
	for _, mode := range []string{"reader", "executor", "policy", "version", "cookie", "duration"} {
		config := signOutConfig(t)
		configuredReader := reader
		var configuredExecutor session.RevokeOneExecutor = executor
		switch mode {
		case "reader":
			configuredReader = nil
		case "executor":
			configuredExecutor = revokeExecutor(nil)
		case "policy":
			config.PolicyID = "invalid policy"
		case "version":
			config.PolicyVersion = 0
		case "cookie":
			config.Cookie = session.CookiePolicy{}
		case "duration":
			config.MaximumDuration = 31 * time.Second
		}
		if service, err := session.NewSignOutService(configuredReader, configuredExecutor, config); err == nil || service != nil {
			t.Fatal("invalid configuration accepted", mode)
		}
	}
	service, err := session.NewSignOutService(reader, executor, signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{session.SignOutRequest{TenantID: "private-tenant"}, session.SignOutResult{CommandID: "private-command"}, signOutConfig(t), service} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("scope serialized")
		}
		for _, verb := range []string{"%v", "%#v", "%x"} {
			if got := fmt.Sprintf(verb, v); !strings.Contains(got, "redacted") || strings.Contains(got, "private") {
				t.Fatal("scope formatted")
			}
		}
	}
}

func TestSignOutDoesNotRequireFreshLogin(t *testing.T) {
	reader, get, clock, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: 24 * time.Hour, RefreshAfter: 12 * time.Hour, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	spec.Remember = policy
	observed.Session, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = spec.IssuedAt.Add(time.Hour)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	life, err := observed.Session.Lifetime(clock.now)
	if err != nil || life.Fresh {
		t.Fatal("nonfresh fixture invalid")
	}
	service, err := session.NewSignOutService(reader, revokeExecutor(func(_ context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
		return signOutReceipt(t, r, identity.CommitOutcomeCommitted), nil
	}), signOutConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignOut(context.Background(), session.SignOutRequest{TenantID: get.TenantID, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "correlation-a", Credential: get.Credential, Transport: session.CredentialCookie})
	if err != nil || !result.SignedOut || result.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("ordinary logout required fresh authentication", err)
	}
}

func TestSignOutBoundsExecutorWithoutInventingRollback(t *testing.T) {
	reader, get, _, _, _, _ := validationFixture(t)
	config := signOutConfig(t)
	config.MaximumDuration = 100 * time.Millisecond
	service, err := session.NewSignOutService(reader, revokeExecutor(func(ctx context.Context, _ session.RevokeOneRequest) (identity.CommandResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("executor unbounded")
		}
		<-ctx.Done()
		return identity.CommandResult{}, ctx.Err()
	}), config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignOut(context.Background(), session.SignOutRequest{TenantID: get.TenantID, CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", CorrelationID: "correlation-a", Credential: get.Credential, Transport: session.CredentialCookie})
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || result.CommitOutcome != identity.CommitOutcomeUnknown || result.SignedOut || result.ClearCookie {
		t.Fatal("timeout proved rollback or successful logout", err)
	}
}
