package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type mutableIssueClock struct {
	now      time.Time
	panicNow bool
}

func (c *mutableIssueClock) Now() time.Time {
	if c.panicNow {
		panic("private clock detail")
	}
	return c.now
}

func issuerFixture(t *testing.T) (*session.SessionIssuer, session.PreparedIssuance, *issueExecutor, *mutableIssueClock) {
	t.Helper()
	c, authority, proof, now := issueRequestFixture(t)
	i, _ := c.Issue()
	spec, _ := i.Session.Bindings()
	spec.Lookup = session.TokenDigest{}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	clock := &mutableIssueClock{now: now}
	executor := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedIssue(r), nil
	}, recover: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		return committedIssue(r), nil
	}}
	issuer, err := session.NewSessionIssuer(executor, session.IssuerConfig{Authority: authority, Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	p, err := issuer.Prepare(i.Binding, spec, proof)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, p, executor, clock
}

func requireNoIssuedToken(t *testing.T, r session.IssueResult) {
	t.Helper()
	if _, err := r.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) || !reflect.DeepEqual(r.Cookie, http.Cookie{}) {
		t.Fatal("non-deliverable outcome disclosed credential/transport")
	}
}

func TestSessionIssuerRetainsAllAuthoritativeOutcomesWithoutSecretDelivery(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeNotCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress} {
		t.Run(fmt.Sprint(outcome), func(t *testing.T) {
			issuer, p, executor, _ := issuerFixture(t)
			executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e := committedIssue(r)
				e.Receipt.Outcome = outcome
				e.Receipt.AuditEventID = ""
				e.Receipt.Feature.BeforeVersion = 0
				e.Receipt.Feature.AfterVersion = 0
				e.Session = session.Session{}
				if outcome == identity.CommitOutcomeInProgress {
					e.Receipt.RetryAfter = time.Second
				}
				return e, errors.New("secret dependency detail")
			}
			got, err := issuer.Issue(context.Background(), p)
			if err == nil || got.CommitOutcome != outcome {
				t.Fatal("lost durable outcome", err)
			}
			requireNoIssuedToken(t, got)
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("dependency detail escaped")
			}
			if got.Session != (session.Session{}) {
				t.Fatal("noncommitted payload")
			}
			switch outcome {
			case identity.CommitOutcomeNotCommitted:
				var e identity.NotCommittedError
				if !errors.As(err, &e) {
					t.Fatal("wrong classification")
				}
			case identity.CommitOutcomeUnknown:
				var e identity.UnknownCommitError
				if !errors.As(err, &e) {
					t.Fatal("wrong classification")
				}
			case identity.CommitOutcomeConflict:
				var e identity.ConflictError
				if !errors.As(err, &e) {
					t.Fatal("wrong classification")
				}
			case identity.CommitOutcomeInProgress:
				var e identity.InProgressError
				if !errors.As(err, &e) || e.RetryAfter != time.Second || got.RetryAfter != time.Second {
					t.Fatal("lost retry delay")
				}
			}
		})
	}
}

func TestSessionIssuerRejectsMalformedOrSubstitutedExecution(t *testing.T) {
	for name, mutate := range map[string]func(*session.IssueExecution){
		"zero":    func(e *session.IssueExecution) { *e = session.IssueExecution{} },
		"binding": func(e *session.IssueExecution) { e.Receipt.Binding.CorrelationID = "different" },
		"feature": func(e *session.IssueExecution) { e.Receipt.Feature = nil },
		"version": func(e *session.IssueExecution) {
			e.Receipt.Feature.BeforeVersion = 1
			e.Receipt.Feature.AfterVersion = 2
		},
		"missing-record": func(e *session.IssueExecution) { e.Session = session.Session{} },
		"digest": func(e *session.IssueExecution) {
			s, _ := e.Session.Bindings()
			s.Lookup.Sum[0] ^= 255
			e.Session, _ = session.NewSession(s)
		},
		"family": func(e *session.IssueExecution) {
			s, _ := e.Session.Bindings()
			s.FamilyID = "another-family"
			e.Session, _ = session.NewSession(s)
		},
		"policy": func(e *session.IssueExecution) {
			s, _ := e.Session.Bindings()
			s.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, config())
			e.Session, _ = session.NewSession(s)
		},
		"authority": func(e *session.IssueExecution) {
			s, _ := e.Session.Bindings()
			a, _ := s.Authority.Bindings()
			a.User.Version++
			s.Authority, _ = session.NewAuthoritySnapshot(a)
			e.Session, _ = session.NewSession(s)
		},
		"credential": func(e *session.IssueExecution) {
			s, _ := e.Session.Bindings()
			s.Authentication.CredentialVersion++
			e.Session, _ = session.NewSession(s)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer, p, executor, _ := issuerFixture(t)
			executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e := committedIssue(r)
				mutate(&e)
				return e, nil
			}
			got, err := issuer.Issue(context.Background(), p)
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || got.CommitOutcome != identity.CommitOutcomeUnknown || got.Session != (session.Session{}) {
				t.Fatal("malformed receipt admitted", err)
			}
			requireNoIssuedToken(t, got)
		})
	}
}

func TestSessionIssuerWithholdsBearerOnReplayErrorCancellationAndExpiredDelivery(t *testing.T) {
	for _, mode := range []string{"replay", "dependency-error", "cancelled", "expired", "panic", "clock-panic"} {
		t.Run(mode, func(t *testing.T) {
			issuer, p, executor, clock := issuerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				e := committedIssue(r)
				switch mode {
				case "replay":
					e.Replayed = true
				case "dependency-error":
					return e, errors.New("private-detail")
				case "cancelled":
					cancel()
				case "expired":
					clock.now = clock.now.Add(24 * time.Hour)
				case "panic":
					panic("private-detail")
				case "clock-panic":
					clock.panicNow = true
				}
				return e, nil
			}
			got, err := issuer.Issue(ctx, p)
			requireNoIssuedToken(t, got)
			if mode == "panic" {
				if got.CommitOutcome != identity.CommitOutcomeUnknown || err == nil {
					t.Fatal("panic inferred known outcome")
				}
			} else if got.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("lost authoritative commit", err)
			}
			if mode == "replay" {
				if err != nil || !got.Replayed {
					t.Fatal("wrong replay result")
				}
			} else if err == nil {
				t.Fatal("delivery failure concealed")
			}
		})
	}
}

func TestSessionIssuerRecoveryNeverRegeneratesOrRedeliversBearer(t *testing.T) {
	issuer, p, executor, clock := issuerFixture(t)
	executor.execute = func(context.Context, session.IssueRequest) (session.IssueExecution, error) {
		return session.IssueExecution{}, errors.New("lost commit response")
	}
	got, err := issuer.Issue(context.Background(), p)
	if err == nil || got.CommitOutcome != identity.CommitOutcomeUnknown {
		t.Fatal("missing unknown outcome")
	}
	requireNoIssuedToken(t, got)
	request, _ := p.Request()
	clock.now = clock.now.Add(time.Hour)
	got, err = issuer.Recover(context.Background(), request)
	if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || !got.Replayed {
		t.Fatal("safe historical recovery failed", err)
	}
	requireNoIssuedToken(t, got)
	c, _ := request.Command()
	i, _ := c.Issue()
	stored, _ := got.Session.Bindings()
	original, _ := i.Session.Bindings()
	if stored.Lookup != original.Lookup || stored.Remember != original.Remember {
		t.Fatal("recovery changed issuance")
	}
	proof, ok := request.AuthenticatedProof()
	if !ok || proof.Bindings().CredentialID != original.Authentication.CredentialID {
		t.Fatal("lost original opaque proof")
	}
	if _, ok := (session.IssueRequest{}).AuthenticatedProof(); ok {
		t.Fatal("zero proof accessor")
	}
}

func TestSessionIssuerConcurrentCopiesHaveOneExecutionAndOneReveal(t *testing.T) {
	issuer, p, executor, _ := issuerFixture(t)
	var executions, winners atomic.Int32
	executor.execute = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		executions.Add(1)
		return committedIssue(r), nil
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := issuer.Issue(context.Background(), p)
			if err == nil {
				if _, e := got.Token.Reveal(); e != nil {
					t.Error("winner lost original token")
				}
				winners.Add(1)
			} else if !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Error("unexpected concurrent outcome", err)
			}
		}()
	}
	wg.Wait()
	if executions.Load() != 1 || winners.Load() != 1 {
		t.Fatal("duplicate execution/delivery")
	}
}

func TestSessionIssuerPreparationAndResultsAreRedacted(t *testing.T) {
	issuer, p, _, _ := issuerFixture(t)
	got, err := issuer.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{p, got} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			wire := fmt.Sprintf(verb, v)
			if strings.Contains(wire, "session-a") || strings.Contains(wire, "tenant-a") || strings.Contains(wire, "password-a") {
				t.Fatal("format disclosure")
			}
		}
		if _, err := json.Marshal(v); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("serialization disclosure")
		}
	}
	if _, err := p.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("text disclosure")
	}
	if _, err := got.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
		t.Fatal("text disclosure")
	}
}

func TestSessionIssuerRejectsInvalidCompositionAndPreAttemptRequests(t *testing.T) {
	c, authority, proof, now := issueRequestFixture(t)
	issue, _ := c.Issue()
	spec, _ := issue.Session.Bindings()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	cfg := session.IssuerConfig{Authority: authority, Clock: issueClock{now}, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}
	executor := &issueExecutor{}
	for _, change := range []func(*session.IssuerConfig){func(c *session.IssuerConfig) { c.Authority = nil }, func(c *session.IssuerConfig) { c.Clock = nil }, func(c *session.IssuerConfig) { c.Clock = (*mutableIssueClock)(nil) }, func(c *session.IssuerConfig) { c.MaximumDuration = 0 }, func(c *session.IssuerConfig) { c.MaximumDuration = 31 * time.Second }, func(c *session.IssuerConfig) { c.LookupKey = session.DigestKey{} }, func(c *session.IssuerConfig) { c.TokenSize = 31 }, func(c *session.IssuerConfig) { c.TokenSize = 65 }, func(c *session.IssuerConfig) { c.Cookie = session.CookiePolicy{} }} {
		bad := cfg
		change(&bad)
		if got, err := session.NewSessionIssuer(executor, bad); !errors.Is(err, session.ErrInvalidIssuer) || got != nil {
			t.Fatal("invalid composition accepted")
		}
	}
	for _, bad := range []session.IssueExecutor{nil, (*issueExecutor)(nil)} {
		if _, err := session.NewSessionIssuer(bad, cfg); !errors.Is(err, session.ErrInvalidIssuer) {
			t.Fatal("nil executor accepted")
		}
	}
	issuer, _ := session.NewSessionIssuer(executor, cfg)
	if _, err := issuer.Prepare(issue.Binding, spec, proof); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("caller-selected lookup accepted")
	}
	spec.Lookup = session.TokenDigest{}
	_, foreign, foreignProof, _ := issueRequestFixture(t)
	_ = foreign
	if _, err := issuer.Prepare(issue.Binding, spec, foreignProof); err == nil {
		t.Fatal("foreign private provenance accepted")
	}
	spec.Remember = session.RememberPolicy{}
	if _, err := issuer.Prepare(issue.Binding, spec, proof); !errors.Is(err, session.ErrInvalidSession) {
		t.Fatal("unresolved remember choice accepted")
	}
	valid, p, _, clock := issuerFixture(t)
	request, _ := p.Request()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		got, err := valid.Issue(ctx, p)
		if err == nil || got.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("invalid context made an attempt")
		}
		requireNoIssuedToken(t, got)
		got, err = valid.Recover(ctx, request)
		if err == nil || got.CommitOutcome != identity.CommitOutcomeInvalid {
			t.Fatal("invalid recovery context observed outcome")
		}
	}
	if got, err := issuer.Issue(context.Background(), p); !errors.Is(err, session.ErrInvalidIssuance) || got.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("foreign preparation accepted")
	}
	if _, err := valid.Issue(context.Background(), session.PreparedIssuance{}); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("zero preparation accepted")
	}
	if _, err := valid.Recover(context.Background(), session.IssueRequest{}); !errors.Is(err, session.ErrInvalidIssuance) {
		t.Fatal("zero recovery accepted")
	}
	if _, ok := (session.PreparedIssuance{}).Request(); ok {
		t.Fatal("zero request projection")
	}
	clock.now = proof.Bindings().Proof.ExpiresAt.Add(time.Hour)
	got, err := valid.Issue(context.Background(), p)
	if err == nil || got.CommitOutcome != identity.CommitOutcomeInvalid {
		t.Fatal("expired original proof attempted")
	}
}

func TestSessionIssuerPersistentCookieUsesOriginalAbsoluteDeadline(t *testing.T) {
	c, authority, proof, now := issueRequestFixtureWith(t, func(s *session.SessionSpec) {
		s.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, config())
	})
	i, _ := c.Issue()
	spec, _ := i.Session.Bindings()
	spec.Lookup = session.TokenDigest{}
	clock := &mutableIssueClock{now: now}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	executor := &issueExecutor{execute: func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		clock.now = now.Add(10 * time.Second)
		e := committedIssue(r)
		stored, _ := e.Session.Bindings()
		stored.IssuedAt = stored.IssuedAt.In(time.FixedZone("db", 3600))
		e.Session, _ = session.NewSession(stored)
		return e, nil
	}}
	issuer, err := session.NewSessionIssuer(executor, session.IssuerConfig{Authority: authority, Clock: clock, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	p, err := issuer.Prepare(i.Binding, spec, proof)
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cookie.MaxAge != int((7*24*time.Hour-10*time.Second)/time.Second) || !got.Cookie.Expires.Equal(now.Add(7*24*time.Hour)) {
		t.Fatal("cookie renewed original lifetime")
	}
}

func TestSessionIssuerRecoveryHandlesMalformedAndPanickingAuthority(t *testing.T) {
	for _, mode := range []string{"panic", "malformed", "cancelled", "not-committed"} {
		t.Run(mode, func(t *testing.T) {
			issuer, p, executor, _ := issuerFixture(t)
			request, _ := p.Request()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor.recover = func(_ context.Context, r session.IssueRequest) (session.IssueExecution, error) {
				switch mode {
				case "panic":
					panic("private")
				case "malformed":
					return session.IssueExecution{}, nil
				case "cancelled":
					cancel()
					return committedIssue(r), nil
				default:
					e := committedIssue(r)
					e.Receipt.Outcome = identity.CommitOutcomeNotCommitted
					e.Receipt.AuditEventID = ""
					e.Receipt.Feature.AfterVersion = 0
					e.Session = session.Session{}
					return e, nil
				}
			}
			got, err := issuer.Recover(ctx, request)
			if err == nil {
				t.Fatal("recovery failure concealed")
			}
			requireNoIssuedToken(t, got)
			want := identity.CommitOutcomeUnknown
			if mode == "cancelled" {
				want = identity.CommitOutcomeCommitted
			}
			if mode == "not-committed" {
				want = identity.CommitOutcomeNotCommitted
			}
			if got.CommitOutcome != want {
				t.Fatal("wrong recovery outcome")
			}
		})
	}
}

type issueExecutor struct {
	execute func(context.Context, session.IssueRequest) (session.IssueExecution, error)
	recover func(context.Context, session.IssueRequest) (session.IssueExecution, error)
}

func (e *issueExecutor) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	return e.execute(ctx, r)
}
func (e *issueExecutor) RecoverIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	return e.recover(ctx, r)
}

func committedIssue(r session.IssueRequest) session.IssueExecution {
	c, _ := r.Command()
	i, _ := c.Issue()
	return session.IssueExecution{Receipt: identity.CommandResult{Binding: i.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.IssueOperation(), BeforeVersion: 0, AfterVersion: 1}}, Session: i.Session}
}

func TestSessionIssuerDeliversOnlyExactCommittedOriginalToken(t *testing.T) {
	c, authority, proof, now := issueRequestFixture(t)
	i, _ := c.Issue()
	spec, _ := i.Session.Bindings()
	spec.Lookup = session.TokenDigest{}
	key, err := session.NewDigestKey(3, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	executor := &issueExecutor{execute: func(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded execution")
		}
		return committedIssue(r), nil
	}}
	issuer, err := session.NewSessionIssuer(executor, session.IssuerConfig{Authority: authority, Clock: issueClock{now}, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(i.Binding, spec, proof)
	if err != nil {
		t.Fatal(err)
	}
	request, ok := prepared.Request()
	if !ok {
		t.Fatal("missing request")
	}
	result, err := issuer.Issue(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if result.CommitOutcome != identity.CommitOutcomeCommitted || result.Cookie.Value != "" || result.Cookie.Name != "__Host-session" || result.Cookie.MaxAge != 0 || !result.Cookie.Expires.IsZero() {
		t.Fatal("wrong transport/outcome")
	}
	wire, err := result.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := result.Session.Bindings()
	if stored.Lookup != digest || stored.Remember != spec.Remember || stored.Authentication != spec.Authentication {
		t.Fatal("original issuance changed")
	}
	original, _ := request.Command()
	oi, _ := original.Issue()
	originalSpec, _ := oi.Session.Bindings()
	if originalSpec.Lookup != digest {
		t.Fatal("unbound bearer")
	}
	if _, err := result.Token.Reveal(); err != session.ErrTokenAlreadyRevealed {
		t.Fatal("bearer revealed twice")
	}
	if _, err := issuer.Issue(context.Background(), prepared); err != session.ErrIssuanceAlreadyAttempted {
		t.Fatal("same preparation executed twice")
	}
}
