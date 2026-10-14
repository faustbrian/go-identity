package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rotationExecutor struct {
	execute func(context.Context, session.RotationRequest) (session.RotationExecution, error)
	recover func(context.Context, session.RotationRequest) (session.RotationExecution, error)
}

func (e *rotationExecutor) ExecuteRotation(ctx context.Context, r session.RotationRequest) (session.RotationExecution, error) {
	return e.execute(ctx, r)
}
func (e *rotationExecutor) RecoverRotation(ctx context.Context, r session.RotationRequest) (session.RotationExecution, error) {
	return e.recover(ctx, r)
}
func committedRotation(r session.RotationRequest) session.RotationExecution {
	command, _ := r.Command()
	rotation, _ := command.Rotation()
	source, _ := rotation.Source.Bindings()
	next, _ := rotation.Successor.Bindings()
	return session.RotationExecution{Receipt: identity.CommandResult{Binding: rotation.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.RotateOperation(), BeforeVersion: source.Version, AfterVersion: next.Version}}, Session: rotation.Successor}
}
func rotationFixture(t *testing.T) (*session.SessionRotator, session.PreparedRotation, *rotationExecutor, *mutableIssueClock, *session.SessionService, session.GetResult) {
	return rotationTransportFixture(t, session.CredentialCookie)
}
func rotationTransportFixture(t *testing.T, transport session.CredentialKind) (*session.SessionRotator, session.PreparedRotation, *rotationExecutor, *mutableIssueClock, *session.SessionService, session.GetResult) {
	t.Helper()
	_, input, clock, observed, validation, backend := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy := config()
	policy.FreshFor = 15 * time.Minute
	spec.Remember, _ = session.ResolveRememberPolicy(session.BrowserSession, policy)
	if transport == session.CredentialBearer {
		token, err := session.NewToken(32)
		if err != nil {
			t.Fatal(err)
		}
		spec.Lookup, _ = token.Digest(validation.LookupKeys[0], string(spec.TenantID))
		input.Credential, _ = session.NewCredential(transport, token)
	}
	var err error
	observed.Session, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewDigestKey(2, make([]byte, 32))
	validation.LookupKeys = append(validation.LookupKeys, key)
	reader, err := session.NewSessionService(backend, validation)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = spec.LastActivityAt.Add(12 * time.Hour)
	observed.ReadStartedAt, observed.ValidUntil = clock.now, clock.now.Add(20*time.Second)
	caller, err := reader.Get(context.Background(), input)
	if err != nil || !caller.Authenticated {
		t.Fatal("rotation source", err)
	}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	executor := &rotationExecutor{execute: func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
		return committedRotation(r), nil
	}, recover: func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
		return committedRotation(r), nil
	}}
	rotator, err := session.NewSessionRotator(reader, executor, session.RotationConfig{PolicyID: "session-policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rotator.Prepare(caller, "AQEBAQEBAQEBAQEBAQEBAQ", "rotation")
	if err != nil {
		t.Fatal(err)
	}
	return rotator, p, executor, clock, reader, caller
}
func TestRotationPreservesOriginalAuthorityAndRevealsOnlyNewCommit(t *testing.T) {
	rotator, p, _, clock, reader, caller := rotationFixture(t)
	request, ok := p.Request()
	if !ok || request.Validate(reader, clock.now) != nil || !request.ValidUntil().Equal(caller.ValidUntil()) {
		t.Fatal("original custody lost")
	}
	command, _ := request.Command()
	rotation, _ := command.Rotation()
	old, _ := rotation.Source.Bindings()
	next, _ := rotation.Successor.Bindings()
	oldLife, _ := rotation.Source.Lifetime(clock.now)
	nextLife, _ := rotation.Successor.Lifetime(clock.now)
	if oldLife.Fresh || nextLife.Fresh || !oldLife.AbsoluteExpiresAt.Equal(nextLife.AbsoluteExpiresAt) {
		t.Fatal("rotation renewed authentication or absolute lifetime")
	}
	vector, _ := next.Authority.Bindings()
	originalVector, _ := old.Authority.Bindings()
	if next.SessionID != old.SessionID || next.FamilyID != old.FamilyID || next.FamilyVersion != old.FamilyVersion || next.IssuedAt != old.IssuedAt || next.Authentication != old.Authentication || next.Remember != old.Remember || next.Version != old.Version+1 || next.Lookup == old.Lookup || next.Lookup.KeyVersion != 2 || !next.LastActivityAt.Equal(clock.now) {
		t.Fatal("rotation renewed or substituted source")
	}
	vector.Session.Version = originalVector.Session.Version
	if vector != originalVector {
		t.Fatal("rotation changed unrelated authority")
	}
	got, err := rotator.Rotate(context.Background(), p)
	if err != nil || got.CommitOutcome != identity.CommitOutcomeCommitted || got.Transport != session.CredentialCookie || got.Cookie.Value != "" || got.Cookie.Name != "__Host-session" || got.Recovery.RecordID != old.SessionID {
		t.Fatal("rotation delivery", err)
	}
	wire, err := got.Token.Reveal()
	if err != nil || wire == "" {
		t.Fatal("committed successor missing")
	}
	if _, err = got.Token.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("rotation revealed twice")
	}
	if _, err = rotator.Rotate(context.Background(), p); !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
		t.Fatal("preparation reused", err)
	}
	recovered, err := rotator.Recover(context.Background(), request)
	if err != nil || recovered.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("historical recovery", err)
	}
	if _, err = recovered.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) || !reflect.DeepEqual(recovered.Cookie, http.Cookie{}) {
		t.Fatal("recovery disclosed successor")
	}
}

func TestRotationPreservesBearerTransportWithoutCookie(t *testing.T) {
	rotator, p, _, _, _, _ := rotationTransportFixture(t, session.CredentialBearer)
	request, _ := p.Request()
	if request.Transport() != session.CredentialBearer {
		t.Fatal("original bearer lost")
	}
	got, err := rotator.Rotate(context.Background(), p)
	if err != nil || got.Transport != session.CredentialBearer || !reflect.DeepEqual(got.Cookie, http.Cookie{}) {
		t.Fatal("bearer changed transport", err)
	}
	if wire, err := got.Token.Reveal(); err != nil || wire == "" {
		t.Fatal("bearer delivery missing", err)
	}
}

func TestRotationCancellationBeforeEntryPreservesPreparation(t *testing.T) {
	rotator, p, executor, _, _, _ := rotationFixture(t)
	entered := false
	executor.execute = func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
		entered = true
		return committedRotation(r), nil
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	got, err := rotator.Rotate(ctx, p)
	if err == nil || entered || got.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("cancelled call entered", err)
	}
	if _, err := got.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) {
		t.Fatal("cancelled call delivered")
	}
	if got, err = rotator.Rotate(context.Background(), p); err != nil || !entered || got.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("unattempted preparation lost", err)
	}
}
func TestRotationNoDeliveryForUnknownReplayErrorOrExpiredAdmission(t *testing.T) {
	for _, mode := range []string{"unknown", "replay", "error", "expired", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			rotator, p, executor, clock, _, _ := rotationFixture(t)
			executor.execute = func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
				e := committedRotation(r)
				switch mode {
				case "unknown":
					e.Receipt.Outcome = identity.CommitOutcomeUnknown
					e.Receipt.AuditEventID = ""
					e.Receipt.Feature.BeforeVersion = 0
					e.Receipt.Feature.AfterVersion = 0
					e.Session = session.Session{}
				case "replay":
					e.Replayed = true
				case "error":
					return e, errors.New("private dependency text")
				case "expired":
					clock.now = r.ValidUntil()
				case "malformed":
					e.Receipt.Feature.AfterVersion++
				}
				return e, nil
			}
			got, err := rotator.Rotate(context.Background(), p)
			if mode != "replay" && err == nil {
				t.Fatal("non-success accepted")
			}
			if _, err := got.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) || !reflect.DeepEqual(got.Cookie, http.Cookie{}) {
				t.Fatal("unsafe delivery")
			}
			if (mode == "error" || mode == "expired") && got.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("known commitment lost")
			}
		})
	}
}

func TestRotationRejectsForgedForeignExpiredAndDeferredPreparation(t *testing.T) {
	for _, mode := range []string{"forged", "foreign-reader", "expired", "backward", "deferred", "clock-panic", "wrong-command"} {
		t.Run(mode, func(t *testing.T) {
			rotator, p, _, clock, reader, caller := rotationFixture(t)
			request, _ := p.Request()
			command, _ := request.Command()
			native, _ := command.Rotation()
			switch mode {
			case "forged":
				caller = session.GetResult{Authenticated: true, Session: caller.Session, NeedsRefresh: caller.NeedsRefresh, RefreshEligibleAt: caller.RefreshEligibleAt}
			case "foreign-reader":
				foreign := *reader
				if request.Validate(&foreign, clock.now) == nil {
					t.Fatal("copied reader gained custody")
				}
				if _, err := foreign.PrepareRotation(caller, command); err == nil {
					t.Fatal("foreign reader prepared")
				}
				return
			case "expired":
				clock.now = caller.ValidUntil()
			case "backward":
				clock.now = clock.now.Add(-time.Second)
			case "clock-panic":
				clock.panicNow = true
			case "wrong-command":
				command, _ = session.NewRevokeOneCommand(func() identity.CommandBinding {
					b := native.Binding
					op := session.RevokeOneOperation()
					b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
					return b
				}(), native.Source)
				if _, err := reader.PrepareRotation(caller, command); err == nil {
					t.Fatal("wrong command admitted")
				}
				return
			case "deferred":
				_, input, earlyClock, _, validation, backend := validationFixture(t)
				earlyReader, err := session.NewSessionService(backend, validation)
				if err != nil {
					t.Fatal(err)
				}
				early, _ := earlyReader.Get(context.Background(), input)
				cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
				earlyRotator, err := session.NewSessionRotator(earlyReader, &rotationExecutor{}, session.RotationConfig{PolicyID: "policy", PolicyVersion: 1, MaximumDuration: time.Second, LookupKey: validation.LookupKeys[0], TokenSize: 32, Cookie: cookie})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = earlyRotator.Prepare(early, "AQEBAQEBAQEBAQEBAQEBAQ", "deferred"); !errors.Is(err, session.ErrRotationDeferred) {
					t.Fatal("early rotation was not deferred", err)
				}
				_ = earlyClock
				return
			}
			if _, err := rotator.Prepare(caller, "AQEBAQEBAQEBAQEBAQEBAQ", "denied"); err == nil {
				t.Fatal("invalid caller prepared")
			}
			if _, err := reader.PrepareRotation(caller, command); err == nil {
				t.Fatal("invalid caller request prepared")
			}
		})
	}
}

func TestRotationCommandRejectsAuthorityExpansionAndPreservesNonfreshLogin(t *testing.T) {
	_, p, _, clock, reader, caller := rotationFixture(t)
	request, _ := p.Request()
	command, _ := request.Command()
	native, _ := command.Rotation()
	for _, mode := range []string{"family", "session", "user", "tenant", "audience", "policy", "authentication", "authority", "version", "digest", "future"} {
		t.Run(mode, func(t *testing.T) {
			candidate, _ := native.Successor.Bindings()
			switch mode {
			case "family":
				candidate.FamilyID = "foreign"
			case "session":
				candidate.SessionID = "foreign"
			case "user":
				candidate.UserID = "foreign"
				candidate.Authentication.Proof.Subject = "foreign"
			case "tenant":
				candidate.TenantID = "foreign"
				candidate.Authentication.Proof.Tenant = "foreign"
			case "audience":
				candidate.Audience = "foreign"
				candidate.Authentication.Proof.Audience = "foreign"
			case "policy":
				candidate.Remember, _ = session.ResolveRememberPolicy(session.PersistentSession, config())
			case "authentication":
				candidate.Authentication.Proof.IssuedAt = candidate.Authentication.Proof.IssuedAt.Add(time.Second)
			case "authority":
				vector, _ := candidate.Authority.Bindings()
				vector.User.Version++
				candidate.Authority, _ = session.NewAuthoritySnapshot(vector)
			case "version":
				candidate.Version++
				vector, _ := candidate.Authority.Bindings()
				vector.Session.Version = candidate.Version
				candidate.Authority, _ = session.NewAuthoritySnapshot(vector)
			case "digest":
				source, _ := native.Source.Bindings()
				candidate.Lookup = source.Lookup
			case "future":
				candidate.LastActivityAt = clock.now.Add(time.Second)
			}
			successor, err := session.NewSession(candidate)
			if err != nil {
				t.Fatal("structural adversarial fixture", err)
			}
			changed, err := session.NewRotateCommand(native.Binding, native.Source, successor)
			if mode == "future" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = reader.PrepareRotation(caller, changed); err == nil {
					t.Fatal("future activity accepted")
				}
			} else if err == nil {
				t.Fatal("rotation changed unrelated authority")
			}
		})
	}
	// Old sign-in proof expiration is historical. Require current owned session
	// admission, not a replacement login or a fresh timestamp during rotation.
	if native.Source == (session.Session{}) || request.Validate(reader, clock.now) != nil {
		t.Fatal("expired historical sign-in proof blocked ordinary rotation")
	}
}

func TestRotationPreparationCopiesHaveOneConcurrentDeliveryAttempt(t *testing.T) {
	rotator, p, executor, _, _, _ := rotationFixture(t)
	var calls atomic.Int32
	executor.execute = func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
		calls.Add(1)
		return committedRotation(r), nil
	}
	var committed atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(func() {
			out, err := rotator.Rotate(context.Background(), p)
			if err == nil && out.CommitOutcome == identity.CommitOutcomeCommitted {
				committed.Add(1)
			} else if !errors.Is(err, session.ErrIssuanceAlreadyAttempted) {
				t.Errorf("concurrent attempt: %v", err)
			}
		})
	}
	group.Wait()
	if calls.Load() != 1 || committed.Load() != 1 {
		t.Fatal("preparation duplicated execution")
	}
}

func TestRotationMetadataFailureCancellationPanicAndRedaction(t *testing.T) {
	for _, mode := range []string{"missing-metadata", "cancelled", "panic", "clock-after-commit"} {
		t.Run(mode, func(t *testing.T) {
			rotator, p, executor, clock, _, _ := rotationFixture(t)
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			executor.execute = func(_ context.Context, r session.RotationRequest) (session.RotationExecution, error) {
				if mode == "panic" {
					panic("private secret")
				}
				e := committedRotation(r)
				if mode == "missing-metadata" {
					e.Session = session.Session{}
					return e, errors.New("private secret")
				}
				if mode == "cancelled" {
					stop()
				}
				if mode == "clock-after-commit" {
					clock.panicNow = true
				}
				return e, nil
			}
			out, err := rotator.Rotate(ctx, p)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("failure escaped", err)
			}
			want := identity.CommitOutcomeCommitted
			if mode == "panic" {
				want = identity.CommitOutcomeUnknown
			}
			if out.CommitOutcome != want {
				t.Fatal("receipt outcome lost")
			}
			if _, err := out.Token.Reveal(); !errors.Is(err, session.ErrInvalidToken) || !reflect.DeepEqual(out.Cookie, http.Cookie{}) {
				t.Fatal("failure delivered credential")
			}
			request, _ := p.Request()
			for _, value := range []any{rotator, p, request, out, session.RotationConfig{}, session.RotationExecution{}} {
				if !strings.Contains(fmt.Sprintf("%#v", value), "redacted") {
					t.Fatal("formatting exposed linkage")
				}
				if _, err := json.Marshal(value); err == nil {
					t.Fatal("implicit serialization accepted")
				}
			}
		})
	}
}
