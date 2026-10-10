//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

// Policy is a deliberate configured callback boundary, not identity discovery
// or proof authority. SQL and all credential/issuance owners remain real.
type signinPublicPolicy struct{}

type signinPublicDenyPolicy struct{}

// Advance at the selected-user decision boundary, after the caller's earlier
// grant was computed, to prove that its authority observation cannot be renewed.
type signinPublicAdvancePolicy struct{ pool *database.Pool }

func (p signinPublicAdvancePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Resource.Type == "identity.user" {
		if _, err := p.pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND policy_namespace='users' AND subject_id=$2`, signinTestTenant, signinTestUser); err != nil {
			return authorization.Decision{}, err
		}
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

func (signinPublicDenyPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, nil
}

type signinPublicFixedClock struct{ at time.Time }

// Both callers must finish real comparison before either reserves authority.
// This is the configured policy callback, not a replacement transaction owner.
type signinPublicBarrierPolicy struct {
	arrivals atomic.Int32
	ready    chan struct{}
}

func (p *signinPublicBarrierPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Resource.Type == "identity.user" {
		if p.arrivals.Add(1) == 2 {
			close(p.ready)
		}
		select {
		case <-p.ready:
		case <-ctx.Done():
			return authorization.Decision{}, ctx.Err()
		}
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

func (c signinPublicFixedClock) Now() time.Time { return c.at }

func (signinPublicPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

func testPublicNativeSignin(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, crypto *primitive.Service, hash primitive.EncodedHash, storage sessionpg.Config, profile sessionpg.IdentifierAdmissionConfig) {
	t.Helper()
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signin-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigninSigningKey("public-signin", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, public := signer.public()
	lookup, _ := session.NewDigestKey(1, bytes.Repeat([]byte{82}, 32))
	flowKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{43}, 32))
	csrf, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{83}, 32))
	cookies, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	query := kernel.CommandQueryPolicy{Authorization: signinPublicPolicy{}, Clock: clock.System{}, PolicyVersion: 3}
	c := SigninConfig{Repository: Config{MaximumDuration: 3 * time.Second, HashPolicy: policy}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: time.Second, DummyHash: hash, Now: time.Now}, Session: storage, Profile: profile, Address: email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}, FlowKeys: []session.DigestKey{flowKey}, Issuance: session.IssuerConfig{Clock: signinTestClock{}, MaximumDuration: 2 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: cookies}, CSRFKey: csrf, Risk: signinTestRisk(t), Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &query, AdmissionPolicy: &query}, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{id: public}, Issuer: "issuer", Environment: "test", ProofTTL: time.Minute, PolicyID: "login", IdentifierKey: bytes.Repeat([]byte{84}, 32)}
	c.Origins = []string{"https://identity.test"}
	c.CallbackURLs = []string{"https://app.test/after"}
	service, err := NewSigninService(pool, c)
	if err != nil {
		t.Fatal("native public composition", err)
	}
	var workflow password.SigninService = service
	for _, mode := range []string{"commit", "commit-persistent", "wrong", "unknown", "invalid-email", "foreign-cookie", "foreign-origin", "foreign-callback", "changed-remember", "policy-advance", "rehash", "rehash-persistent", "rehash-wrong", "rehash-policy-advance", "rehash-outbox-failure", "rehash-concurrent", "rehash-expired", "rehash-cancelled", "rehash-disconnect-before", "rehash-disconnect-after"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := nativeSigninFlow(t)
			r.TenantID, r.Caller.Request.Tenant, r.Caller.Request.Subject.ID = signinTestTenant, signinTestTenant, signinTestActor
			r.Device = "synthetic-device"
			r.Identifier = "person@EXAMPLE.test"
			if mode == "commit-persistent" || mode == "rehash-persistent" {
				r.Remember, err = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
				if err != nil {
					t.Fatal("persistent policy fixture")
				}
			}
			r.PreAuthID, _ = identity.NewPreAuthTransactionID()
			now := time.Now().UTC().Truncate(time.Microsecond)
			b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{2}, Remember: r.Remember, PolicyID: c.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			if mode == "commit" {
				// A legitimate one-minute original flow close to expiry allows
				// primary-clock passage to be proven without a minute-long test.
				b.IssuedAt, b.ExpiresAt = now.Add(-57*time.Second), now.Add(3*time.Second)
			}
			token, _ := session.ParseToken(r.Cookie.Token())
			digest, _ := token.PreAuthDigest(flowKey, b)
			flow, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
			if e != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
				t.Fatal("original flow fixture")
			}
			switch mode {
			case "wrong", "rehash-wrong":
				r.Password, e = primitive.NewSecret([]byte("synthetic-password"))
				t.Cleanup(r.Password.Destroy)
			case "unknown":
				r.Identifier = "missing@example.test"
			case "invalid-email":
				r.Identifier = "not-an-email"
			case "foreign-cookie":
				r.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{85}, 32)))
			case "foreign-origin":
				r.Origin = "https://foreign.test"
			case "foreign-callback":
				r.CallbackURL = "https://foreign.test/after"
			case "changed-remember":
				r.Remember, e = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
				if e != nil {
					t.Fatal("remember substitution fixture")
				}
			}
			if mode == "commit-persistent" || mode == "wrong" || mode == "unknown" || mode == "invalid-email" {
				expected := "person@example.test"
				if mode == "unknown" || mode == "invalid-email" {
					expected = string(r.Identifier)
				}
				for count := 0; count < 2; count++ {
					canonical, err := service.SigninRateSource(ctx, r)
					if err != nil || canonical != expected {
						t.Fatal("signin source diverged from native normalization", err)
					}
				}
				unchanged, err := sessionpg.ReadPreAuth(ctx, pool.Raw(), storage, r.TenantID, r.PreAuthID)
				before, _ := flow.Bindings()
				after, e := unchanged.Bindings()
				if err != nil || e != nil || after != before {
					t.Fatal("rate source consumed or changed original flow", err)
				}
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				if canonical, err := service.SigninRateSource(canceled, r); err == nil || canonical != "" {
					t.Fatal("canceled signin source disclosed metadata")
				}
			}
			if mode == "foreign-cookie" || mode == "foreign-origin" || mode == "foreign-callback" || mode == "changed-remember" {
				if canonical, err := service.SigninRateSource(ctx, r); err == nil || canonical != "" {
					t.Fatal("foreign original custody selected a signin budget")
				}
			}
			attempt := workflow
			attemptContext := ctx
			var fault *signinCommitFault
			upgrading := strings.HasPrefix(mode, "rehash")
			current := crypto
			if upgrading {
				parameters := policy.Argon2idParameters()
				parameters.Time++
				strong, e := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: parameters, Limits: policy.Limits()})
				if e != nil {
					t.Fatal("upgrade policy fixture", e)
				}
				current, e = primitive.New(strong)
				if e != nil {
					t.Fatal("upgrade primitive fixture", e)
				}
				dummy, e := current.Hash(ctx, []byte("synthetic-dummy-only"))
				if e != nil {
					t.Fatal("upgrade dummy fixture")
				}
				changed := c
				selectedPool := pool
				if mode == "rehash-expired" {
					changed.ProofTTL = 500 * time.Millisecond
				}
				if mode == "rehash-cancelled" || strings.HasPrefix(mode, "rehash-disconnect-") {
					fault = &signinCommitFault{before: mode == "rehash-disconnect-before"}
					if mode == "rehash-cancelled" {
						var stop context.CancelFunc
						attemptContext, stop = context.WithCancel(ctx)
						defer stop()
						fault.cancel = stop
					}
					selectedPool, e = database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
					if e != nil {
						t.Fatal("fault pool unavailable")
					}
					defer func() {
						cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
						defer stop()
						if selectedPool.Close(cleanup) != nil {
							t.Error("fault pool cleanup")
						}
					}()
					changed.Coordinator.LeaseDuration = 500 * time.Millisecond
				}
				changed.Repository.HashPolicy = strong
				changed.Verifier.Primitive, changed.Verifier.DummyHash = current, dummy
				if mode == "rehash-policy-advance" {
					admission := query
					admission.Authorization = signinPublicAdvancePolicy{pool: pool}
					changed.Coordinator.AdmissionPolicy = &admission
				}
				if mode == "rehash-concurrent" {
					admission := query
					admission.Authorization = &signinPublicBarrierPolicy{ready: make(chan struct{})}
					changed.Coordinator.AdmissionPolicy = &admission
				}
				attempt, e = NewSigninService(selectedPool, changed)
				if e != nil {
					t.Fatal("upgrade composition", e)
				}
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.users SET version=11,authority_version=19,identifier_version=17,credential_version=13 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser); e != nil {
					t.Fatal(e)
				}
				defer func() {
					for _, statement := range []string{`UPDATE identity.users SET version=1,authority_version=1,identifier_version=1,credential_version=1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.credential_references SET version=7 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity_password.credentials SET version=7,encoded_hash=$3 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id=$1 AND subject_id=$2`} {
						args := []any{signinTestTenant, signinTestUser}
						if strings.Contains(statement, "$3") {
							args = append(args, hash.String())
						}
						if _, e := pool.Raw().Exec(ctx, statement, args...); e != nil {
							t.Error("restore upgrade fixture", e)
						}
					}
				}()
			}
			if mode == "policy-advance" {
				changed := c
				admission := query
				admission.Authorization = signinPublicAdvancePolicy{pool: pool}
				changed.Coordinator.AdmissionPolicy = &admission
				attempt, e = NewSigninService(pool, changed)
				if e != nil {
					t.Fatal("authority-change composition", e)
				}
				t.Cleanup(func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id=$1 AND policy_namespace='users' AND subject_id=$2`, signinTestTenant, signinTestUser); err != nil {
						t.Error("restore isolated authority fixture", err)
					}
				})
			}
			if mode == "rehash-outbox-failure" {
				if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings ADD CONSTRAINT signin_rehash_fault CHECK(false) NOT VALID`); e != nil {
					t.Fatal("outbox fault fixture", e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings DROP CONSTRAINT signin_rehash_fault`); e != nil {
						t.Error("outbox fault cleanup", e)
					}
				}()
			}
			if mode == "rehash-expired" {
				if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION public.signin_rehash_wait() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN PERFORM pg_sleep(0.6); RETURN NEW; END'; CREATE TRIGGER signin_rehash_wait BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.signin_rehash_wait()`); e != nil {
					t.Fatal("expiry wait fixture", e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER signin_rehash_wait ON public.identity_outbox_bindings; DROP FUNCTION public.signin_rehash_wait()`); e != nil {
						t.Error("expiry wait cleanup", e)
					}
				}()
			}
			var result password.SigninResult
			var signinErr error
			if mode == "rehash-concurrent" {
				other := r
				other.PreAuthID, e = identity.NewPreAuthTransactionID()
				if e != nil {
					t.Fatal(e)
				}
				otherBinding := b
				otherBinding.ID = other.PreAuthID
				otherDigest, e := token.PreAuthDigest(flowKey, otherBinding)
				if e != nil {
					t.Fatal("second cookie fixture")
				}
				otherFlow, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: otherBinding, Cookie: otherDigest, Version: 1})
				if e != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, otherFlow) != nil {
					t.Fatal("second flow fixture")
				}
				type outcome struct {
					request password.SigninRequest
					result  password.SigninResult
					err     error
				}
				outcomes := make(chan outcome, 2)
				for _, request := range []password.SigninRequest{r, other} {
					go func() { value, err := attempt.Signin(ctx, request); outcomes <- outcome{request, value, err} }()
				}
				winners := 0
				for range 2 {
					completed := <-outcomes
					if completed.result.State == auth.SignInStateAuthenticated {
						winners++
						r, result, signinErr = completed.request, completed.result, completed.err
					} else if completed.err == nil || completed.result.Issuance.Token != (session.Token{}) || completed.result.CSRFToken != (session.CSRFToken{}) {
						t.Fatal("concurrent loser disclosed authentication")
					}
				}
				if winners != 1 {
					t.Fatal("concurrent rehash did not have exactly one winner")
				}
			} else {
				result, signinErr = attempt.Signin(attemptContext, r)
			}
			if strings.HasPrefix(mode, "rehash-disconnect-") {
				checkSigninDisconnect(t, ctx, pool, service, r, result, signinErr, fault, hash, mode == "rehash-disconnect-after")
				return
			}
			if mode == "rehash-cancelled" {
				if !errors.Is(signinErr, context.Canceled) || !fault.hit.Load() {
					t.Fatal("staged cancellation classification lost")
				}
				// Driver cancellation can close the original socket before rollback
				// acknowledgement. Preserve unknown rather than inventing a receipt;
				// the unfaulted primary must reconcile the original attempt.
				if result.Issuance.CommitOutcome == identity.CommitOutcomeUnknown {
					checkSigninDisconnect(t, ctx, pool, service, r, result, signinErr, fault, hash, false)
					return
				}
			}
			var state string
			if e = pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&state); e != nil {
				t.Fatal("flow observation")
			}
			if mode != "commit" && mode != "commit-persistent" && mode != "rehash" && mode != "rehash-persistent" && mode != "rehash-concurrent" {
				if result.State == auth.SignInStateAuthenticated || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || result.Issuance.Cookie.Name != "" || state != "issued" {
					t.Fatal("neutral denial disclosed or consumed authentication")
				}
				if (mode == "wrong" || mode == "unknown" || mode == "invalid-email") && (signinErr != nil || result.Validate() != nil) {
					t.Fatal("neutral result shape differs", signinErr)
				}
				if upgrading {
					var uv, ca, cv, mv, raw string
					if e := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,r.version::text,m.version::text,m.encoded_hash FROM identity.users u JOIN identity.credential_references r USING(tenant_id,user_id) JOIN identity_password.credentials m USING(tenant_id,user_id,credential_id) WHERE u.tenant_id=$1 AND u.user_id=$2`, signinTestTenant, signinTestUser).Scan(&uv, &ca, &cv, &mv, &raw); e != nil || uv != "11" || ca != "13" || cv != "7" || mv != "7" || raw != hash.String() {
						t.Fatal("denied upgrade changed material or authority", e)
					}
					if mode == "rehash-outbox-failure" && signinErr == nil {
						t.Fatal("required outbox failure swallowed")
					}
					if (mode == "rehash-expired" || mode == "rehash-cancelled") && (signinErr == nil || result.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted) {
						t.Fatal("expired or cancelled rehash fabricated outcome")
					}
					if mode == "rehash-cancelled" && !fault.hit.Load() {
						t.Fatal("cancellation missed staged rehash")
					}
				}
				return
			}
			if signinErr != nil || result.Validate() != nil || result.State != auth.SignInStateAuthenticated || state != "consumed" || result.Issuance.Replayed {
				t.Fatal("public native login failed", signinErr)
			}
			s, _ := result.Issuance.Session.Bindings()
			wantCredential := uint64(7)
			if upgrading {
				wantCredential++
			}
			if s.UserID != signinTestUser || s.Remember != r.Remember || s.Authentication.Proof.Method != "password" || s.Authentication.CredentialVersion != wantCredential {
				t.Fatal("public orchestration lost selected authority")
			}
			if upgrading {
				var uv, ua, ia, ca, cv, mv string
				var raw string
				e := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.authority_version::text,u.identifier_version::text,u.credential_version::text,r.version::text,m.version::text,m.encoded_hash FROM identity.users u JOIN identity.credential_references r USING(tenant_id,user_id) JOIN identity_password.credentials m USING(tenant_id,user_id,credential_id) WHERE u.tenant_id=$1 AND u.user_id=$2`, signinTestTenant, signinTestUser).Scan(&uv, &ua, &ia, &ca, &cv, &mv, &raw)
				if e != nil || uv != "12" || ua != "19" || ia != "17" || ca != "14" || cv != "8" || mv != "8" {
					t.Fatal("distinct upgrade versions not atomic", e)
				}
				stored, e := primitive.ParseEncodedHash(raw, current.Policy().Limits())
				if e != nil {
					t.Fatal("stored upgrade invalid")
				}
				var comparison primitive.Result
				if e := r.Password.Use(func(raw []byte) error {
					var e error
					comparison, e = current.Verify(ctx, raw, stored.String())
					return e
				}); e != nil || !comparison.Match() || comparison.NeedsRehash() {
					t.Fatal("upgraded password unusable")
				}
			}
			if _, e = result.Issuance.Token.Reveal(); e != nil {
				t.Fatal("native bearer withheld")
			}
			if _, e = result.Issuance.Token.Reveal(); e == nil {
				t.Fatal("bearer revealed twice")
			}
			if _, e = result.CSRFToken.Reveal(); e != nil || s.SessionID != result.SessionID {
				t.Fatal("native synchronizer or identity withheld")
			}
			if (mode == "commit-persistent" || mode == "rehash-persistent") && (result.Issuance.Cookie.MaxAge <= 0 || result.Issuance.Cookie.Expires.IsZero()) || (mode == "commit" || mode == "rehash") && (result.Issuance.Cookie.MaxAge != 0 || !result.Issuance.Cookie.Expires.IsZero()) {
				t.Fatal("issued cookie lost original remember choice")
			}
			replay, replayErr := workflow.Signin(ctx, r)
			if replayErr == nil || replay.Issuance.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) || replay.Issuance.Cookie.Name != "" {
				t.Fatal("consumed pre-auth admitted another secret-bearing login")
			}
			// Recreate the native service to ensure recovery relies on durable
			// original custody and retained history, not an in-memory attempt.
			restarted, e := NewSigninService(pool, c)
			if e != nil {
				t.Fatal("restart native signin composition", e)
			}
			recovery := password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
			checkHistory := func() {
				t.Helper()
				historical, e := restarted.RecoverSignin(ctx, recovery)
				if e != nil || historical.Validate() != nil || historical.State != auth.SignInStateAuthenticated || historical.SessionID != result.SessionID || historical.Recovery != result.Recovery || historical.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || !historical.Issuance.Replayed || historical.Issuance.Session != (session.Session{}) || historical.Issuance.Token != (session.Token{}) || historical.CSRFToken != (session.CSRFToken{}) || historical.Issuance.Cookie.Name != "" {
					t.Fatal("restart recovery did not preserve credential-free original history", e)
				}
			}
			checkHistory()
			future := c
			future.Issuance.Clock = signinPublicFixedClock{at: b.ExpiresAt.Add(time.Hour)}
			expired, e := NewSigninService(pool, future)
			if e != nil {
				t.Fatal("expired history composition", e)
			}
			restarted = expired
			checkHistory()
			foreign := recovery
			foreign.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{85}, 32)))
			if denied, e := restarted.RecoverSignin(ctx, foreign); e == nil || denied.SessionID != "" || denied.Issuance.Token != (session.Token{}) {
				t.Fatal("foreign cookie disclosed signin history")
			}
			foreign = recovery
			foreign.Origin = "https://foreign.test"
			if denied, e := restarted.RecoverSignin(ctx, foreign); e == nil || denied.SessionID != "" {
				t.Fatal("foreign origin disclosed signin history")
			}
			deniedConfig := c
			deniedPolicy := query
			deniedPolicy.Authorization = signinPublicDenyPolicy{}
			deniedConfig.Coordinator.QueryPolicy = &deniedPolicy
			deniedService, e := NewSigninService(pool, deniedConfig)
			if e != nil {
				t.Fatal("current disclosure policy fixture")
			}
			if denied, e := deniedService.RecoverSignin(ctx, recovery); e == nil || denied.SessionID != "" || denied.Issuance.CommitOutcome == identity.CommitOutcomeCommitted {
				t.Fatal("earlier login policy bypassed current history denial")
			}
			if _, e := pool.Raw().Exec(ctx, `DELETE FROM signin_sessions.sessions WHERE tenant_id=$1 AND session_id=$2`, string(r.TenantID), result.SessionID); e != nil {
				t.Fatal("live session payload cleanup")
			}
			checkHistory()
			if mode == "commit" {
				var primaryNow time.Time
				if e := pool.Raw().QueryRow(ctx, `WITH waited AS MATERIALIZED (SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.01)) SELECT clock_timestamp() FROM waited`, b.ExpiresAt).Scan(&primaryNow); e != nil || primaryNow.Before(b.ExpiresAt) {
					t.Fatal("actual primary did not cross original flow expiry", e)
				}
				checkHistory()
			}
		})
	}
}

func checkSigninDisconnect(t *testing.T, ctx context.Context, pool *database.Pool, restarted *SigninService, request password.SigninRequest, original password.SigninResult, originalErr error, fault *signinCommitFault, previous primitive.EncodedHash, committed bool) {
	t.Helper()
	if originalErr == nil || fault == nil || !fault.hit.Load() || original.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || original.Issuance.Token != (session.Token{}) || original.CSRFToken != (session.CSRFToken{}) || original.Issuance.Cookie.Name != "" || original.SessionID != "" {
		t.Fatal("transport ambiguity disclosed authentication or fabricated outcome")
	}
	id, err := base64.RawURLEncoding.DecodeString(string(original.Issuance.CommandID))
	if err != nil || len(id) != 16 {
		t.Fatal("original correlation absent")
	}
	var records, audits, events int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.signin_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&records, &audits, &events); err != nil {
		t.Fatal("original effects observation", err)
	}
	want := 0
	version, authority, aggregate, outcome := "7", "13", "11", identity.CommitOutcomeNotCommitted
	if committed {
		want, version, authority, aggregate, outcome = 1, "8", "14", "12", identity.CommitOutcomeCommitted
	}
	var uv, ca, cv, mv, raw, state string
	if err := pool.Raw().QueryRow(ctx, `SELECT u.version::text,u.credential_version::text,r.version::text,m.version::text,m.encoded_hash FROM identity.users u JOIN identity.credential_references r USING(tenant_id,user_id) JOIN identity_password.credentials m USING(tenant_id,user_id,credential_id) WHERE u.tenant_id=$1 AND u.user_id=$2`, signinTestTenant, signinTestUser).Scan(&uv, &ca, &cv, &mv, &raw); err != nil || uv != aggregate || ca != authority || cv != version || mv != version || (raw == previous.String()) == committed || records != want || audits != want || events != want {
		t.Fatal("disconnect split credential and required effects", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(request.PreAuthID)).Scan(&state); err != nil || committed && state != "consumed" || !committed && state != "issued" {
		t.Fatal("disconnect split original flow", err)
	}
	recovery := password.SigninRecoveryRequest{Recovery: original.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device}
	bounded, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		history, err := restarted.RecoverSignin(bounded, recovery)
		if history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || history.Issuance.Cookie.Name != "" || history.Issuance.Session != (session.Session{}) {
			t.Fatal("ambiguous recovery recreated credential")
		}
		if history.Issuance.CommitOutcome == outcome {
			if committed && (err != nil || history.State != auth.SignInStateAuthenticated || history.SessionID == "") {
				t.Fatal("committed rehash history missing", err)
			}
			if committed {
				var sessions int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM signin_sessions.sessions s JOIN signin_sessions.families f USING(tenant_id,family_id,user_id) WHERE s.tenant_id=$1 AND s.session_id=$2 AND s.state='active'`, signinTestTenant, history.SessionID).Scan(&sessions); err != nil || sessions != 1 {
					t.Fatal("committed rehash lost actual session or family", err)
				}
			}
			break
		}
		select {
		case <-bounded.Done():
			t.Fatal("original ambiguity unresolved", err)
		case <-ticker.C:
		}
	}
	// Historical reads must not generate another hash or advance the versions.
	var after string
	if err := pool.Raw().QueryRow(ctx, `SELECT encoded_hash FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser).Scan(&after); err != nil || after != raw {
		t.Fatal("recovery replaced password again")
	}
}
