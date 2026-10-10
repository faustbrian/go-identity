//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
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
	for _, mode := range []string{"commit", "commit-persistent", "wrong", "unknown", "invalid-email", "foreign-cookie", "foreign-origin", "foreign-callback", "changed-remember", "policy-advance"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := nativeSigninFlow(t)
			r.TenantID, r.Caller.Request.Tenant, r.Caller.Request.Subject.ID = signinTestTenant, signinTestTenant, signinTestActor
			r.Device = "synthetic-device"
			r.Identifier = "person@EXAMPLE.test"
			if mode == "commit-persistent" {
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
			case "wrong":
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
			attempt := workflow
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
			result, signinErr := attempt.Signin(ctx, r)
			var state string
			if e = pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&state); e != nil {
				t.Fatal("flow observation")
			}
			if mode != "commit" && mode != "commit-persistent" {
				if result.State == auth.SignInStateAuthenticated || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || result.Issuance.Cookie.Name != "" || state != "issued" {
					t.Fatal("neutral denial disclosed or consumed authentication")
				}
				if (mode == "wrong" || mode == "unknown" || mode == "invalid-email") && (signinErr != nil || result.Validate() != nil) {
					t.Fatal("neutral result shape differs", signinErr)
				}
				return
			}
			if signinErr != nil || result.Validate() != nil || result.State != auth.SignInStateAuthenticated || state != "consumed" || result.Issuance.Replayed {
				t.Fatal("public native login failed", signinErr)
			}
			s, _ := result.Issuance.Session.Bindings()
			if s.UserID != signinTestUser || s.Remember != r.Remember || s.Authentication.Proof.Method != "password" || s.Authentication.CredentialVersion != 7 {
				t.Fatal("public orchestration lost selected authority")
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
			if mode == "commit-persistent" && (result.Issuance.Cookie.MaxAge <= 0 || result.Issuance.Cookie.Expires.IsZero()) || mode == "commit" && (result.Issuance.Cookie.MaxAge != 0 || !result.Issuance.Cookie.Expires.IsZero()) {
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
