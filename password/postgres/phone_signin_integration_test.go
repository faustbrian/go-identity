//go:build integration

package passwordpostgres

import (
	"context"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// The selected-user policy decision occurs after native factor observation.
// Withdraw that exact generation there so success requires the Work fence,
// not merely the pre-comparison/read-time check.
type phoneSigninWithdrawalPolicy struct {
	base authorization.Service
	pool *database.Pool
	once sync.Once
}

func (p *phoneSigninWithdrawalPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	decision, err := p.base.Decide(ctx, c)
	if err == nil && c.Request.Resource.Type == "identity.user" && c.Request.Action == "identity.phone.password-signin" {
		p.once.Do(func() {
			_, err = p.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(c.Request.Tenant), string(c.Request.Resource.ID))
		})
	}
	return decision, err
}

// Reuse the genuine registration, email confirmation, fresh password proof,
// encrypted SMS delivery and consuming phone verification consumer. No account,
// credential, phone, factor authority or session is manufactured for signin.
func TestNativeVerifiedPhonePasswordSigninIntegration(t *testing.T) {
	for _, mode := range []string{"sessions", "unknown", "wrong-password", "unverified", "suspended", "missing-profile", "foreign-profile", "late-profile", "retarget", "foreign-tenant", "enrolled-factor", "missing-factor", "late-factor", "late-phone", "rollback", "rehash", "concurrent", "lost-commit"} {
		t.Run(mode, func(t *testing.T) {
			testNativeSigninPhaseIntegration(t, "verified phone password signin", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
				testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, policy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
					testNativeVerifiedPhonePasswordSignin(t, ctx, pool, config, policy, registration, user, mode)
				})
			})
		})
	}
}

func testNativeVerifiedPhonePasswordSignin(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, policy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID, mode string) {
	t.Helper()
	// Install only the new suffixes after already-populated original password
	// signin records/issuances. The old email session remains original history.
	for _, source := range []migrations.Source{
		PhonePasswordSigninMigrationSource{Base: MigrationSource{}, Version: 90},
		sessionpg.PhonePasswordSigninMigrationSource{Schema: config.Session.Schema, Version: 90, Predecessor: sessionpg.UsernameSigninAfterPassword},
		sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: config.Session.Schema, Version: 1}, Version: 2}, Version: 91},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal("phone signin forward history", err)
		}
		for _, step := range history {
			if step.Version() >= 90 {
				if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
					t.Fatal("populated phone signin migration", err)
				}
			}
		}
	}
	config.Phone = policy
	service, err := NewSigninService(pool, config)
	if err != nil {
		t.Fatal("phone password startup", err)
	}
	choices := []session.RememberChoice{session.BrowserSession}
	if mode == "sessions" {
		choices = append(choices, session.PersistentSession)
	}
	for _, choice := range choices {
		t.Run(map[session.RememberChoice]string{session.BrowserSession: "browser", session.PersistentSession: "persistent"}[choice], func(t *testing.T) {
			request, _, _, _ := nativeSigninFlow(t)
			request.TenantID, request.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
			request.Caller.Request.Action, request.Caller.Request.Resource.ID = "identity.phone.password-signin", "identity.phone.password-signin"
			request.Identifier, request.Password, request.Device = "+12025550123", registration.Password, "phone-signin-browser"
			if mode == "unknown" {
				request.Identifier = "+12025550124"
			}
			if mode == "wrong-password" {
				request.Password, err = primitive.NewSecret([]byte("synthetic-wrong-password"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(request.Password.Destroy)
			}
			request.Remember, err = session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			request.PreAuthID, err = identity.NewPreAuthTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			number, err := policy.Canonicalize(ctx, string(request.Identifier))
			if err != nil {
				t.Fatal(err)
			}
			commitment, err := phone.PasswordSigninIdentifierBinding(number, request.TenantID, config.IdentifierKey)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			binding := session.PreAuthBinding{ID: request.PreAuthID, Intent: session.PreAuthIntent{TenantID: request.TenantID, Action: "identity.phone.password-signin", Origin: request.Origin, CallbackURL: request.CallbackURL, Nonce: [32]byte{147}, Remember: request.Remember, PolicyID: config.PolicyID, PolicyVersion: 3, IdentifierBinding: commitment}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			token, _ := session.ParseToken(request.Cookie.Token())
			digest, err := token.PreAuthDigest(config.FlowKeys[0], binding)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
			if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, config.Session, flow) != nil {
				t.Fatal("original phone password browser", err)
			}
			var sessionsBefore, recordsBefore int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records)`).Scan(&sessionsBefore, &recordsBefore); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "retarget":
				request.Identifier = "+12025550124"
			case "foreign-tenant":
				request.TenantID, request.Caller.Request.Tenant = "foreign", "foreign"
			case "suspended":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(user)); err != nil {
					t.Fatal(err)
				}
			case "unverified":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(request.TenantID), string(user)); err != nil {
					t.Fatal(err)
				}
			case "missing-profile", "foreign-profile":
				profile, version := "", uint32(0)
				if mode == "foreign-profile" {
					profile, version = "identity.phone.other-metadata", 1
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET normalization_profile=$3,normalization_version=$4 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(request.TenantID), string(user), profile, int64(version)); err != nil {
					t.Fatal(err)
				}
			case "enrolled-factor":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(user)); err != nil {
					t.Fatal(err)
				}
			case "missing-factor":
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(user)); err != nil {
					t.Fatal(err)
				}
			case "late-factor":
				admission := *config.Coordinator.AdmissionPolicy
				admission.Authorization = &phoneSigninWithdrawalPolicy{base: admission.Authorization, pool: pool}
				config.Coordinator.AdmissionPolicy = &admission
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "late-phone", "late-profile":
				var once sync.Once
				config.Verifier.Now = func() time.Time {
					once.Do(func() {
						query := `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`
						if mode == "late-profile" {
							query = `UPDATE identity.identifiers SET normalization_profile='identity.phone.other-metadata',normalization_version=1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`
						}
						if _, err := pool.Raw().Exec(ctx, query, string(request.TenantID), string(user)); err != nil {
							t.Error(err)
						}
					})
					return time.Now()
				}
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "rollback":
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings ADD CONSTRAINT phone_signin_fault CHECK(false) NOT VALID`); err != nil {
					t.Fatal(err)
				}
			case "rehash":
				parameters := config.Repository.HashPolicy.Argon2idParameters()
				parameters.Time++
				strong, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: parameters, Limits: config.Repository.HashPolicy.Limits()})
				if err != nil {
					t.Fatal(err)
				}
				config.Repository.HashPolicy = strong
				config.Verifier.Primitive, err = primitive.New(strong)
				if err != nil {
					t.Fatal(err)
				}
				config.Verifier.DummyHash, err = config.Verifier.Primitive.Hash(ctx, []byte("synthetic-phone-dummy"))
				if err != nil {
					t.Fatal(err)
				}
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			case "lost-commit":
				testPasswordSigninLostCommit(t, ctx, pool, config, request)
				return
			case "concurrent":
				admission := *config.Coordinator.AdmissionPolicy
				admission.Authorization = &signinPublicBarrierPolicy{ready: make(chan struct{})}
				config.Coordinator.AdmissionPolicy = &admission
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			var result password.SigninResult
			if mode == "concurrent" {
				type completion struct {
					result password.SigninResult
					err    error
				}
				// Two bounded calls own their sends; this buffered collector joins
				// both before continuing, including after a loser is observed.
				outcomes := make(chan completion, 2)
				for range 2 {
					go func() { value, e := service.Signin(ctx, request); outcomes <- completion{value, e} }()
				}
				winners := 0
				for range 2 {
					completed := <-outcomes
					if completed.err == nil && completed.result.State == auth.SignInStateAuthenticated {
						winners++
						result = completed.result
					} else if completed.err == nil || completed.result.Issuance.Token != (session.Token{}) || completed.result.CSRFToken != (session.CSRFToken{}) {
						t.Error("concurrent phone loser disclosed credentials or no terminal denial")
					}
				}
				if winners != 1 {
					t.Fatal("one original phone browser did not have exactly one winner")
				}
				var sessionsAfter, recordsAfter int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records)`).Scan(&sessionsAfter, &recordsAfter); err != nil || sessionsAfter != sessionsBefore+1 || recordsAfter != recordsBefore+1 {
					t.Fatal("phone contention duplicated protected effects", err)
				}
			} else {
				result, err = service.Signin(ctx, request)
			}
			if mode != "sessions" && mode != "rehash" && mode != "concurrent" {
				if result.State == auth.SignInStateAuthenticated || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || result.Issuance.Cookie.Name != "" {
					t.Fatal("denied phone signin disclosed credentials")
				}
				if mode == "unknown" || mode == "wrong-password" || mode == "unverified" || mode == "suspended" || mode == "missing-profile" || mode == "foreign-profile" {
					if err != nil || result.Validate() != nil || result.State != auth.SignInStateRejected {
						t.Fatal("phone denial lost uniform public shape", err)
					}
				} else if err == nil {
					t.Fatal("invalid original or withdrawn authority admitted")
				}
				var sessionsAfter, recordsAfter int
				var flowState string
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records),state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(request.PreAuthID)).Scan(&sessionsAfter, &recordsAfter, &flowState); err != nil || sessionsAfter != sessionsBefore || recordsAfter != recordsBefore || flowState != "issued" {
					t.Fatal("denied phone signin left partial proof/session or consumed browser", err)
				}
				return
			}
			if err != nil || result.Validate() != nil || result.State != auth.SignInStateAuthenticated || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("genuine verified phone cannot sign in", err)
			}
			spec, err := result.Issuance.Session.Bindings()
			gotRemember, rememberErr := spec.Remember.Bindings()
			wantRemember, _ := request.Remember.Bindings()
			if err != nil || rememberErr != nil || spec.UserID != user || gotRemember != wantRemember {
				t.Fatal("phone signin changed account or remember policy")
			}
			if mode == "rehash" {
				var version uint64
				var encoded string
				if err := pool.Raw().QueryRow(ctx, `SELECT version::bigint,encoded_hash FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(user)).Scan(&version, &encoded); err != nil || version != 2 || spec.Authentication.CredentialVersion != version {
					t.Fatal("phone rehash did not share the issued credential successor", err)
				}
				var checked primitive.Result
				if err := request.Password.Use(func(raw []byte) error {
					var e error
					checked, e = config.Verifier.Primitive.Verify(ctx, raw, encoded)
					return e
				}); err != nil || !checked.Match() || checked.NeedsRehash() {
					t.Fatal("phone rehash successor unusable", err)
				}
			}
			wire, err := result.Issuance.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := session.ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := session.NewCredential(session.CredentialBearer, parsed)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: config.Session, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}})
			if err != nil {
				t.Fatal(err)
			}
			current, err := reader.Get(ctx, session.GetRequest{TenantID: registration.TenantID, Credential: credential})
			if err != nil || !current.Authenticated {
				t.Fatal("phone-issued session is unusable", err)
			}
			restarted, err := NewSigninService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			history, err := restarted.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device})
			if err != nil || history.State != auth.SignInStateAuthenticated || history.SessionID != spec.SessionID || !history.Issuance.Replayed || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("phone restart recovery changed original or redelivered credentials", err)
			}
			if repeated, err := service.Signin(ctx, request); err == nil || repeated.Issuance.Token != (session.Token{}) || repeated.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("phone browser replay issued credentials")
			}
			validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}
			logout, err := sessionpg.NewSignOutService(pool, sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: config.Session, Profile: sessionpg.IssueAdmissionConfig(config.Profile), Coordinator: config.Coordinator, Authorization: config.Coordinator.QueryPolicy.Authorization, Clock: config.Issuance.Clock, PolicyID: config.PolicyID, PolicyVersion: config.Coordinator.QueryPolicy.PolicyVersion, AuditRetentionVersion: 1}, Validation: validation, Cookie: config.Issuance.Cookie, MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal("phone session logout composition", err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			signedOut, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: registration.TenantID, CommandID: id, CorrelationID: string(id), Transport: session.CredentialBearer, Credential: credential})
			if err != nil || !signedOut.SignedOut || !signedOut.ClearBearer || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("phone-issued session cannot log out", err)
			}
			if current, err := reader.Get(ctx, session.GetRequest{TenantID: registration.TenantID, Credential: credential}); err != nil || current.Authenticated {
				t.Fatal("phone logout left session usable", err)
			}
		})
	}
	if mode == "sessions" {
		testPhoneSigninPurposeHistories(t, ctx, pool, registration.TenantID, user)
	}
}
