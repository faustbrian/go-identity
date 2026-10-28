//go:build integration

package passwordpostgres

import (
	"context"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-identity/username"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// The selected-user callback runs after the native factor read. Advancing that
// authority here proves the protected Work fence, not an earlier snapshot check.
type bearerSigninFactorWithdrawalPolicy struct {
	pool *database.Pool
	once sync.Once
}

func (p *bearerSigninFactorWithdrawalPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	var err error
	if c.Request.Resource.Type == "identity.user" {
		p.once.Do(func() {
			_, err = p.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser)
		})
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, err
}

func TestNativeBearerSigninIntegration(t *testing.T) {
	t.Run("authority", func(t *testing.T) {
		testNativeSigninPhaseIntegration(t, "public bearer service")
	})
	t.Run("failure-recovery", func(t *testing.T) {
		testNativeSigninPhaseIntegration(t, "public bearer regression")
	})
}

func TestNativeBearerSignupConsumerIntegration(t *testing.T) {
	testNativeSigninPhaseIntegration(t, "genuine bearer signup consumer", func(t *testing.T, ctx context.Context, pool *database.Pool, _ *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		c.Risk = phoneNativeAuthenticationRisk(t, ctx, pool, nil)
		c.AuthorizationNamespace = "users"
		signup, err := NewSignupService(pool, c, keys)
		if err != nil {
			t.Fatal("genuine bearer signup composition", err)
		}
		history, err := (sessionpg.PreAuthIssueMigrationSource{Schema: c.Session.Schema, Version: 95}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, migration := range history {
			if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("native pre-auth issuance history", err)
			}
		}
		profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
		_, config := publicSigninFixture(t, pool, c.Repository.HashPolicy, c.Screening.Primitive, c.Screening.DummyHash, c.Session, profile)
		config.Transport, config.CSRFKey, config.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
		config.Risk = c.Risk
		registration := fresh("bearer-owner@example.test", 'B')
		registrationFlow := config
		registrationFlow.Coordinator, registrationFlow.PolicyID = c.Coordinator, c.PolicyID
		registrationFlow.FlowKeys, registrationFlow.Origins, registrationFlow.CallbackURLs = c.FlowKeys, c.Origins, c.CallbackURLs
		issued := issueNativeBearerPreAuth(t, ctx, pool, registrationFlow, "identity.password.signup", registration.RememberPolicy)
		binding, err := issued.Flow.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		wire, err := issued.Token.Reveal()
		if err != nil {
			t.Fatal("committed registration flow withheld original cookie")
		}
		registration.PreAuthID, registration.Cookie = binding.Binding.ID, auth.NewBearerCredential(wire)
		registered, err := signup.Signup(ctx, registration)
		if err != nil || registered.Outcome != identity.CommitOutcomeCommitted || !registered.VerificationRequired {
			t.Fatal("genuine bearer registration", err)
		}
		query, _, err := registered.Recovery.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		testPublicSignupVerificationOrigin(t, ctx, signup, c, registration, query.CommandID, keys)
		service, err := NewSigninService(pool, config)
		if err != nil {
			t.Fatal("genuine bearer signin composition", err)
		}
		request, _, _, _ := nativeSigninFlow(t)
		request.TenantID, request.Caller.Request.Tenant, request.Caller.Request.Subject.ID = registration.TenantID, registration.Caller.Request.Tenant, signinTestActor
		request.Password, request.Device = registration.Password, "bearer-consumer-device"
		request.Identifier, err = identifier.NewInput(string(registration.Email))
		if err != nil {
			t.Fatal("registered email is not valid signin input")
		}
		issued = issueNativeBearerPreAuth(t, ctx, pool, config, "identity.password.signin", request.Remember)
		binding, err = issued.Flow.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		wire, err = issued.Token.Reveal()
		if err != nil {
			t.Fatal("committed signin flow withheld original cookie")
		}
		request.PreAuthID, request.Cookie = binding.Binding.ID, auth.NewBearerCredential(wire)
		result, err := service.Signin(ctx, request)
		if err != nil || result.Validate() != nil || result.State != auth.SignInStateAuthenticated || result.Transport != password.BearerSignin || result.CSRFToken != (session.CSRFToken{}) || !zeroSigninCookie(result.Issuance.Cookie) {
			t.Fatal("verified genuine account cannot sign in as bearer", err)
		}
		wire, err = result.Issuance.Token.Reveal()
		if err != nil {
			t.Fatal("genuine bearer withheld")
		}
		checkNativeBearerSession(t, ctx, pool, config, wire, result.Issuance.Session)
		if _, err := result.Issuance.Token.Reveal(); err == nil {
			t.Fatal("genuine bearer revealed twice")
		}
		restarted, err := NewSigninService(pool, config)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := restarted.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device})
		if err != nil || recovered.Validate() != nil || recovered.SessionID != result.SessionID || recovered.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || !recovered.Issuance.Replayed || recovered.Issuance.Token != (session.Token{}) || recovered.Issuance.Session != (session.Session{}) || recovered.CSRFToken != (session.CSRFToken{}) || !zeroSigninCookie(recovered.Issuance.Cookie) {
			t.Fatal("genuine bearer recovery changed original history or redelivered a credential", err)
		}
	})
}

func issueNativeBearerPreAuth(t *testing.T, ctx context.Context, pool *database.Pool, c SigninConfig, action string, remember session.RememberPolicy) session.PreAuthIssueResult {
	t.Helper()
	version := c.Coordinator.AdmissionPolicy.PolicyVersion
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: c.Session, Coordinator: c.Coordinator, Authorization: c.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: signinTestActor, Action: action, Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: version, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal("native pre-auth executor unavailable", err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: signinTestActor, Action: action, Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: version, Clock: clock.System{}, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: c.FlowKeys[0], TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal("native pre-auth issuer unavailable", err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: signinTestTenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal("original pre-auth preparation failed", err)
	}
	issued, err := issuer.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed {
		t.Fatal("original pre-auth issuance failed", err)
	}
	return issued
}

func seedNativeBearerFactors(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	seedID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.RawURLEncoding.DecodeString(string(seedID))
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,decode('01','hex'))`, seed, signinTestTenant, make([]byte, 32)); err != nil {
		t.Fatal("original signup claim fixture", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, seed, signinTestTenant); err != nil {
		t.Fatal("original signup fixture", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES($1,$2,1,0,$3,'identity.password.signup')`, signinTestTenant, signinTestUser, seed); err != nil {
		t.Fatal("known-empty factor fixture", err)
	}
}

func testPublicNativeBearerSignin(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, crypto *primitive.Service, hash primitive.EncodedHash, storage sessionpg.Config, profile sessionpg.IdentifierAdmissionConfig) {
	t.Helper()
	_, c := publicSigninFixture(t, pool, policy, crypto, hash, storage, profile)
	seedNativeBearerFactors(t, ctx, pool)
	t.Run("unknown-transport", func(t *testing.T) {
		bad := c
		bad.Transport = 255
		if got, err := NewSigninService(pool, bad); err == nil || got != nil {
			t.Fatal("unknown transport fell back to valid cookie composition")
		}
	})
	namePolicy, err := username.NewPolicy(username.ReferencePolicySpec())
	if err != nil {
		t.Fatal("valid username policy unavailable", err)
	}
	numberPolicy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal("valid phone policy unavailable", err)
	}
	for _, mutate := range []func(*SigninConfig){
		func(c *SigninConfig) { c.Username = namePolicy },
		func(c *SigninConfig) { c.Phone = numberPolicy },
	} {
		valid := c
		mutate(&valid)
		if got, err := NewSigninService(pool, valid); err != nil || got == nil {
			t.Fatal("unsupported-bearer oracle has an invalid cookie counterpart", err)
		}
	}
	c.Transport, c.CSRFKey, c.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
	c.ProofTTL = 45 * time.Second
	service, err := NewSigninService(pool, c)
	if err != nil {
		t.Fatal("native bearer composition", err)
	}
	for _, check := range []struct {
		name   string
		mutate func(*SigninConfig)
	}{
		{"unsupported-username", func(c *SigninConfig) { c.Username = namePolicy }},
		{"unsupported-phone", func(c *SigninConfig) { c.Phone = numberPolicy }},
		{"mixed-csrf", func(c *SigninConfig) { c.CSRFKey, _ = session.NewCSRFKey(1, make([]byte, 32)) }},
		{"mixed-cookie", func(c *SigninConfig) {
			c.Issuance.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
		}},
		{"cookie-without-custody", func(c *SigninConfig) { c.Transport = password.CookieSignin }},
	} {
		t.Run(check.name, func(t *testing.T) {
			bad := c
			check.mutate(&bad)
			if got, err := NewSigninService(pool, bad); err == nil || got != nil {
				t.Fatal("mixed transport composition accepted")
			}
		})
	}
	for _, mode := range []string{"commit", "wrong", "unknown", "suspended", "unverified", "policy-advance", "expired", "factor-enrolled", "late-factor", "factor-absent"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := nativeSigninFlow(t)
			r.TenantID, r.Caller.Request.Tenant, r.Caller.Request.Subject.ID = signinTestTenant, signinTestTenant, signinTestActor
			r.Device, r.Identifier = "synthetic-device", "person@EXAMPLE.test"
			r.PreAuthID, _ = identity.NewPreAuthTransactionID()
			now := time.Now().UTC().Truncate(time.Microsecond)
			b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{2}, Remember: r.Remember, PolicyID: c.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
			if mode == "expired" {
				b.IssuedAt, b.ExpiresAt = now.Add(-2*time.Minute), now.Add(-time.Minute)
			}
			token, _ := session.ParseToken(r.Cookie.Token())
			digest, _ := token.PreAuthDigest(c.FlowKeys[0], b)
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
			if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
				t.Fatal("original bearer flow fixture", err)
			}
			attempt := service
			if mode == "suspended" || mode == "unverified" {
				statement := `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2`
				if mode == "unverified" {
					statement = `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL,version=version+1 WHERE tenant_id=$1 AND user_id=$2`
				}
				if _, err := pool.Raw().Exec(ctx, statement, signinTestTenant, signinTestUser); err != nil {
					t.Fatal("account eligibility fixture", err)
				}
				t.Cleanup(func() {
					for _, restore := range []string{`UPDATE identity.users SET status='active',version=1 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.identifiers SET verified=true,is_primary=true,verification_state=2,verified_at=clock_timestamp(),version=1 WHERE tenant_id=$1 AND user_id=$2`} {
						if _, err := pool.Raw().Exec(ctx, restore, signinTestTenant, signinTestUser); err != nil {
							t.Error("account eligibility cleanup", err)
						}
					}
				})
			}
			if mode == "factor-enrolled" || mode == "late-factor" {
				if mode == "factor-enrolled" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser); err != nil {
						t.Fatal(err)
					}
				} else {
					changed := c
					admission := *c.Coordinator.AdmissionPolicy
					admission.Authorization = &bearerSigninFactorWithdrawalPolicy{pool: pool}
					changed.Coordinator.AdmissionPolicy = &admission
					attempt, err = NewSigninService(pool, changed)
					if err != nil {
						t.Fatal("factor withdrawal composition", err)
					}
				}
				t.Cleanup(func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser); err != nil {
						t.Error("factor fixture cleanup", err)
					}
				})
			}
			if mode == "factor-absent" {
				if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, signinTestTenant, signinTestUser); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "wrong" {
				r.Password, err = primitive.NewSecret([]byte("wrong-password"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(r.Password.Destroy)
			}
			if mode == "unknown" {
				r.Identifier = "absent@example.test"
			}
			if mode == "policy-advance" {
				changed := c
				admission := *c.Coordinator.AdmissionPolicy
				admission.Authorization = signinPublicAdvancePolicy{pool: pool}
				changed.Coordinator.AdmissionPolicy = &admission
				attempt, err = NewSigninService(pool, changed)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id=$1 AND policy_namespace='users' AND subject_id=$2`, signinTestTenant, signinTestUser); err != nil {
						t.Error("policy fixture cleanup", err)
					}
				})
			}
			result, err := attempt.Signin(ctx, r)
			var state string
			if e := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&state); e != nil {
				t.Fatal("original flow observation", e)
			}
			if mode != "commit" {
				if result.State == auth.SignInStateAuthenticated || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || !zeroSigninCookie(result.Issuance.Cookie) || state != "issued" {
					t.Fatal("bearer denial disclosed authentication or consumed original flow")
				}
				if (mode == "wrong" || mode == "unknown" || mode == "suspended" || mode == "unverified") && (err != nil || result.Validate() != nil || result.Transport != password.BearerSignin) {
					t.Fatal("bearer neutral denial differs", err)
				}
				if (mode == "policy-advance" || mode == "expired" || mode == "factor-enrolled" || mode == "late-factor" || mode == "factor-absent") && err == nil {
					t.Fatal("stale original bearer authority accepted")
				}
				return
			}
			if err != nil || result.Validate() != nil || result.Transport != password.BearerSignin || result.State != auth.SignInStateAuthenticated || state != "consumed" || result.Issuance.Replayed || result.CSRFToken != (session.CSRFToken{}) || !zeroSigninCookie(result.Issuance.Cookie) {
				t.Fatal("native bearer signin failed", err)
			}
			spec, err := result.Issuance.Session.Bindings()
			if err != nil || result.Issuance.Session.CSRFState() != (session.CSRFState{}) || spec.Authentication.Proof.Method != "password" || spec.Authentication.Proof.ExpiresAt.Sub(spec.Authentication.Proof.IssuedAt) != c.ProofTTL {
				t.Fatal("bearer session changed authentication bounds or added CSRF")
			}
			stored, err := service.sessions.Lookup(ctx, r.TenantID, spec.Lookup)
			storedSpec, storedErr := stored.Session.Bindings()
			if err != nil || storedErr != nil || storedSpec.SessionID != spec.SessionID || storedSpec.Lookup != spec.Lookup || storedSpec.Authentication != spec.Authentication || stored.Session.CSRFState() != (session.CSRFState{}) {
				t.Fatal("bearer storage differs from genuine original session", err)
			}
			wire, err := result.Issuance.Token.Reveal()
			if err != nil || wire == "" {
				t.Fatal("original bearer not deliverable")
			}
			if _, err := result.Issuance.Token.Reveal(); err == nil {
				t.Fatal("original bearer delivered twice")
			}
			checkNativeBearerSession(t, ctx, pool, c, wire, result.Issuance.Session)
			replay, err := service.Signin(ctx, r)
			if err == nil || replay.Issuance.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("consumed original flow issued another bearer")
			}
			restarted, err := NewSigninService(pool, c)
			if err != nil {
				t.Fatal(err)
			}
			history, err := restarted.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device})
			if err != nil || history.Validate() != nil || history.Transport != password.BearerSignin || history.SessionID != result.SessionID || !history.Issuance.Replayed || history.Issuance.Session != (session.Session{}) || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || history.Issuance.Cookie.Name != "" {
				t.Fatal("bearer recovery redelivered credentials or changed original history", err)
			}
		})
	}
}

func zeroSigninCookie(c http.Cookie) bool {
	return c.Name == "" && c.Value == "" && !c.Quoted && c.Path == "" && c.Domain == "" && c.Expires.IsZero() && c.RawExpires == "" && c.MaxAge == 0 && !c.Secure && !c.HttpOnly && c.SameSite == 0 && !c.Partitioned && c.Raw == "" && c.Unparsed == nil
}

func checkNativeBearerSession(t *testing.T, ctx context.Context, pool *database.Pool, c SigninConfig, wire string, original session.Session) {
	t.Helper()
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal("delivered bearer is not consumable")
	}
	spec, err := original.Bindings()
	if err != nil {
		t.Fatal("issued session absent")
	}
	digest, err := token.Digest(c.Issuance.LookupKey, string(spec.TenantID))
	if err != nil || digest != spec.Lookup {
		t.Fatal("delivered bearer does not select the persisted session")
	}
	reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: c.Session, Profile: c.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: c.Profile.Audience, Clock: c.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{c.Issuance.LookupKey}}})
	if err != nil {
		t.Fatal("public native session reader unavailable", err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal("delivered bearer transport invalid")
	}
	read, err := reader.Get(ctx, session.GetRequest{TenantID: spec.TenantID, Credential: credential})
	if err != nil || !read.Authenticated || read.ValidateAt(time.Now()) != nil || read.Session.CSRFState() != (session.CSRFState{}) {
		t.Fatal("real bearer cannot authenticate through the public session reader", err)
	}
	actual, err := read.Session.Bindings()
	if err != nil || actual.SessionID != spec.SessionID || actual.UserID != spec.UserID || actual.Authentication != spec.Authentication || actual.Remember != spec.Remember {
		t.Fatal("public session read changed original identity or authentication")
	}
	if read.ValidUntil().After(time.Now().Add(20 * time.Second)) {
		t.Fatal("session read renewed authority beyond the separate evidence budget")
	}
}
