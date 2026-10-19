//go:build integration

package passwordpostgres

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-identity/username"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

// Continue the actual newly registered account before and after its captured
// email confirmation. No username/password row, user, proof or session is seeded
// here. Policy and original browser construction use their supported seams.
func testPublicUsernamePasswordSignin(t *testing.T, ctx context.Context, pool *database.Pool, signup SignupConfig, original password.SignupRequest, verified bool) {
	t.Helper()
	if !verified {
		for _, source := range []migrations.Source{
			UsernameSigninMigrationSource{Base: MigrationSource{}, Version: 9},
			sessionpg.UsernameSigninMigrationSource{Schema: signup.Session.Schema, Version: 9, Predecessor: sessionpg.UsernameSigninAfterPassword},
			sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: signup.Session.Schema, Version: 1}, Version: 2}, Version: 10},
		} {
			history, err := source.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range history {
				if m.Version() >= 9 {
					if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal("native username signin forward history", err)
					}
				}
			}
		}
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: signup.AuthorizationNamespace, Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	_, config := publicSigninFixture(t, pool, signup.Repository.HashPolicy, signup.Screening.Primitive, signup.Screening.DummyHash, signup.Session, profile)
	config.Username = signup.Username
	service, err := NewSigninService(pool, config)
	if err != nil {
		t.Fatal("native username signin startup composition", err)
	}
	modes := []string{"unknown", "wrong", "invalid", "actual", "persistent"}
	if verified {
		modes = append(modes, "foreign-operation", "foreign-cookie", "changed-name", "nonempty-factors", "rollback", "disconnect-after", "rehash")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			config, service := config, service
			request, _, _, _ := nativeSigninFlow(t)
			request.TenantID, request.Caller.Request.Tenant = original.TenantID, original.Caller.Request.Tenant
			request.Caller.Request.Action, request.Caller.Request.Resource.ID = "identity.username.signin", "identity.username.signin"
			request.Identifier, request.Password, request.Device = "STRASSE", original.Password, "username-browser"
			switch mode {
			case "unknown":
				request.Identifier = "missing-name"
			case "wrong":
				request.Password, err = primitive.NewSecret([]byte("synthetic-wrong-password"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(request.Password.Destroy)
			case "invalid":
				request.Identifier = "invalid name"
			case "persistent":
				request.Remember, err = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
				if err != nil {
					t.Fatal(err)
				}
			}
			request.PreAuthID, err = identity.NewPreAuthTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			binding := session.PreAuthBinding{ID: request.PreAuthID, Intent: session.PreAuthIntent{TenantID: request.TenantID, Action: "identity.username.signin", Origin: request.Origin, CallbackURL: request.CallbackURL, Nonce: [32]byte{3}, Remember: request.Remember, PolicyID: config.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			token, _ := session.ParseToken(request.Cookie.Token())
			digest, err := token.PreAuthDigest(config.FlowKeys[0], binding)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
			if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, config.Session, flow) != nil {
				t.Fatal("original username browser flow", err)
			}
			if mode == "foreign-operation" {
				request.Caller.Request.Action = "identity.password.signin"
			} else if mode == "foreign-cookie" {
				foreign, err := session.NewToken(32)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := foreign.Reveal()
				if err != nil {
					t.Fatal(err)
				}
				request.Cookie = auth.NewBearerCredential(wire)
			}
			if mode != "foreign-operation" && mode != "foreign-cookie" {
				expectedCanonical := "strasse"
				if mode == "unknown" || mode == "invalid" {
					expectedCanonical = string(request.Identifier)
				}
				if source, err := service.SigninRateSource(ctx, request); err != nil || source != expectedCanonical {
					t.Fatal("username rate source diverged from signin normalization", err)
				}
			} else if source, err := service.SigninRateSource(ctx, request); err == nil || source != "" {
				t.Fatal("foreign original custody obtained a username rate identity")
			}
			if mode == "changed-name" {
				var once sync.Once
				// The actual verifier clock is an explicit test seam after username
				// discovery. Change only that original name, not any proof/store.
				config.Verifier.Now = func() time.Time {
					once.Do(func() {
						if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND kind='username' AND canonical_value='strasse'`, string(request.TenantID)); err != nil {
							t.Error("current username withdrawal fixture", err)
						}
					})
					return time.Now()
				}
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			} else if mode == "nonempty-factors" {
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id IN (SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND kind='username' AND canonical_value='strasse')`, string(request.TenantID)); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=0,version=version+1 WHERE tenant_id=$1 AND user_id IN (SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND kind='username' AND canonical_value='strasse')`, string(request.TenantID)); err != nil {
						t.Error("factor authority fixture cleanup", err)
					}
				}()
			} else if mode == "rollback" {
				if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings ADD CONSTRAINT username_signin_fault CHECK(false) NOT VALID`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings DROP CONSTRAINT username_signin_fault`); err != nil {
						t.Error("username signin failure cleanup", err)
					}
				}()
			} else if mode == "rehash" {
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
				config.Verifier.DummyHash, err = config.Verifier.Primitive.Hash(ctx, []byte("synthetic-username-dummy"))
				if err != nil {
					t.Fatal(err)
				}
				service, err = NewSigninService(pool, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			var sessionsBefore, recordsBefore int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records)`).Scan(&sessionsBefore, &recordsBefore); err != nil {
				t.Fatal(err)
			}
			if mode == "disconnect-after" {
				testPasswordSigninLostCommit(t, ctx, pool, config, request)
				return
			}
			originalPolicy := *config.Username
			*config.Username = username.Policy{}
			result, err := service.Signin(ctx, request)
			*config.Username = originalPolicy
			if mode == "foreign-operation" || mode == "foreign-cookie" || mode == "changed-name" || mode == "nonempty-factors" || mode == "rollback" {
				if err == nil || result.State == auth.SignInStateAuthenticated || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) || result.Issuance.Cookie.Name != "" {
					t.Fatal("wrong original custody/current name or failed atomic effects issued credentials", err)
				}
				var sessionsAfter, recordsAfter int
				var flowState string
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records),state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(request.PreAuthID)).Scan(&sessionsAfter, &recordsAfter, &flowState); err != nil || sessionsAfter != sessionsBefore || recordsAfter != recordsBefore || flowState != "issued" {
					t.Fatal("denied username attempt left partial session/proof or consumed original browser", err)
				}
				return
			}
			if mode != "actual" && mode != "persistent" && mode != "rehash" || !verified {
				if err != nil || result.Validate() != nil || result.State != auth.SignInStateRejected || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("unknown/wrong/invalid/unverified username lost uniform credential-free denial", err)
				}
				return
			}
			if err != nil || result.Validate() != nil || result.State != auth.SignInStateAuthenticated || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("genuine verified signup could not sign in by canonical username", err)
			}
			q, _, err := result.Recovery.Bindings()
			if err != nil || q.OperationID != "identity.username.signin" {
				t.Fatal("username signin recovery lost its original operation", err)
			}
			wire, err := result.Issuance.Token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			parsedToken, err := session.ParseToken(wire)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := session.NewCredential(session.CredentialBearer, parsedToken)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: config.Session, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}})
			if err != nil {
				t.Fatal(err)
			}
			current, err := reader.Get(ctx, session.GetRequest{TenantID: original.TenantID, Credential: credential})
			before, _ := result.Issuance.Session.Bindings()
			after, _ := current.Session.Bindings()
			beforeRemember, _ := before.Remember.Bindings()
			afterRemember, _ := after.Remember.Bindings()
			if err != nil || !current.Authenticated || before.SessionID != after.SessionID || before.UserID != after.UserID || before.TenantID != after.TenantID || before.Authentication != after.Authentication || beforeRemember != afterRemember || before.Authority.CompareCurrent(after.Authority) != nil {
				t.Fatal("username-issued session is not usable through the genuine reader", err)
			}
			if mode == "rehash" {
				var credentialVersion uint64
				var raw string
				if err := pool.Raw().QueryRow(ctx, `SELECT version::bigint,encoded_hash FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2`, string(before.TenantID), string(before.UserID)).Scan(&credentialVersion, &raw); err != nil || credentialVersion != before.Authentication.CredentialVersion || credentialVersion != 2 {
					t.Fatal("username rehash lost atomic credential successor", err)
				}
				var comparison primitive.Result
				if err := request.Password.Use(func(value []byte) error {
					var err error
					comparison, err = config.Verifier.Primitive.Verify(ctx, value, raw)
					return err
				}); err != nil || !comparison.Match() || comparison.NeedsRehash() {
					t.Fatal("username hash successor unusable under current policy")
				}
			}
			if replay, err := service.Signin(ctx, request); err == nil || replay.State == auth.SignInStateAuthenticated || replay.Issuance.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) || replay.Issuance.Cookie.Name != "" {
				t.Fatal("consumed username browser reissued credentials")
			}
			restarted, err := NewSigninService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			recovery := password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device}
			for range 2 {
				history, err := restarted.RecoverSignin(ctx, recovery)
				if err != nil || history.Validate() != nil || history.State != auth.SignInStateAuthenticated || history.SessionID != before.SessionID || history.Recovery != result.Recovery || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || !history.Issuance.Replayed || history.Issuance.Session != (session.Session{}) || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || history.Issuance.Cookie.Name != "" {
					t.Fatal("restarted username recovery lost original metadata or recreated credentials", err)
				}
			}
			validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}
			logout, err := sessionpg.NewSignOutService(pool, sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: config.Session, Profile: sessionpg.IssueAdmissionConfig(config.Profile), Coordinator: config.Coordinator, Authorization: config.Coordinator.QueryPolicy.Authorization, Clock: config.Issuance.Clock, PolicyID: config.PolicyID, PolicyVersion: config.Coordinator.QueryPolicy.PolicyVersion, AuditRetentionVersion: 1}, Validation: validation, Cookie: config.Issuance.Cookie, MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal("native username session logout composition", err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			signedOut, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: original.TenantID, CommandID: id, CorrelationID: string(id), Transport: session.CredentialBearer, Credential: credential})
			if err != nil || !signedOut.SignedOut || !signedOut.ClearBearer || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
				t.Fatal("username-issued session could not log out", err)
			}
			if current, err := reader.Get(ctx, session.GetRequest{TenantID: original.TenantID, Credential: credential}); err != nil || current.Authenticated {
				t.Fatal("username logout left its bearer usable", err)
			}
		})
	}
	if verified {
		testUsernameSigninVerificationHistories(t, ctx, pool, original.TenantID)
	}
}

// These populated storage fixtures prove forward purpose compatibility, not
// factor authentication. The complete username journey above uses actual owners.
func testUsernameSigninVerificationHistories(t *testing.T, ctx context.Context, pool *database.Pool, tenant identity.TenantID) {
	t.Helper()
	var user string
	if err := pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity.identifiers WHERE tenant_id=$1 AND kind='username' AND canonical_value='strasse'`, string(tenant)).Scan(&user); err != nil {
		t.Fatal(err)
	}
	for _, mfaFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "verification-only-history", true: "mfa-first-verification-history"}[mfaFirst], func(t *testing.T) {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			// Distinct schemas keep pgx's prepared domain-type identities valid
			// after the preceding transaction removes its disposable namespace.
			schema := "username_verification_history"
			if mfaFirst {
				schema = "username_mfa_verification_history"
			}
			table := schema + ".session_issuances"
			sources := []migrations.Source{
				sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3},
				sessionpg.OTPIssueMigrationSource{Schema: schema, Version: 4},
				sessionpg.PasswordSigninMigrationSource{Schema: schema, Version: 5},
				sessionpg.PasswordSignupMigrationSource{Schema: schema, Version: 6},
				sessionpg.MagicLinkSigninMigrationSource{Schema: schema, Version: 7},
			}
			if mfaFirst {
				sources = append(sources, sessionpg.MFASigninMigrationSource{Schema: schema, Version: 8})
			}
			sources = append(sources, sessionpg.EmailVerificationSigninMigrationSource{Schema: schema, Version: 9, MFASignin: mfaFirst})
			for _, source := range sources {
				history, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range history {
					if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
						t.Fatal("installed verification history", err)
					}
				}
			}
			purpose := "identity.email.verification-signin"
			var parent any = make([]byte, 16)
			if mfaFirst {
				purpose, parent = "identity.mfa.totp-verify", nil
			}
			if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest,verification_command_id) VALUES($1,$2,$3,$4,'retained-session','retained-family',$5,$5,$6)`, string(tenant), make([]byte, 16), purpose, user, make([]byte, 32), parent); err != nil {
				t.Fatal("populated original verification/MFA issuance", err)
			}
			var before, after string
			if err := tx.QueryRow(ctx, `SELECT row_to_json(s)::text FROM `+table+` s`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			history, err := (sessionpg.UsernameSigninMigrationSource{Schema: schema, Version: 10, Predecessor: sessionpg.UsernameSigninAfterVerification, MFASignin: mfaFirst}).Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
				t.Fatal("username suffix rejected retained original purpose", err)
			}
			if err := tx.QueryRow(ctx, `SELECT row_to_json(s)::text FROM `+table+` s`).Scan(&after); err != nil || before != after {
				t.Fatal("username suffix rewrote populated original issuance", err)
			}
			id := [16]byte{1}
			if _, err := tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest) VALUES($1,$2,'identity.username.signin',$3,'new-session','new-family',$4,$4)`, string(tenant), id[:], user, make([]byte, 32)); err != nil {
				t.Fatal("username suffix did not admit its new issuance purpose", err)
			}
		})
	}
}

func testPasswordSigninLostCommit(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, request password.SigninRequest) {
	t.Helper()
	fault := &signinCommitFault{}
	faulted, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal("username commit fault connection unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if faulted.Close(cleanup) != nil {
			t.Error("username fault pool cleanup")
		}
	}()
	service, err := NewSigninService(faulted, config)
	if err != nil {
		t.Fatal(err)
	}
	original, err := service.Signin(ctx, request)
	if err == nil || !fault.hit.Load() || original.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || original.Issuance.Token != (session.Token{}) || original.CSRFToken != (session.CSRFToken{}) || original.Issuance.Cookie.Name != "" || original.SessionID != "" {
		t.Fatal("username commit interruption disclosed credentials or fabricated its outcome")
	}
	query, _, err := original.Recovery.Bindings()
	if err != nil || query.OperationID != string(request.Caller.Request.Action) {
		t.Fatal("username ambiguity lost exact original recovery scope", err)
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(query.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewSigninService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		history, err := restarted.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: original.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device})
		if err != nil || history.Validate() != nil || history.State != auth.SignInStateAuthenticated || history.SessionID == "" || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || !history.Issuance.Replayed || history.Issuance.Session != (session.Session{}) || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || history.Issuance.Cookie.Name != "" {
			t.Fatal("original username commit recovery lost history or recreated credentials", err)
		}
		var records, audits, events, sessions int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.signin_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM signin_sessions.sessions WHERE tenant_id=$2 AND session_id=$3)`, id, string(request.TenantID), history.SessionID).Scan(&records, &audits, &events, &sessions); err != nil || records != 1 || audits != 1 || events != 1 || sessions != 1 {
			t.Fatal("username commit/recovery split or repeated protected effects", err)
		}
	}
}
