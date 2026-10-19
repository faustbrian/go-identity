//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Eligibility comes from the same genuine registration/email confirmation,
// fresh proof and captured encrypted SMS enrollment consumer as password login.
// Only the original browser-flow fixture is inserted, never an eligible phone,
// account, factor authority, challenge or issued authentication session.
func TestNativeVerifiedPhoneOTPSigninIntegration(t *testing.T) {
	for _, mode := range []string{"sessions", "wrong-code", "exhausted", "retarget", "foreign-cookie", "unknown", "unverified", "suspended", "missing-profile", "foreign-profile", "enrolled-factor", "missing-factor", "late-factor", "late-profile", "late-account", "late-phone", "rollback", "concurrent", "mixed-race", "lost-commit", "lost-denial"} {
		choices := []session.RememberChoice{session.BrowserSession}
		if mode == "sessions" {
			choices = append(choices, session.PersistentSession)
		}
		for _, choice := range choices {
			t.Run(mode+"/"+map[session.RememberChoice]string{session.BrowserSession: "browser", session.PersistentSession: "persistent"}[choice], func(t *testing.T) {
				// Each profile gets genuine account/history, not another case's
				// consumed browser or resend window. Admission limits stay active.
				testNativeVerifiedPhoneOTPSignin(t, choice, mode)
			})
		}
	}
}

func testNativeVerifiedPhoneOTPSignin(t *testing.T, choice session.RememberChoice, mode string) {
	t.Helper()
	testNativeSigninPhaseIntegration(t, "verified phone OTP signin", func(t *testing.T, ctx context.Context, pool *database.Pool, _ *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, nil, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, policy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			crypto, err := envelope.NewService(keys)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []migrations.Source{
				sessionpg.OTPMigrationSource{Schema: config.Session.Schema, Version: 90},
				sessionpg.PhoneOTPSigninMigrationSource{Schema: config.Session.Schema, Version: 91, Predecessor: sessionpg.UsernameSigninAfterPassword},
				sessionpg.RevokeOneMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: config.Session.Schema, Version: 1}, Version: 2}, Version: 92},
			} {
				history, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, step := range history {
					if step.Version() >= 90 {
						if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
							t.Fatal("populated phone OTP session migration", err)
						}
					}
				}
			}
			codeProfile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
			if err != nil {
				t.Fatal(err)
			}
			attemptPolicy, err := otp.NewAttemptPolicy(codeProfile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			requestKeys, err := kernel.NewRequestKeyConfig("phone-otp-signin", [32]byte{141}, *config.Coordinator.QueryPolicy)
			if err != nil {
				t.Fatal(err)
			}
			templates := []delivery.Template{{ID: "phone-signin-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 4096}}
			custody := deliverypg.ContributorConfig{Deployment: "phone-signin-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {142}}, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "sms", PolicyVersion: 1}}}
			selected := otppg.PhoneSigninConfig{Policy: policy, Send: otppg.SendConfig{
				Store:    otppg.ContributorConfig{Schema: "phone_codes", GlobalAuthorityID: config.Profile.GlobalAuthorityID, UserPolicyNamespace: config.Profile.PolicyNamespace, LockoutKey: [32]byte{133}, PreAuth: config.Session, PreAuthCookieKeys: map[uint32][]byte{1: bytes.Repeat([]byte{43}, 32)}},
				Codec:    otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"phone-wrap": bytes.Repeat([]byte{129}, 32)}, CurrentWrappingKey: "phone-wrap", AttemptKeys: map[uint32][32]byte{1: {130}}, CodeKeys: map[uint32][32]byte{1: {131}}, CurrentCodeKeyVersion: 1, MaximumDuration: time.Second},
				Delivery: custody, Coordinator: config.Coordinator, RequestKeys: requestKeys, Risk: config.Risk, Policy: attemptPolicy,
				TemplateID: "phone-signin-code", TemplateVersion: 1, LocaleChain: []string{"en"}, Templates: templates, ProviderVersion: 2,
				PolicyID: "phone-otp-signin", PolicyVersion: 3, PreAuthAction: "identity.phone.signin", IntentKey: [32]byte{143}, IdentifierKey: [32]byte{144}, Timeout: 5 * time.Second,
			}, Signin: otppg.SigninConfig{Coordinator: config.Coordinator, CurrentAttemptKeyVersion: 1, Session: config.Session,
				Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: config.Profile.GlobalAuthorityID, PolicyNamespace: config.Profile.PolicyNamespace, Audience: config.Profile.Audience}, Issuer: config.Issuance, CSRFKey: config.CSRFKey}}
			service, err := otppg.NewPhoneSigninService(pool, selected, crypto)
			if err != nil {
				t.Fatal("native phone OTP composition", err)
			}
			if err := service.Initialize(ctx); err != nil {
				t.Fatal("native phone OTP startup", err)
			}
			t.Run("signin", func(t *testing.T) {
				r, _, _, _ := nativeSigninFlow(t)
				r.TenantID, r.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
				// The canonical identity risk audit requires an opaque system
				// actor ID, unlike the older password-only flow fixture's label.
				r.Caller.Request.Subject.ID = signinTestActor
				r.Caller.Request.Action, r.Caller.Request.Resource.ID = "identity.phone.signin", "identity.phone.signin"
				destination := "+12025550123"
				if mode == "unknown" {
					destination = "+12025550124"
				}
				number, err := policy.Canonicalize(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				commitment, err := phone.OTPSigninIdentifierBinding(number, r.TenantID, selected.Send.IdentifierKey[:])
				if err != nil {
					t.Fatal(err)
				}
				remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
				if err != nil {
					t.Fatal(err)
				}
				id, err := identity.NewPreAuthTransactionID()
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				binding := session.PreAuthBinding{ID: id, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.phone.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{145}, Remember: remember, PolicyID: selected.Send.PolicyID, PolicyVersion: 3, IdentifierBinding: commitment}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
				token, err := session.ParseToken(r.Cookie.Token())
				if err != nil {
					t.Fatal(err)
				}
				digest, err := token.PreAuthDigest(config.FlowKeys[0], binding)
				if err != nil {
					t.Fatal(err)
				}
				original, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
				if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, config.Session, original) != nil {
					t.Fatal("phone OTP original browser fixture", err)
				}
				flow, err := otp.NewPreAuthSendFlow(id, r.Cookie)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "retarget" {
					number, err = policy.Canonicalize(ctx, "+12025550124")
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "foreign-cookie" {
					flow, err = otp.NewPreAuthSendFlow(id, auth.NewBearerCredential(strings.Repeat("A", 43)))
					if err != nil {
						t.Fatal(err)
					}
				}
				key, err := identity.NewIdempotencyKey([]byte("phone-otp-" + string(id)))
				if err != nil {
					t.Fatal(err)
				}
				request, err := phone.NewSigninSendRequest(phone.SigninSendRequestSpec{TenantID: r.TenantID, Number: number, Caller: r.Caller, Flow: flow, Network: r.Network, Device: "phone-otp-browser", IdempotencyKey: key})
				if err != nil {
					t.Fatal(err)
				}
				retained, err := sessionpg.ReadPreAuth(ctx, pool.Raw(), config.Session, r.TenantID, id)
				if err != nil {
					t.Fatal("original bound phone OTP browser is unreadable", err)
				}
				retainedSpec, err := retained.Bindings()
				if err != nil || retainedSpec.Binding != binding {
					t.Fatal("original phone OTP browser lost its target commitment", err)
				}
				directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				recipient, err := directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123", Eligibility: kernel.RecipientVerified, NormalizationProfile: policy.Profile().ID, NormalizationVersion: policy.Profile().Version})
				if err != nil || recipient.Suppressed || recipient.User.ID != user {
					t.Fatal("genuine verified phone is not discoverable under its stored profile", err)
				}
				var sessionBaseline [2]int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.families),(SELECT count(*) FROM signin_sessions.sessions)`).Scan(&sessionBaseline[0], &sessionBaseline[1]); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "unverified":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(r.TenantID), string(user))
				case "suspended":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
				case "missing-profile":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET normalization_profile='',normalization_version=0 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(r.TenantID), string(user))
				case "foreign-profile":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET normalization_profile='identity.phone.other-metadata',normalization_version=1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(r.TenantID), string(user))
				}
				if err != nil {
					t.Fatal("established phone eligibility withdrawal", err)
				}
				sent, err := service.SendSignin(ctx, request)
				if mode == "retarget" || mode == "foreign-cookie" {
					if err == nil {
						t.Fatal("foreign original target or cookie admitted")
					}
					assertPhoneOTPNoSuccess(t, ctx, pool, id, "", 0, 0)
					return
				}
				if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
					t.Fatalf("actual phone signin SMS initiation: outcome=%v command-present=%t error=%v", sent.Outcome, sent.CommandID != "", err)
				}
				if mode == "unknown" || mode == "unverified" || mode == "suspended" || mode == "missing-profile" || mode == "foreign-profile" {
					var codes, deliveries int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM phone_codes.challenges WHERE purpose='signin'),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1)`, mustPhoneOTPCommandBytes(t, sent.CommandID)).Scan(&codes, &deliveries); err != nil || codes != 0 || deliveries != 0 {
						t.Fatal("ineligible phone produced a login code or SMS", codes, deliveries, err)
					}
					assertPhoneOTPNoSuccess(t, ctx, pool, id, "", 0, 0)
					return
				}
				code := capturePhoneSigninSMS(t, ctx, pool, c, crypto, custody, templates, r.TenantID)
				if mode == "sessions" {
					sourceRequest := otp.SigninSourceRequest{TenantID: r.TenantID, Caller: r.Caller, Flow: flow, SendCommandID: sent.CommandID}
					source, err := service.ResolveSigninSource(ctx, sourceRequest)
					originalSource, sourceErr := source.Bindings()
					if err != nil || sourceErr != nil || originalSource.TenantID != r.TenantID || originalSource.SendCommandID != sent.CommandID || originalSource.Channel != otp.ChannelSMS || originalSource.Destination.Value() != "+12025550123" {
						t.Fatal("native phone rate source lost original authenticated SMS target", err)
					}
					for _, substitute := range []string{"user", "action", "cookie"} {
						foreign := sourceRequest
						foreign.Caller = sourceRequest.Caller.Clone()
						switch substitute {
						case "user":
							foreign.UserID = user
						case "action":
							foreign.Caller.Request.Action = "identity.otp.signin"
						case "cookie":
							foreign.Flow, err = otp.NewPreAuthSendFlow(id, auth.NewBearerCredential(strings.Repeat("A", 43)))
							if err != nil {
								t.Fatal(err)
							}
						}
						denied, err := service.ResolveSigninSource(ctx, foreign)
						if _, projectionErr := denied.Bindings(); err == nil || projectionErr == nil {
							t.Fatal("foreign rate-source request disclosed original phone")
						}
					}
					assertPhoneOTPNoSuccess(t, ctx, pool, id, sent.CommandID, 0, 0, sessionBaseline)
				}
				wrongBytes := []byte(code)
				wrongBytes[0] = '0' + (wrongBytes[0]-'0'+1)%10
				wrongCode, err := auth.NewOneTimeCode(string(wrongBytes))
				clear(wrongBytes)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := auth.NewOneTimeCode(code)
				code = ""
				if err != nil {
					t.Fatal(err)
				}
				submission := otp.SigninRequest{TenantID: r.TenantID, Caller: r.Caller, Flow: flow, SendCommandID: sent.CommandID, Code: actual}
				if mode == "wrong-code" || mode == "exhausted" {
					attempts := 1
					if mode == "exhausted" {
						attempts = 5
					}
					for index := range attempts {
						wrong := submission
						wrong.Code = wrongCode
						denied, err := service.Signin(ctx, wrong)
						if err == nil || denied.Issuance.Token != (session.Token{}) || denied.CSRFToken != (session.CSRFToken{}) {
							t.Fatal("wrong phone code disclosed credentials")
						}
						assertPhoneOTPNoSuccess(t, ctx, pool, id, sent.CommandID, index+1, index+1)
						caller := r.Caller.Clone()
						caller.Request.Action = "identity.phone.signin.recover"
						for range 2 {
							history, err := service.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: r.TenantID, Caller: caller, Flow: flow, Recovery: denied.Recovery})
							if err == nil || history.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || history.SessionID != "" || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
								t.Fatal("wrong phone code recovery changed outcome or delivered secrets", err)
							}
						}
						assertPhoneOTPNoSuccess(t, ctx, pool, id, sent.CommandID, index+1, index+1)
					}
				}
				switch mode {
				case "late-account":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
				case "late-phone":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(r.TenantID), string(user))
				case "enrolled-factor":
					_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
				case "missing-factor":
					_, err = pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
				case "late-factor", "late-profile":
					policy := *selected.Signin.Coordinator.AdmissionPolicy
					policy.Authorization = &phoneOTPWithdrawalPolicy{base: policy.Authorization, pool: pool, profile: mode == "late-profile"}
					selected.Signin.Coordinator.AdmissionPolicy = &policy
					service, err = otppg.NewPhoneSigninService(pool, selected, crypto)
				case "rollback":
					_, err = pool.Raw().Exec(ctx, `ALTER TABLE public.identity_outbox_bindings ADD CONSTRAINT phone_otp_signin_fault CHECK(false) NOT VALID`)
				}
				if err != nil {
					t.Fatal("phone OTP negative interleave", err)
				}
				if mode == "lost-commit" || mode == "lost-denial" {
					testPhoneOTPLostCommit(t, ctx, pool, selected, crypto, submission, wrongCode, mode == "lost-denial")
					return
				}
				var result otp.SigninResult
				if mode == "concurrent" || mode == "mixed-race" {
					result = testPhoneOTPContention(t, ctx, pool, service, submission, wrongCode, mode == "mixed-race")
					if result.SessionID == "" {
						return
					}
				} else {
					result, err = service.Signin(ctx, submission)
				}
				if mode == "enrolled-factor" || mode == "missing-factor" || mode == "late-factor" || mode == "late-profile" || mode == "late-account" || mode == "late-phone" || mode == "rollback" || mode == "exhausted" {
					if err == nil || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
						t.Fatal("withdrawn, exhausted or rolled-back phone signin delivered credentials")
					}
					used, failed := 0, 0
					if mode == "exhausted" {
						used, failed = 5, 5
					}
					if mode == "late-profile" || mode == "late-account" || mode == "late-phone" || mode == "rollback" {
						// The OTP owner's reservation durably counts its real correct
						// comparison. A later protected failure releases the challenge;
						// it must not erase that charge or finalize consumption.
						used = 1
						var state string
						if err := pool.Raw().QueryRow(ctx, `SELECT state FROM phone_codes.challenges WHERE challenge_id=$1`, string(sent.CommandID)).Scan(&state); err != nil || state != "released" {
							t.Fatal("protected failure did not terminally release its original OTP reservation", err)
						}
					}
					assertPhoneOTPNoSuccess(t, ctx, pool, id, sent.CommandID, used, failed, sessionBaseline)
					return
				}
				if err != nil || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("delivered phone code cannot sign in", err)
				}
				spec, err := result.Issuance.Session.Bindings()
				gotRemember, rememberErr := spec.Remember.Bindings()
				wantRemember, _ := remember.Bindings()
				metadata, metadataErr := result.Issuance.Session.OTPAuthentication().Bindings()
				if err != nil || rememberErr != nil || metadataErr != nil || spec.UserID != user || spec.TenantID != r.TenantID || gotRemember != wantRemember || metadata.IdentifierKind != identity.IdentifierPhone {
					t.Fatal("phone OTP changed user, method or original remember policy")
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
				reader, err := sessionpg.NewOTPSessionService(pool, sessionpg.OTPSessionServiceConfig{Repository: config.Session, Profile: selected.Signin.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}})
				if err != nil {
					t.Fatal(err)
				}
				current, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
				if err != nil || !current.Authenticated {
					t.Fatal("phone OTP session is unusable", err)
				}
				var finalized, consumed, issued, audits, lifecycle int
				commandID, err := base64.RawURLEncoding.DecodeString(string(result.Issuance.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM phone_codes.challenges WHERE challenge_id=$1 AND state='finalized'),(SELECT count(*) FROM signin_sessions.preauth_transactions WHERE flow_id=$2 AND state='consumed'),(SELECT count(*) FROM signin_sessions.session_issuances WHERE command_id=$3 AND purpose='identity.phone.signin'),(SELECT count(*) FROM audit.records WHERE action='phone.signin' AND correlation_id=$4),(SELECT count(*) FROM public.outbox_messages WHERE topic='phone.signed-in.v1')`, string(sent.CommandID), string(id), commandID, string(result.Issuance.CommandID)).Scan(&finalized, &consumed, &issued, &audits, &lifecycle); err != nil || finalized != 1 || consumed != 1 || issued != 1 || audits != 1 || lifecycle != 1 {
					t.Fatal("phone OTP effects did not commit together", finalized, consumed, issued, audits, lifecycle, err)
				}
				restarted, err := otppg.NewPhoneSigninService(pool, selected, crypto)
				if err != nil {
					t.Fatal(err)
				}
				recoverCaller := r.Caller.Clone()
				recoverCaller.Request.Action = "identity.phone.signin.recover"
				history, err := restarted.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: r.TenantID, Caller: recoverCaller, Flow: flow, Recovery: result.Recovery})
				if err != nil || history.SessionID != spec.SessionID || !history.Issuance.Replayed || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("phone OTP recovery changed original or redelivered credentials", err)
				}
				revoke, err := sessionpg.NewRevokeOneExecutor(pool, sessionpg.RevokeOneExecutorConfig{Execution: sessionpg.IssueExecutorConfig{Repository: config.Session, Profile: sessionpg.IssueAdmissionConfig(config.Profile), Coordinator: config.Coordinator, Authorization: config.Coordinator.QueryPolicy.Authorization, Clock: config.Issuance.Clock, PolicyID: config.PolicyID, PolicyVersion: 3, AuditRetentionVersion: 1}, Sessions: reader, Admission: &sessionpg.SingleFactorSessionAdmissionConfig{OTP: &selected.Signin.Profile}})
				if err != nil {
					t.Fatal("phone OTP native logout composition", err)
				}
				logout, err := session.NewSignOutService(reader, revoke, session.SignOutConfig{Cookie: config.Issuance.Cookie, PolicyID: config.PolicyID, PolicyVersion: 3, MaximumDuration: 2 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				command, err := identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: r.TenantID, CommandID: command, CorrelationID: string(command), Transport: session.CredentialBearer, Credential: credential})
				if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("phone OTP session cannot log out", err)
				}
				if current, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); err != nil || current.Authenticated {
					t.Fatal("phone OTP logout left credential usable", err)
				}
			})
			if mode == "sessions" && choice == session.BrowserSession {
				testPhoneOTPPurposeHistories(t, ctx, pool, registration.TenantID, user)
			}
		})
	})
}

type phoneOTPWithdrawalPolicy struct {
	base    authorization.Service
	pool    *database.Pool
	once    sync.Once
	profile bool
}

func (p *phoneOTPWithdrawalPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	decision, err := p.base.Decide(ctx, c)
	if err == nil && c.Request.Resource.Type == "identity.user" && c.Request.Action == "identity.phone.signin" {
		p.once.Do(func() {
			query := `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`
			if p.profile {
				query = `UPDATE identity.identifiers SET normalization_profile='identity.phone.other-metadata',normalization_version=1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`
			}
			_, err = p.pool.Raw().Exec(ctx, query, string(c.Request.Tenant), string(c.Request.Resource.ID))
		})
	}
	return decision, err
}

func mustPhoneOTPCommandBytes(t *testing.T, command identity.CommandID) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(string(command))
	if err != nil || len(raw) != 16 {
		t.Fatal("invalid original command identity")
	}
	return raw
}

func assertPhoneOTPNoSuccess(t *testing.T, ctx context.Context, pool *database.Pool, flow identity.PreAuthTransactionID, challenge identity.CommandID, wantUsed, wantFailed int, baseline ...[2]int) {
	t.Helper()
	var issued, audits, lifecycle, consumed int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.session_issuances WHERE purpose='identity.phone.signin'),(SELECT count(*) FROM audit.records WHERE action='phone.signin' AND outcome=$2),(SELECT count(*) FROM public.outbox_messages WHERE topic='phone.signed-in.v1'),(SELECT count(*) FROM signin_sessions.preauth_transactions WHERE flow_id=$1 AND state='consumed')`, string(flow), int16(audit.OutcomeSucceeded)).Scan(&issued, &audits, &lifecycle, &consumed); err != nil || issued != 0 || audits != 0 || lifecycle != 0 || consumed != 0 {
		t.Fatal("denied phone signin left successful partial effects", issued, audits, lifecycle, consumed, err)
	}
	if challenge != "" {
		var used, failed int
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,state FROM phone_codes.challenges WHERE challenge_id=$1`, string(challenge)).Scan(&used, &failed, &state); err != nil || used != wantUsed || failed != wantFailed || state == "finalized" {
			t.Fatal("denied phone signin changed attempt conservation or finalized its code", used, failed, state, err)
		}
	}
	if len(baseline) == 1 {
		var after [2]int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.families),(SELECT count(*) FROM signin_sessions.sessions)`).Scan(&after[0], &after[1]); err != nil || after != baseline[0] {
			t.Fatal("denied phone signin left an orphan session or family", err)
		}
	}
}

func capturePhoneSigninSMS(t *testing.T, ctx context.Context, pool *database.Pool, config SignupConfig, crypto *envelope.Service, custody deliverypg.ContributorConfig, templates []delivery.Template, tenant identity.TenantID) string {
	t.Helper()
	workerPolicy := delivery.DefaultConfig()
	workerPolicy.Production, workerPolicy.DedupeTTL = true, 25*time.Hour
	authorize, err := authorization.NewDecisionService(signupVerificationWorkerPolicy{3})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: config.Coordinator, PolicyID: "phone-signin-worker", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{146}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, crypto, authorize, templates)
	if err != nil {
		t.Fatal("phone signin encrypted queue", err)
	}
	var code string
	calls := 0
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "phone-signin-worker", Request: authorization.Request{Tenant: authorization.TenantID(tenant), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "phone-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "phone-worker"}}}, ProviderConfigVersion: 2}, signupVerificationSender(func(_ context.Context, attempt delivery.Attempt) (delivery.DeliveryResult, error) {
		if attempt.Recipient != "+12025550123" || !strings.HasPrefix(string(attempt.Body), "Code: ") {
			t.Error("phone signin SMS changed original destination/content")
		}
		calls++
		code = strings.TrimPrefix(string(attempt.Body), "Code: ")
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || calls != 1 || len(code) != 6 {
		t.Fatal("phone signin captured encrypted SMS", err)
	}
	return code
}
