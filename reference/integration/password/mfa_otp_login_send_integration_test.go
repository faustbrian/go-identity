//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

// Only original browser initiation is seeded; later custody uses native Work.
type otpLoginBrowserFixture struct{ pool *database.Pool }

func (f otpLoginBrowserFixture) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return f.pool.Raw().Query(ctx, query, args...)
}
func (f otpLoginBrowserFixture) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	tag, err := f.pool.Raw().Exec(ctx, query, args...)
	return tag.RowsAffected(), err
}

// This is the actual public password -> signed OTP-only child -> native sender
// -> encrypted delivery path. The sole seeded boundary is browser pre-auth;
// account, confirmed factor and code come from the preceding native fixture.
func testPublicPasswordOTPLoginSend(t *testing.T, ctx context.Context, pool *database.Pool, source passwordpg.ReauthenticationConfig, enrollment mfapg.OTPEnrollmentConfig, keys *keyring.Provider, enrolled mfa.OtpSendRequest, codec *otppg.AttemptCodec, deliveryOwner *deliverypg.Contributor, attemptPolicy otp.AttemptPolicy, templates []delivery.Template, worker *deliverypg.Worker, captured func() (auth.OneTimeCode, auth.OneTimeCode, string), mode string) {
	t.Helper()
	base := mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}
	passwordHistory, err := (mfapg.PasswordContinuationMigrationSource{Base: base, Version: 16}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []migrations.Source{
		sessionpg.PreAuthMigrationSource{Schema: source.Session.Schema, Version: 3},
		riskpg.MFALoginSendCounterMigrationSource{Schema: enrollment.Counters.Schema, Version: 6},
	} {
		history, err := selected.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, migration := range history {
			if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("login-send selected history unavailable", err)
			}
		}
	}
	loginHistory, err := (mfapg.OTPLoginSendMigrationSource{Version: 17}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, loginHistory[0].UpSQL()); err != nil {
		t.Fatal("native continuation send attribution unavailable", err)
	}
	if _, err := pool.Raw().Exec(ctx, passwordHistory[len(passwordHistory)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(capabilitypg.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		wire, err := fs.ReadFile(capabilitypg.Migrations(), entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal("actual child issuer history unavailable", err)
		}
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signin-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{112}, 32))
	public := bytes.Clone(private.Public().(ed25519.PublicKey))
	signing, err := passwordpg.NewSigninSigningKey("otp-primary", private)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	flowMaterial := bytes.Repeat([]byte{113}, 32)
	defer clear(flowMaterial)
	flowKey, _ := session.NewDigestKey(1, flowMaterial)
	csrfKey, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{114}, 32))
	cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	query := *source.Coordinator.QueryPolicy
	coordinator := source.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &query
	c := passwordpg.SigninConfig{Repository: source.Repository, Verifier: source.Verifier, Session: source.Session, Profile: source.Profile, Address: email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}, FlowKeys: []session.DigestKey{flowKey}, Issuance: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: source.LookupKeys[0], TokenSize: 32, Cookie: cookiePolicy}, CSRFKey: csrfKey, Risk: source.Risk, Coordinator: coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"otp-primary": public}, Issuer: source.Issuer, Environment: source.Environment, PolicyID: "otp-login", ProofTTL: time.Minute, IdentifierKey: source.IdentifierKey, Origins: []string{enrolled.Origin}, CallbackURLs: []string{"https://app.test/after"}}
	childKey := bytes.Repeat([]byte{115}, 32)
	defer clear(childKey)
	childSigner, _ := capability.NewHMACSHA256Signer("otp-child", childKey)
	childVerifier, _ := capability.NewHMACSHA256Verifier(childKey)
	childKeys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "otp-child", Verifier: childVerifier}})
	issuer := capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.test", Signer: childSigner, Resolver: childKeys, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: source.Profile.Audience, CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {116}}, PreparationTimeout: time.Second}
	challenge := passwordpg.MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: "https://identity.test", AllowedMethods: []string{"otp"}, Issuer: issuer, Custody: capabilitypg.IssuancePreparationConfig{Deployment: "reauth-deployment", ActiveEnvelopeKey: "otp-child-envelope", EnvelopeKeys: map[string][]byte{"otp-child-envelope": bytes.Repeat([]byte{117}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "otp-child", HMAC: childKey}}, Clock: time.Now}}
	c.ProofTTL, challenge.Lifetime = 2*time.Minute, 2*time.Minute
	primary, err := passwordpg.NewMFASigninService(pool, c, challenge)
	if err != nil {
		t.Fatal("actual OTP-only password primary unavailable", err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := primitive.NewSecret([]byte("synthetic-test-password"))
	defer secret.Destroy()
	preauth, _ := identity.NewPreAuthTransactionID()
	token, _ := session.NewToken(32)
	cookie, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	caller := enrolled.Caller.Clone()
	caller.Request.Subject = authorization.Subject{ID: "otp-login-browser", Kind: authorization.SubjectServiceAccount}
	caller.Request.Action = "identity.password.signin"
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}
	r := password.SigninRequest{TenantID: enrolled.TenantID, PreAuthID: preauth, Cookie: auth.NewBearerCredential(cookie), Identifier: "mfa@example.test", Password: secret, Remember: remember, Origin: enrolled.Origin, CallbackURL: c.CallbackURLs[0], Caller: caller, Network: enrolled.Network, Device: "otp-browser"}
	var transport *otpHTTPJourney
	if mode == "login-http" {
		transport = newOTPHTTPJourney(t, ctx, pool, r.TenantID, r.Origin, r.CallbackURL, r.Network, cookiePolicy, source.Profile.Audience, caller)
		r.Device = transport.device.DeviceID()
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := session.PreAuthBinding{ID: preauth, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{118}, Remember: remember, PolicyID: c.PolicyID, PolicyVersion: query.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, _ := token.PreAuthDigest(flowKey, binding)
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, otpLoginBrowserFixture{pool}, source.Session, flow) != nil {
		t.Fatal("original browser fixture unavailable", err)
	}
	result, err := primary.Signin(ctx, r)
	if err != nil || result.State != auth.SignInStateChallengeRequired || result.Issuance.Token != (session.Token{}) {
		t.Fatalf("password did not issue actual OTP-only child: state=%d error=%v", result.State, err)
	}
	childOwner, _ := capabilitypg.NewIssuer(issuer)
	grant, _, _, err := childOwner.ReadIssuanceOrigin(ctx, pool, result.Challenge.Proof, "identity.mfa.complete")
	if err != nil {
		t.Fatal("actual issued child origin unavailable", err)
	}
	continuations, _ := mfapg.NewContinuationReader(pool, time.Second)
	continuation, err := continuations.Read(ctx, grant, challenge.IssuerURL)
	if err != nil {
		t.Fatal("actual OTP continuation unavailable", err)
	}
	originalFlow, err := sessionpg.ReadPreAuth(ctx, pool.Raw(), source.Session, r.TenantID, r.PreAuthID)
	if err != nil {
		t.Fatal("actual consumed browser unavailable", err)
	}
	if _, err := primary.ReadMFAPasswordPrimary(ctx, result.Challenge.Proof, continuation, originalFlow, caller); err != nil {
		t.Fatal("actual password comparison provenance unavailable", err)
	}
	factorReader, _ := mfapg.NewOTPFactorReader(pool, time.Second)
	if _, err := factorReader.Read(ctx, grant, challenge.IssuerURL, string(enrolled.FactorID)); err != nil {
		t.Fatal("actual confirmed OTP factor unavailable", err)
	}
	if _, err := factorReader.ReadLoginSend(ctx, grant, challenge.IssuerURL); err == nil {
		t.Fatal("unsent child invented an original OTP issuance")
	}
	loginIssuer, err := otppg.NewMFALoginIssuer(otppg.MFALoginIssuerConfig{Store: otppg.ContributorConfig{Schema: "mfa_otp", GlobalAuthorityID: source.Profile.GlobalAuthorityID, UserPolicyNamespace: source.Profile.PolicyNamespace, Codec: codec, LockoutKey: [32]byte{105}, PreAuth: source.Session, PreAuthCookieKeys: map[uint32][]byte{1: flowMaterial}}, Delivery: deliveryOwner, Policy: attemptPolicy, TemplateID: "mfa-otp", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates})
	if err != nil || loginIssuer.Initialize(ctx, pool) != nil {
		t.Fatal("actual partial-login OTP owner unavailable", err)
	}
	lookup, _ := kernel.NewRequestKeyConfig("otp-login-send", [32]byte{119}, query)
	config, err := reference.NewPasswordOTPLoginSendConfig(lookup, [32]byte{120}, "totp-v1")
	if err != nil {
		t.Fatal(err)
	}
	config.ConfigurationID, config.PolicyID, config.IssuerURL, config.MaximumDuration = "otp-login-send-v1", c.PolicyID, challenge.IssuerURL, 3*time.Second
	config.Primary, config.Issuance, config.Issuer = primary, loginIssuer, issuer
	config.Session, config.Profile, config.CookieKeys = source.Session, source.Profile, map[uint32]session.DigestKey{1: flowKey}
	config.Coordinator, config.Risk, config.Counters, config.AllowedOrigins = coordinator, enrollment.Risk, enrollment.Counters, c.Origins
	sender, err := reference.NewPasswordOTPLoginSendService(pool, config, keys)
	if err != nil {
		t.Fatal("public sender composition unavailable", err)
	}
	caller.Request.Action = "identity.mfa.otp-send"
	caller.Request.Resource = authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(result.Challenge.ID)}
	key, _ := identity.NewIdempotencyKey([]byte("actual-password-otp-send"))
	send := mfa.OtpSendRequest{TenantID: r.TenantID, ContinuationID: mfa.ContinuationID(result.Challenge.ID), FactorID: enrolled.FactorID, Channel: enrolled.Channel, Proof: result.Challenge.Proof, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Caller: caller, Origin: r.Origin, Callback: r.CallbackURL, Network: r.Network, Device: r.Device, IdempotencyKey: key}
	if transport != nil {
		transport.captureProof(t, ctx, &send)
	}
	if err := send.Validate(); err != nil {
		t.Fatal("public OTP browser request invalid", err)
	}
	var sourceMappingsBefore, sourceMappingsAfter int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&sourceMappingsBefore); err != nil {
		t.Fatal(err)
	}
	canonicalDestination, err := sender.OtpSendingRateSource(ctx, send)
	if err != nil || canonicalDestination != "mfa@example.test" {
		t.Fatal("native send source lost confirmed canonical recipient", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&sourceMappingsAfter); err != nil || sourceMappingsBefore != sourceMappingsAfter {
		t.Fatal("quota source allocated a request command", err)
	}
	for n, change := range []func(*mfa.OtpSendRequest){
		func(r *mfa.OtpSendRequest) {
			other, _ := session.NewToken(32)
			wire, _ := other.Reveal()
			r.Cookie = auth.NewBearerCredential(wire)
		},
		func(r *mfa.OtpSendRequest) { id, _ := identity.NewCommandID(); r.FactorID = mfa.FactorID(id) },
		func(r *mfa.OtpSendRequest) { r.Callback = "https://app.test/foreign" },
		func(r *mfa.OtpSendRequest) { r.Channel = delivery.ChannelSMS },
	} {
		candidate := send
		candidate.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte{byte(n + 1), 121})
		change(&candidate)
		if destination, err := sender.OtpSendingRateSource(ctx, candidate); err == nil || destination != "" {
			t.Fatal("foreign source selected a delivery quota destination")
		}
		if out, err := sender.OtpSend(ctx, candidate); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.ChallengeID != "" || out.DeliveryState != 0 {
			t.Fatal("foreign browser/factor/callback/channel acquired delivery", err)
		}
	}
	// Confirming enrollment cannot refill the same account/destination send
	// window. The first login send must retain that native resend protection.
	denied, err := sender.OtpSend(ctx, send)
	if err == nil || denied.Outcome != identity.CommitOutcomeNotCommitted || denied.ChallengeID != "" || denied.DeliveryState != 0 {
		t.Fatal("new login child reset the enrollment resend budget", err)
	}
	profile, _, _ := attemptPolicy.Bindings()
	var lastSent time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT sent_at[cardinality(sent_at)] FROM mfa_otp.send_families WHERE tenant_id=$1`, string(send.TenantID)).Scan(&lastSent); err != nil {
		t.Fatal("native send history unavailable", err)
	}
	timer := time.NewTimer(time.Until(lastSent.Add(profile.ResendInterval)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("bounded real resend interval expired test context")
	case <-timer.C:
	}
	if replay, err := sender.OtpSend(ctx, send); replay.CommandID != denied.CommandID || replay.Outcome != identity.CommitOutcomeNotCommitted || replay.ChallengeID != "" {
		t.Fatal("elapsed time rewrote original send denial", err)
	}
	rolled := send
	rolled.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("actual-password-otp-send-rollback"))
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_login_otp_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $fn$; CREATE TRIGGER reject_login_otp_fixture AFTER INSERT ON mfa_otp.challenges FOR EACH ROW EXECUTE FUNCTION public.reject_login_otp_fixture()`); err != nil {
		t.Fatal(err)
	}
	rollback, rollbackErr := sender.OtpSend(ctx, rolled)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_login_otp_fixture ON mfa_otp.challenges; DROP FUNCTION public.reject_login_otp_fixture()`); err != nil {
		t.Fatal(err)
	}
	if rollbackErr == nil || rollback.Outcome != identity.CommitOutcomeNotCommitted || rollback.ChallengeID != "" || rollback.DeliveryState != 0 {
		t.Fatal("failed login send retained or disclosed partial effects", rollbackErr)
	}
	var challenges, intents int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM mfa_otp.challenges),(SELECT count(*) FROM identity.delivery_intents)`).Scan(&challenges, &intents); err != nil || challenges != 1 || intents != 1 {
		t.Fatal("failed/foreign login sends retained OTP or delivery", err)
	}
	send.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("actual-password-otp-send-after-cooldown"))
	var queued mfa.OtpSendResult
	if transport != nil {
		queued = transport.send(t, ctx, sender, send)
		err = nil
	} else {
		queued, err = sender.OtpSend(ctx, send)
	}
	if err != nil || queued.Outcome != identity.CommitOutcomeCommitted || queued.ChallengeID == "" || queued.DeliveryState != delivery.StateQueued {
		var invalid identity.InvalidInputError
		errors.As(err, &invalid)
		t.Fatalf("public password OTP did not queue: outcome=%d error=%v field=%s", queued.Outcome, err, invalid.Field)
	}
	originalSend, err := factorReader.ReadLoginSend(ctx, grant, challenge.IssuerURL)
	if err != nil || originalSend.CommandID != queued.CommandID || originalSend.FactorID != send.FactorID || originalSend.ContinuationID != send.ContinuationID {
		t.Fatal("verification cannot restore the child's exact original committed send", err)
	}
	restarted, err := reference.NewPasswordOTPLoginSendService(pool, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := restarted.OtpSend(ctx, send); err != nil || replay != queued {
		t.Fatal("sender restart changed original challenge", err)
	}
	if destination, err := restarted.OtpSendingRateSource(ctx, send); err != nil || destination != canonicalDestination {
		t.Fatal("restart lost retained delivery quota destination", err)
	}
	recovery := identity.RecoveryQuery{TenantID: send.TenantID, CommandID: queued.CommandID, AnonymousFlowID: string(send.PreAuthID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: "identity.mfa.otp-send", RecordID: string(send.FactorID)}
	recoveryCaller := caller.Clone()
	recoveryCaller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(send.PreAuthID)}
	if replay, err := restarted.RecoverOtpSend(ctx, recovery, recoveryCaller); err != nil || replay != queued {
		t.Fatal("proof/cookie-free send recovery failed", err)
	}
	userRecovery := recovery
	userRecovery.AnonymousFlowID, userRecovery.UserID = "", identity.UserID(enrolled.Caller.Request.Subject.ID)
	userCaller := recoveryCaller.Clone()
	userCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(userRecovery.UserID)}
	if out, err := restarted.RecoverOtpSend(ctx, userRecovery, userCaller); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.ChallengeID != "" {
		t.Fatal("anonymous send was adopted as a user-owned command", err)
	}
	changed := send
	changed.Network = "192.0.2.99"
	if _, err := restarted.OtpSend(ctx, changed); err == nil {
		t.Fatal("same key adopted changed browser intent")
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || processed.Completion.State != delivery.StateDelivered {
		t.Fatal("password OTP did not reach actual delivery worker", err)
	}
	if again, err := worker.ProcessOne(ctx); err != nil || again.Claimed {
		t.Fatal("password OTP was redelivered", err)
	}
	var consumed bool
	var factorState, sessions, remaining, uses int
	if err := pool.Raw().QueryRow(ctx, `SELECT p.state='consumed',f.state,(SELECT count(*) FROM reauth_sessions.sessions),c.attempts_remaining,u.uses FROM reauth_sessions.preauth_transactions p JOIN identity_mfa.otp_factors f ON f.tenant_id=p.tenant_id AND f.factor_id=$3 JOIN identity_mfa.continuations c ON c.tenant_id=p.tenant_id AND c.continuation_id=$4 JOIN public.capability_identity_one_use u ON u.tenant_id=p.tenant_id AND u.capability_id=c.continuation_id WHERE p.tenant_id=$1 AND p.flow_id=$2`, string(send.TenantID), string(send.PreAuthID), string(send.FactorID), string(send.ContinuationID)).Scan(&consumed, &factorState, &sessions, &remaining, &uses); err != nil || !consumed || factorState != 2 || sessions != 1 || remaining != 3 || uses != 0 {
		t.Fatal("sending consumed child/budget, changed primary/factor, or issued a session", err)
	}
	for _, selected := range []migrations.Source{
		riskpg.MFAOTPCompletionCounterMigrationSource{Schema: enrollment.Counters.Schema, Version: 7},
		sessionpg.OTPMigrationSource{Schema: source.Session.Schema, Version: 4},
		sessionpg.CredentialContinuationMigrationSource{Schema: source.Session.Schema, Version: 5},
		sessionpg.MagicLinkMigrationSource{Schema: source.Session.Schema, Version: 6},
		sessionpg.MFAMigrationSource{Schema: source.Session.Schema, Version: 7},
		sessionpg.PasswordMFAMigrationSource{Schema: source.Session.Schema, Version: 8},
		sessionpg.MFARecoveryMigrationSource{Schema: source.Session.Schema, Version: 9},
		sessionpg.MFAOTPRecordMigrationSource{Schema: source.Session.Schema, Version: 10},
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: source.Session.Schema, Version: 1}, Version: 11}, Version: 12},
		sessionpg.OTPIssueMigrationSource{Schema: source.Session.Schema, Version: 13},
		sessionpg.PreAuthIssueMigrationSource{Schema: source.Session.Schema, Version: 14},
		sessionpg.PasswordSigninMigrationSource{Schema: source.Session.Schema, Version: 15},
		sessionpg.PasswordSignupMigrationSource{Schema: source.Session.Schema, Version: 16},
		sessionpg.MagicLinkSigninMigrationSource{Schema: source.Session.Schema, Version: 17},
		sessionpg.MFASigninMigrationSource{Schema: source.Session.Schema, Version: 18},
	} {
		history, err := selected.Load(ctx)
		if err != nil {
			t.Fatal("selected OTP completion history", err)
		}
		for _, migration := range history {
			if migration.Version() <= 3 {
				continue
			}
			if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal("OTP completion installation", err)
			}
		}
	}
	completionSender := restarted
	if strings.HasPrefix(mode, "login-unknown-") || mode == "login-contention" {
		// Recovery needs a bounded expired lease, but unrelated send/rollback
		// setup must retain its ordinary profile. Give the protected execution
		// its full configured budget before the test-only recovery lease expires.
		config.Coordinator.LeaseDuration = config.Coordinator.MaximumDuration + time.Second
		completionSender, err = reference.NewPasswordOTPLoginSendService(pool, config, keys)
		if err != nil {
			t.Fatal("bounded completion recovery profile unavailable", err)
		}
	}
	completionConfig := reference.PasswordOTPLoginCompletionConfig{Sender: completionSender, ConfigurationID: "otp-login-completion-v1", SessionIssuer: c.Issuance, CSRF: csrfKey, AttemptKeyVersion: 1}
	completion, err := reference.NewPasswordOTPLoginCompletionService(completionConfig)
	if err != nil {
		t.Fatal("public secondary OTP completion composition unavailable", err)
	}
	code, wrong, codeWire := captured()
	id, _ := identity.NewCommandID()
	verifyCaller := send.Caller.Clone()
	verifyCaller.Request.Action = "identity.mfa.otp-verify"
	verify := mfa.OtpVerifyRequest{TenantID: send.TenantID, CommandID: id, ContinuationID: send.ContinuationID, Code: code, Proof: send.Proof, PreAuthID: send.PreAuthID, Cookie: send.Cookie, Caller: verifyCaller, Origin: send.Origin, Callback: send.Callback, Network: send.Network, Device: send.Device}
	if verify.Validate() != nil {
		t.Fatal("actual delivered OTP verification request invalid")
	}
	var originalRateLifetime time.Duration
	assertRateSource := func(request mfa.OtpVerifyRequest) {
		t.Helper()
		user, child, lifetime, err := completion.OtpVerificationRateSource(ctx, request)
		if err != nil || user != identity.UserID(enrolled.Caller.Request.Subject.ID) || child != string(send.ContinuationID) || lifetime < time.Second || lifetime > 5*time.Minute {
			t.Fatal("native OTP rate source lost original subject/child/interval", err)
		}
		if originalRateLifetime != 0 && originalRateLifetime != lifetime {
			t.Fatal("OTP quota source renewed or shortened the signed interval")
		}
		originalRateLifetime = lifetime
	}
	assertRateSource(verify)
	for _, alter := range []func(*mfa.OtpVerifyRequest){
		func(r *mfa.OtpVerifyRequest) {
			r.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{122}, 32)))
		},
		func(r *mfa.OtpVerifyRequest) {
			tenant, _ := identity.NewSubjectID()
			r.TenantID = identity.TenantID(tenant)
		},
		func(r *mfa.OtpVerifyRequest) { r.Callback = "https://foreign.test/after" },
	} {
		foreign := verify
		foreign.CommandID, _ = identity.NewCommandID()
		alter(&foreign)
		if user, child, lifetime, err := completion.OtpVerificationRateSource(ctx, foreign); err == nil || user != "" || child != "" || lifetime != 0 {
			t.Fatal("foreign browser/tenant/callback exported OTP quota identity")
		}
		if denied, err := completion.OtpVerify(ctx, foreign); err == nil || denied.Outcome == identity.CommitOutcomeCommitted || denied.Session.Token != (session.Token{}) || denied.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("foreign browser, tenant or callback acquired an OTP session", err)
		}
	}
	deniedVerify := verify
	deniedVerify.CommandID, _ = identity.NewCommandID()
	deniedVerify.Code = wrong
	if out, err := completion.OtpVerify(ctx, deniedVerify); err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("wrong actual delivered-code submission did not terminate without credentials", err)
	}
	var before, after int
	if err := pool.Raw().QueryRow(ctx, `SELECT attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(send.TenantID), string(send.ContinuationID)).Scan(&before); err != nil || before != 2 {
		t.Fatal("wrong OTP did not debit the original shared budget exactly once", err)
	}
	if out, err := completion.OtpVerify(ctx, deniedVerify); err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Session.Token != (session.Token{}) {
		t.Fatal("wrong-code replay changed its retained denial", err)
	}
	assertRateSource(deniedVerify)
	conflicting := deniedVerify
	conflicting.Code = code
	if user, child, lifetime, err := completion.OtpVerificationRateSource(ctx, conflicting); err == nil || user != "" || child != "" || lifetime != 0 {
		t.Fatal("changed historical code exported OTP quota identity")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, string(send.TenantID), string(send.ContinuationID)).Scan(&after); err != nil || before != after {
		t.Fatal("wrong-code replay debited the shared budget again", err)
	}
	var wrongChildState string
	var wrongChildUses int
	var wrongChildOwned bool
	if err := pool.Raw().QueryRow(ctx, `SELECT state,uses,command_id IS NOT NULL FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(send.TenantID), string(send.ContinuationID)).Scan(&wrongChildState, &wrongChildUses, &wrongChildOwned); err != nil || wrongChildState != "issued" || wrongChildUses != 0 || wrongChildOwned {
		t.Fatal("wrong-code denial retained or consumed the one-use child", err)
	}
	if mode == "login-rollback" {
		if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_otp_login_session_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $fn$; CREATE TRIGGER reject_otp_login_session_fixture AFTER INSERT ON reauth_sessions.sessions FOR EACH ROW EXECUTE FUNCTION public.reject_otp_login_session_fixture()`); err != nil {
			t.Fatal(err)
		}
		out, failure := completion.OtpVerify(ctx, verify)
		if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_otp_login_session_fixture ON reauth_sessions.sessions; DROP FUNCTION public.reject_otp_login_session_fixture()`); err != nil {
			t.Fatal(err)
		}
		if failure == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("native session write failure did not roll back OTP login without credentials", failure)
		}
		assertPasswordOTPLoginEffects(t, ctx, pool, verify, false)
		q := passwordOTPLoginRecoveryQuery(verify)
		if recovered, err := completion.RecoverOtpVerify(ctx, q, verify.Caller); recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("code-free rollback recovery changed its original outcome", err)
		}
		if replay, err := completion.OtpVerify(ctx, verify); err == nil || replay.Outcome != identity.CommitOutcomeNotCommitted || replay.Session.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("failed OTP login replay resumed or disclosed a credential", err)
		}
		assertPasswordOTPLoginEffects(t, ctx, pool, verify, false)
		return
	}
	if mode == "login-unknown-before" || mode == "login-unknown-after" {
		beforeCommit := mode == "login-unknown-before"
		fault := &reauthenticationCommitFault{before: beforeCommit, marker: []byte(`INSERT INTO "reauth_sessions".sessions(`)}
		faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if err != nil {
			t.Fatal("owned OTP-login commit-fault pool unavailable")
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := faultPool.Close(cleanup); err != nil {
				t.Error("OTP-login commit-fault pool cleanup failed")
			}
		}()
		faultSender, err := reference.NewPasswordOTPLoginSendService(faultPool, config, keys)
		if err != nil {
			t.Fatal("native OTP-login fault sender unavailable", err)
		}
		faultConfig := completionConfig
		faultConfig.Sender = faultSender
		faultCompletion, err := reference.NewPasswordOTPLoginCompletionService(faultConfig)
		if err != nil {
			t.Fatal("native OTP-login fault completion unavailable", err)
		}
		out, failure := faultCompletion.OtpVerify(ctx, verify)
		if failure == nil || out.Outcome != identity.CommitOutcomeUnknown || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) || !fault.hit.Load() {
			t.Fatal("ambiguous OTP login fabricated outcome or disclosed credentials", failure)
		}
		want := identity.CommitOutcomeCommitted
		if beforeCommit {
			want = identity.CommitOutcomeNotCommitted
		}
		awaitPasswordOTPLoginRecovery(t, ctx, pool, faultCompletion, verify, want)
		assertPasswordOTPLoginEffects(t, ctx, pool, verify, !beforeCommit)
		if replay, err := faultCompletion.OtpVerify(ctx, verify); replay.Outcome != want || replay.Session.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) || !beforeCommit && err != nil {
			t.Fatal("ambiguous OTP-login replay changed its known result or disclosed a credential", err)
		}
		assertPasswordOTPLoginEffects(t, ctx, pool, verify, !beforeCommit)
		return
	}
	if mode == "login-contention" {
		type attempt struct {
			request mfa.OtpVerifyRequest
			result  mfa.OtpVerifyResult
			err     error
		}
		start, results := make(chan struct{}), make(chan attempt, 2)
		for range 2 {
			candidate := verify
			candidate.CommandID, _ = identity.NewCommandID()
			go func(r mfa.OtpVerifyRequest) {
				<-start
				result, err := completion.OtpVerify(ctx, r)
				results <- attempt{r, result, err}
			}(candidate)
		}
		close(start)
		commits := 0
		for range 2 {
			r := <-results
			if r.result.Outcome == identity.CommitOutcomeCommitted && r.err == nil {
				commits++
				if r.result.Session.Token == (session.Token{}) || r.result.CSRFToken == (session.CSRFToken{}) {
					t.Error("winning native OTP command withheld fresh credentials")
				}
			} else {
				if r.result.Session.Token != (session.Token{}) || r.result.CSRFToken != (session.CSRFToken{}) {
					t.Error("losing native OTP command disclosed a credential")
				}
				if r.result.Outcome == identity.CommitOutcomeUnknown || r.result.Outcome == identity.CommitOutcomeInProgress {
					awaitPasswordOTPLoginRecovery(t, ctx, pool, completion, r.request, identity.CommitOutcomeNotCommitted)
					for range 2 {
						replay, _ := completion.OtpVerify(ctx, r.request)
						if replay.Outcome != identity.CommitOutcomeNotCommitted || replay.Session.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) {
							t.Fatal("losing OTP preparation replay changed its durable denial or disclosed credentials")
						}
						awaitPasswordOTPLoginRecovery(t, ctx, pool, completion, r.request, identity.CommitOutcomeNotCommitted)
					}
				}
			}
		}
		if commits != 1 {
			t.Fatal("contending OTP commands did not produce exactly one authenticated session", commits)
		}
		assertPasswordOTPLoginEffects(t, ctx, pool, verify, true)
		return
	}
	if transport != nil {
		transport.complete(t, ctx, pool, source, completion, verify, codeWire)
		return
	}
	completed, err := completion.OtpVerify(ctx, verify)
	if err != nil || completed.Outcome != identity.CommitOutcomeCommitted || completed.Session.Token == (session.Token{}) || completed.CSRFToken == (session.CSRFToken{}) {
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		var claims, journals, charges int
		var state string
		var declared, started, output, attached bool
		inspection := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM otp_enrollment_risk.counter_charges WHERE command_id=$1),coalesce((SELECT state FROM identity.commands WHERE command_id=$1),''),coalesce((SELECT preparation_declaration IS NOT NULL FROM identity.commands WHERE command_id=$1),false),coalesce((SELECT preparation_started_generation IS NOT NULL FROM identity.commands WHERE command_id=$1),false),coalesce((SELECT preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1),false),coalesce((SELECT command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1),false)`, raw).Scan(&claims, &journals, &charges, &state, &declared, &started, &output, &attached)
		t.Fatalf("actual delivered OTP did not authenticate a session: outcome=%d error=%v journal=%s claims=%d journals=%d charges=%d declaration=%t started=%t output=%t final=%t inspection=%T", completed.Outcome, err, state, claims, journals, charges, declared, started, output, attached, inspection)
	}
	record, err := completed.Session.Session.Bindings()
	metadata, factorErr := completed.Session.Session.MFAAuthentication().Bindings()
	originalRemember, _ := remember.Bindings()
	issuedRemember, _ := record.Remember.Bindings()
	if err != nil || factorErr != nil || record.Authentication.Kind != session.AuthenticationVerified || record.Authentication.Proof.Method != "password" || metadata.Method != "otp" || metadata.FactorID != string(send.FactorID) || metadata.ContinuationID != identity.CommandID(send.ContinuationID) || issuedRemember != originalRemember {
		t.Fatal("OTP completion lost original password, factor, child or remember provenance")
	}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: source.Profile.Audience, Clock: clock.System{}, MaximumDuration: source.Session.MaximumDuration, ClockUncertainty: time.Millisecond, LookupKeys: source.LookupKeys}
	readConfig := sessionpg.SessionServiceConfig{Repository: source.Session, Profile: source.Profile, Validation: validation}
	reader, err := sessionpg.NewMFAPasswordSessionService(pool, readConfig)
	if err != nil {
		t.Fatal("native password/OTP session reader unavailable", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, completed.Session.Token)
	if err != nil {
		t.Fatal("issued token could not select cookie transport", err)
	}
	get := session.GetRequest{TenantID: send.TenantID, Credential: credential}
	observed, err := reader.Get(ctx, get)
	if err != nil || !observed.Authenticated || observed.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("newly issued password/OTP session did not authenticate through its native reader", err)
	}
	combined, err := sessionpg.NewSelectedSessionService(pool, sessionpg.SelectedSessionServiceConfig{Repository: source.Session, Validation: validation, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: sessionpg.SingleFactorSessionAdmissionConfig{Verified: &source.Profile}, MFAPassword: &source.Profile}})
	if err != nil {
		t.Fatal("selected native session composition unavailable", err)
	}
	if current, err := combined.Get(ctx, get); err != nil || !current.Authenticated || current.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("selected composition lost native OTP authority", err)
	}
	ordinary, err := sessionpg.NewSessionService(pool, readConfig)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := ordinary.Get(ctx, get); err != nil || current.Authenticated {
		t.Fatal("ordinary password reader erased the OTP factor", err)
	}
	if replay, err := completion.OtpVerify(ctx, verify); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Session.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("committed OTP replay regenerated or redelivered a credential", err)
	}
	if destination, err := restarted.OtpSendingRateSource(ctx, send); err != nil || destination != canonicalDestination {
		t.Fatal("consumed primary/child broke exact send quota source", err)
	}
	assertRateSource(verify)
	queryReceipt := identity.RecoveryQuery{TenantID: verify.TenantID, CommandID: verify.CommandID, AnonymousFlowID: string(verify.PreAuthID), ActorID: identity.ActorID(verify.Caller.Request.Subject.ID), ActorKind: verify.Caller.Request.Subject.Kind, OperationID: "identity.mfa.otp-verify"}
	if recovered, err := completion.RecoverOtpVerify(ctx, queryReceipt, verify.Caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("code-free OTP recovery changed commit or disclosed a credential", err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(record.TenantID), string(record.UserID)); err != nil {
		t.Fatal(err)
	}
	for _, service := range []*session.SessionService{reader, combined} {
		if current, err := service.Get(ctx, get); err != nil || current.Authenticated {
			t.Fatal("changed OTP authority still authenticates its original session", err)
		}
	}
	if replay, err := completion.OtpVerify(ctx, verify); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Session.Token != (session.Token{}) || replay.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("terminal history reread changed current factor or disclosed credentials", err)
	}
	assertRateSource(verify)
}

func passwordOTPLoginRecoveryQuery(r mfa.OtpVerifyRequest) identity.RecoveryQuery {
	return identity.RecoveryQuery{TenantID: r.TenantID, CommandID: r.CommandID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.mfa.otp-verify"}
}

func assertPasswordOTPLoginEffects(t *testing.T, ctx context.Context, pool *database.Pool, r mfa.OtpVerifyRequest, committed bool) {
	t.Helper()
	var count, remaining, uses, state int
	var otpState, childState string
	var primaryConsumed bool
	err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM reauth_sessions.sessions),c.attempts_remaining,c.state,u.uses,u.state,o.state,p.state='consumed'
FROM identity_mfa.continuations c
JOIN public.capability_identity_one_use u ON u.tenant_id=c.tenant_id AND u.capability_id=c.continuation_id
JOIN reauth_sessions.preauth_transactions p ON p.tenant_id=c.tenant_id AND p.flow_id=c.source_preauth_id
JOIN mfa_otp.challenges o ON o.tenant_id=c.tenant_id AND o.challenge_id=(SELECT challenge_id FROM mfa_otp.challenges WHERE tenant_id=c.tenant_id AND issue_command_id=c.otp_send_command_id)
WHERE c.tenant_id=$1 AND c.continuation_id=$2`, string(r.TenantID), string(r.ContinuationID)).Scan(&count, &remaining, &state, &uses, &childState, &otpState, &primaryConsumed)
	if err != nil {
		t.Fatal("native OTP login effects unavailable", err)
	}
	wantCount, wantRemaining, wantState, wantUses, wantTerminal := 1, 2, int(mfa.Challenged), 0, "released"
	if committed {
		wantCount, wantRemaining, wantState, wantUses, wantTerminal = 2, 1, 3, 1, "finalized"
	}
	if count != wantCount || remaining != wantRemaining || state != wantState || uses != wantUses || childState != wantTerminal || otpState != wantTerminal || !primaryConsumed {
		t.Fatalf("OTP login effects diverged: sessions=%d remaining=%d continuation=%d uses=%d child=%s otp=%s primary-consumed=%t", count, remaining, state, uses, childState, otpState, primaryConsumed)
	}
}

func awaitPasswordOTPLoginRecovery(t *testing.T, ctx context.Context, pool *database.Pool, service *reference.PasswordOTPLoginCompletionService, r mfa.OtpVerifyRequest, want identity.CommitOutcome) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		out, err := service.RecoverOtpVerify(ctx, passwordOTPLoginRecoveryQuery(r), r.Caller)
		if out.Outcome == want {
			if want == identity.CommitOutcomeCommitted && err != nil || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("OTP-login recovery returned error or credentials for a known outcome", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("OTP-login recovery context ended")
		case <-deadline.C:
			raw, _ := base64.RawURLEncoding.DecodeString(string(r.CommandID))
			var state string
			var declared, started, output, attached, live bool
			inspection := pool.Raw().QueryRow(ctx, `SELECT state,preparation_declaration IS NOT NULL,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,lease_until>clock_timestamp() FROM identity.commands WHERE command_id=$1`, raw).Scan(&state, &declared, &started, &output, &attached, &live)
			t.Fatalf("OTP-login recovery did not reach its durable outcome: outcome=%d error=%T journal=%s declaration=%t started=%t output=%t final=%t live=%t inspection=%T", out.Outcome, err, state, declared, started, output, attached, live, inspection)
		case <-tick.C:
		}
	}
}
