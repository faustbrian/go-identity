//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestNativeVerifiedPhonePasswordTOTPChallenge(t *testing.T) {
	testNativeSigninPhaseIntegration(t, "phone password TOTP", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, policy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			factor, secret := testNativeEnrolledPhoneTOTP(t, ctx, pool, config, registration, user, keys)
			defer clear(secret)
			if factor == "" {
				t.Fatal("confirmed native TOTP missing")
			}
			testPhoneMFAForward(t, ctx, pool, PhoneMFASigninMigrationSource{Base: MigrationSource{}, Version: 95}, 95)
			base := mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}
			testPhoneMFAForward(t, ctx, pool, mfapg.PasswordContinuationMigrationSource{Base: base, Version: 96}, 96)
			testPhoneMFAForward(t, ctx, pool, mfapg.PhoneContinuationMigrationSource{Base: mfapg.PasswordContinuationMigrationSource{Base: base, Version: 96}, Version: 97}, 97)
			config.Phone = policy
			challenge := testPhoneMFAChallengeConfig(t, config)
			service, err := NewPhoneMFASigninService(pool, config, challenge)
			if err != nil {
				t.Fatal("actual phone MFA composition", err)
			}
			for _, methods := range [][]string{{"otp"}, {"recovery-code"}, {"totp", "otp"}} {
				bad := challenge
				bad.AllowedMethods = methods
				if other, err := NewPhoneMFASigninService(pool, config, bad); err == nil || other != nil {
					t.Fatal("phone TOTP profile accepted weaker completion")
				}
			}
			if old, err := NewMFASigninService(pool, config, challenge); err == nil || old != nil {
				t.Fatal("legacy password MFA factory silently selected phone")
			}
			var sessionsBefore, finalBefore int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records)`).Scan(&sessionsBefore, &finalBefore); err != nil {
				t.Fatal(err)
			}
			request, _, _, _ := nativeSigninFlow(t)
			request.TenantID, request.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
			request.Identifier, request.Password, request.Device = "+12025550123", registration.Password, "phone-mfa-browser"
			request.Caller.Request.Action, request.Caller.Request.Resource.ID = "identity.phone.password-signin", "identity.phone.password-signin"
			request.PreAuthID, _ = identity.NewPreAuthTransactionID()
			number, err := policy.Canonicalize(ctx, string(request.Identifier))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := number.DeliveryNumber()
			if err != nil {
				t.Fatal(err)
			}
			target, err := phone.PasswordSigninIdentifierBinding(number, request.TenantID, config.IdentifierKey)
			if err != nil {
				t.Fatal(err)
			}
			flow := testPhoneMFASigninBrowser(t, ctx, pool, config, request, target)
			wrong := request
			wrong.Password, err = primitive.NewSecret([]byte("synthetic-wrong-password"))
			if err != nil {
				t.Fatal(err)
			}
			rejected, err := service.Signin(ctx, wrong)
			wrong.Password.Destroy()
			if err != nil || rejected.State != auth.SignInStateRejected || rejected.Challenge != (password.MFAChallengeResult{}) {
				t.Fatal("wrong phone password obtained challenge", err)
			}
			retarget := request
			retarget.Identifier = "+12025550124"
			if denied, err := service.Signin(ctx, retarget); err == nil || denied.Challenge != (password.MFAChallengeResult{}) {
				t.Fatal("phone original browser retargeted")
			}
			out, err := service.Signin(ctx, request)
			if err != nil || out.State != auth.SignInStateChallengeRequired || out.Validate() != nil || out.SessionID != "" || out.Issuance.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) || out.Challenge.Proof == (capability.Proof{}) {
				t.Fatalf("actual phone TOTP challenge: state=%v error=%v", out.State, err)
			}
			var sessions, final, primaries, continuations int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.signin_records),(SELECT count(*) FROM identity_password.mfa_primary_records WHERE purpose='identity.phone.password-signin'),(SELECT count(*) FROM identity_mfa.continuations WHERE origin_purpose='identity.phone.password-signin'),state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(request.PreAuthID)).Scan(&sessions, &final, &primaries, &continuations, &state); err != nil || sessions != sessionsBefore || final != finalBefore || primaries != 1 || continuations != 1 || state != "consumed" {
				t.Fatal("phone primary created final authentication or split effects", err)
			}
			child, err := capability.NewService(challenge.Issuer.Crypto)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := child.Verify(ctx, out.Challenge.Proof, "identity.mfa.complete", config.Profile.Audience)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := mfapg.NewContinuationReader(pool, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			continuation, err := reader.Read(ctx, grant, challenge.IssuerURL)
			if err != nil {
				t.Fatal("genuine phone continuation", err)
			}
			primary, err := service.ReadMFAPasswordPrimary(ctx, out.Challenge.Proof, continuation, flow, request.Caller)
			if err != nil || primary.Recipient.User.ID != user || primary.Recipient.Identifier.Kind != identity.IdentifierPhone || primary.Recipient.Identifier.CanonicalValue != canonical || primary.Authentication.Proof.Purpose != session.PasswordMFAPrimaryPurpose {
				t.Fatal("genuine phone primary cannot enter existing completion", err)
			}
			restarted, err := NewPhoneMFASigninService(pool, config, challenge)
			if err != nil {
				t.Fatal(err)
			}
			recovery := password.SigninRecoveryRequest{Recovery: out.Recovery, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device}
			recovered, err := restarted.RecoverSignin(ctx, recovery)
			if err != nil || recovered.State != auth.SignInStateChallengeRequired || recovered.Challenge.ID != out.Challenge.ID || recovered.Challenge.ExpiresAt != out.Challenge.ExpiresAt || recovered.Challenge.Proof != (capability.Proof{}) || recovered.SessionID != "" || recovered.Issuance.Token != (session.Token{}) {
				t.Fatal("phone challenge recovery regenerated secret or lost original outcome", err)
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='phone'`, string(request.TenantID), string(user)); err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.ReadMFAPasswordPrimary(ctx, out.Challenge.Proof, continuation, flow, request.Caller); err == nil {
				t.Fatal("changed current phone renewed original signed authority")
			}
		})
	})
}

func testPhoneMFAChallengeConfig(t *testing.T, c SigninConfig) MFAChallengeConfig {
	t.Helper()
	key := bytes.Repeat([]byte{188}, 32)
	signer, err := capability.NewHMACSHA256Signer("phone-mfa-child", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "phone-mfa-child", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	return MFAChallengeConfig{Lifetime: 2 * time.Minute, MaxAttempts: 3, IssuerURL: "https://identity.test", Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: c.Profile.Audience, CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {189}}, PreparationTimeout: time.Second}, Custody: issuerpg.IssuancePreparationConfig{Deployment: "phone-mfa-test", ActiveEnvelopeKey: "phone-mfa-child", EnvelopeKeys: map[string][]byte{"phone-mfa-child": bytes.Repeat([]byte{190}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "phone-mfa-child", HMAC: key}}, Clock: time.Now}}
}

var _ migrations.Source = PhoneMFASigninMigrationSource{}
