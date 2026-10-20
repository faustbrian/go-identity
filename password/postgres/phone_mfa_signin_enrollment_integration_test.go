//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestNativeVerifiedPhoneTOTPEnrollment(t *testing.T) {
	testNativeSigninPhaseIntegration(t, "phone TOTP enrollment", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, _ *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			factor, secret := testNativeEnrolledPhoneTOTP(t, ctx, pool, config, registration, user, keys)
			defer clear(secret)
			if factor == "" || len(secret) != 32 {
				t.Fatal("actual confirmed factor unavailable")
			}
		})
	})
}

// This fixture starts from the genuine phone-enrollment consumer's newly
// registered/verified account. Password signin, fresh target-specific proof,
// encrypted TOTP enrollment, URI revelation and confirmation all use actual
// native owners. The only generated TOTP code is the test authenticator's code.
func testNativeEnrolledPhoneTOTP(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, registration password.SignupRequest, user identity.UserID, keys *keyring.Provider, consumers ...func(*mfapg.TOTPEnrollmentService, mfapg.TOTPEnrollmentConfig, session.Session)) (mfa.FactorID, []byte) {
	t.Helper()
	// The preceding phone enrollment uses ordinary admission. Actual protected
	// TOTP enrollment additionally requires the counter-declaration suffix.
	testPhoneMFAForward(t, ctx, pool, kernel.CounterPreparationMigrationSource{Base: kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 21}, Version: 22}, Version: 23}, 23)
	base := mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}
	recovery := mfapg.RecoveryMigrationSource{Base: base, Version: 4}
	uri := mfapg.URIRevealMigrationSource{Base: recovery, Version: 5}
	activation := mfapg.TOTPActivationMigrationSource{Base: uri, Version: 6}
	history, err := activation.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history[1:] {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("genuine TOTP history", err)
		}
	}
	counters, protected := phoneChangeCounterConfig(t, ctx, pool, config.Risk, time.Second, func(context.Context) error { return nil })
	service, err := NewSigninService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	request, _, _, _ := nativeSigninFlow(t)
	request.TenantID, request.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
	request.Identifier, request.Password, request.Device = "phone-owner@example.test", registration.Password, "phone-totp-enrollment"
	request.PreAuthID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	testPhoneMFASigninBrowser(t, ctx, pool, config, request, [32]byte{})
	signedIn, err := service.Signin(ctx, request)
	if err != nil || signedIn.State != auth.SignInStateAuthenticated {
		t.Fatal("genuine enrollment password signin", err)
	}
	wire, err := signedIn.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	original, err := signedIn.Issuance.Session.Bindings()
	if err != nil || original.UserID != user {
		t.Fatal("enrollment original account", err)
	}
	target := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "phone-totp-enrollment"}
	signing, err := NewReauthenticationSigningKey("phone-totp-reauth", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{181}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, public := signing.public()
	reauth, err := NewReauthenticationService(pool, ReauthenticationConfig{Repository: config.Repository, Verifier: config.Verifier, Session: config.Session, Profile: config.Profile, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}, Risk: config.Risk, Coordinator: config.Coordinator, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{id: public}, Issuer: config.Issuer, Environment: config.Environment, Targets: []ReauthenticationTarget{target}, TTL: time.Minute, IdentifierKey: bytes.Repeat([]byte{182}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(registration.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.mfa.enable", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	proof, err := reauth.Verify(ctx, ReauthenticationRequest{TenantID: registration.TenantID, Session: auth.NewBearerCredential(wire), Password: registration.Password, Target: target, Caller: caller, Network: request.Network, Device: request.Device})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine TOTP action proof", err)
	}
	primary, err := NewMFAEnablePrimarySource(reauth, MFAEnablePrimaryConfig{Audience: target.Audience, MaximumAge: 2 * time.Minute, PrimaryFreshFor: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	primary, err = NewCookieMFAEnablePrimarySource(primary, []session.CSRFKey{config.CSRFKey})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("phone-totp-enrollment", [32]byte{183}, *config.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := mfapg.NewTOTPEnrollmentConfig(requestKeys, [32]byte{184}, [32]byte{185}, 1, "input")
	if err != nil {
		t.Fatal(err)
	}
	enrollment.ConfigurationID, enrollment.PolicyID = "phone-totp-enrollment", "phone-totp-enrollment"
	enrollment.MaximumDuration, enrollment.TTL, enrollment.Primary = 3*time.Second, 5*time.Minute, primary
	enrollment.Profile = mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, AllowedSkewSteps: 1, Issuer: "Phone Test"}
	enrollment.Coordinator, enrollment.Counters, enrollment.Risk = config.Coordinator, counters, protected
	enroller, err := mfapg.NewTOTPEnrollmentService(pool, enrollment, keys)
	if err != nil {
		t.Fatal("actual TOTP enrollment composition", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("phone-native-totp-enrollment"))
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := enroller.Enable(ctx, mfa.EnableRequest{TenantID: registration.TenantID, PrimaryProof: original.Authentication.Proof, Reauthentication: proof.Proof, Session: auth.NewBearerCredential(wire), CSRFToken: signedIn.CSRFToken, IdempotencyKey: key, Caller: caller, Network: request.Network, FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 10}})
	for _, code := range enabled.RecoveryMaterial.Codes {
		code.Destroy()
	}
	if err != nil || enabled.Outcome != identity.CommitOutcomeCommitted || enabled.Enrollment.ID == "" {
		t.Fatal("genuine pending TOTP enrollment", err)
	}
	uriOwner, err := mfapg.NewTOTPURIService(enroller, mfapg.TOTPURIConfig{Primary: primary, AllowedOrigins: []string{request.Origin}})
	if err != nil {
		t.Fatal(err)
	}
	uriCaller := caller.Clone()
	uriCaller.Request.Action = "identity.mfa.totp-uri"
	command, _ := identity.NewCommandID()
	revealed, err := uriOwner.TotpUri(ctx, mfa.TotpUriRequest{TenantID: registration.TenantID, CommandID: command, EnrollmentID: enabled.Enrollment.ID, Session: auth.NewBearerCredential(wire), CSRFToken: signedIn.CSRFToken, Caller: uriCaller, Origin: request.Origin, Network: request.Network})
	if err != nil || revealed.Outcome != identity.CommitOutcomeCommitted || revealed.URI.URI == "" {
		t.Fatal("genuine TOTP URI", err)
	}
	parsed, err := url.Parse(revealed.URI.URI)
	if err != nil {
		t.Fatal("bounded authenticator URI")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	if err != nil || len(secret) != 32 {
		t.Fatal("actual authenticator secret unavailable")
	}
	confirmer, err := mfapg.NewTOTPConfirmationService(enroller, mfapg.TOTPConfirmationConfig{Primary: primary, AllowedOrigins: []string{request.Origin}, ComparisonKey: [32]byte{186}, ComparisonKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	caller.Request.Action = "identity.mfa.totp-verify"
	command, _ = identity.NewCommandID()
	confirmed, err := confirmer.TotpVerify(ctx, mfa.TotpVerifyRequest{TenantID: registration.TenantID, CommandID: command, FactorID: mfa.FactorID(enabled.Enrollment.ID), Code: testPhoneTOTPCode(t, secret, now), Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: auth.NewBearerCredential(wire), CSRFToken: signedIn.CSRFToken}, Caller: caller, Origin: request.Origin, Network: request.Network})
	if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || confirmed.Enrollment.ID != enabled.Enrollment.ID {
		clear(secret)
		t.Fatal("genuine confirmed TOTP", err)
	}
	for _, consume := range consumers {
		consume(enroller, enrollment, signedIn.Issuance.Session)
	}
	return mfa.FactorID(enabled.Enrollment.ID), secret
}

func testPhoneTOTPCode(t *testing.T, secret []byte, now time.Time) auth.OneTimeCode {
	t.Helper()
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, secret)
	_, _ = h.Write(step[:])
	digest := h.Sum(nil)
	defer clear(digest)
	offset := digest[len(digest)-1] & 15
	code, err := auth.NewOneTimeCode(fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func testPhoneMFASigninBrowser(t *testing.T, ctx context.Context, pool *database.Pool, c SigninConfig, request password.SigninRequest, target [32]byte) session.PreAuthTransaction {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	binding := session.PreAuthBinding{ID: request.PreAuthID, Intent: session.PreAuthIntent{TenantID: request.TenantID, Action: string(request.Caller.Request.Action), Origin: request.Origin, CallbackURL: request.CallbackURL, Nonce: [32]byte{187}, Remember: request.Remember, PolicyID: c.PolicyID, PolicyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, IdentifierBinding: target}, IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}
	token, err := session.ParseToken(request.Cookie.Token())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.PreAuthDigest(c.FlowKeys[0], binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, c.Session, flow) != nil {
		t.Fatal("actual original browser", err)
	}
	return flow
}

func testPhoneMFAForward(t *testing.T, ctx context.Context, pool *database.Pool, source migrations.Source, minimum migrations.Version) {
	t.Helper()
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if step.Version() >= minimum {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("selected phone MFA history", err)
			}
		}
	}
}
