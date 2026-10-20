//go:build integration

package passwordpostgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Authority selection is not a reset or permission to send. Start with actual
// registration, verified phone and independently confirmed TOTP; the later
// request Work must fence these originals and consume real risk evidence.
func TestNativePhonePasswordRecoverySource(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false)
}

func TestNativePhonePasswordRecoveryRequestRollback(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, true)
}

func TestNativePhonePasswordRecoveryKeyedRequest(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false, phoneResetKeyedProfile)
}

func TestNativePhonePasswordRecoveryComplete(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false, phoneResetCompleteProfile)
}

func TestNativePhonePasswordRecoveryCompleteRollback(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false, phoneResetRollbackProfile)
}

func TestNativePhonePasswordRecoveryCompleteWrongSMS(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false, phoneResetWrongSMSProfile)
}

func TestNativePhonePasswordRecoveryCompleteWrongTOTP(t *testing.T) {
	testNativePhonePasswordRecoveryRequest(t, false, phoneResetWrongTOTPProfile)
}

type nativePhoneResetProfile uint8

const (
	phoneResetSourceProfile nativePhoneResetProfile = iota
	phoneResetKeyedProfile
	phoneResetCompleteProfile
	phoneResetRollbackProfile
	phoneResetWrongSMSProfile
	phoneResetWrongTOTPProfile
)

func testNativePhonePasswordRecoveryRequest(t *testing.T, rollback bool, profiles ...nativePhoneResetProfile) {
	profile := phoneResetSourceProfile
	if len(profiles) != 0 {
		profile = profiles[0]
	}
	testNativeSigninPhaseIntegration(t, "phone password recovery source", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, numbers *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			factor, secret := testNativeEnrolledPhoneTOTP(t, ctx, pool, config, registration, user, keys)
			defer clear(secret)
			number, err := numbers.Canonicalize(ctx, "+12025550123")
			if err != nil {
				t.Fatal(err)
			}
			target, err := phone.PasswordResetIdentifierBinding(number, registration.TenantID, config.IdentifierKey)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := identity.NewPreAuthTransactionID()
			command, _ := identity.NewCommandID()
			issuance, _ := identity.NewCommandID()
			at := time.Now().UTC().Truncate(time.Microsecond)
			binding := session.PreAuthBinding{ID: id, Intent: session.PreAuthIntent{TenantID: registration.TenantID, Purpose: session.PreAuthPhonePasswordRecovery, Action: "identity.phone.password-reset-request", Origin: "https://identity.test", CallbackURL: "https://identity.test/reset", Nonce: [32]byte{211}, PolicyID: config.PolicyID, PolicyVersion: config.Coordinator.AdmissionPolicy.PolicyVersion, IdentifierBinding: target}, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
			token, err := session.NewToken(32)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := token.PreAuthDigest(config.FlowKeys[0], binding)
			if err != nil {
				t.Fatal(err)
			}
			original, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err = sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, config.Session, original); err != nil {
				t.Fatal(err)
			}
			wire, err := token.Reveal()
			if err != nil {
				t.Fatal(err)
			}
			flow, err := otp.NewPreAuthSendFlow(id, auth.NewBearerCredential(wire))
			if err != nil {
				t.Fatal(err)
			}
			part := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			ref, err := risk.ParseRiskEvidenceRef("re1.1." + part + "." + part)
			if err != nil {
				t.Fatal(err)
			}
			key, _ := identity.NewIdempotencyKey([]byte("phone-recovery-source"))
			caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(registration.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: signinTestActor}, Action: "identity.phone.password-reset-request", Resource: authorization.Resource{Type: "identity.user"}}}
			r := phone.PasswordResetRequestRequestSpec{TenantID: registration.TenantID, CommandID: command, Number: number, Flow: flow, RiskEvidence: ref, RiskIssuanceCommandID: issuance, IdempotencyKey: key, Caller: caller, Origin: binding.Intent.Origin, Network: "192.0.2.1", Device: "recovery-browser"}
			config.Origins, config.CallbackURLs = []string{binding.Intent.Origin}, []string{binding.Intent.CallbackURL}
			source, err := newPhonePasswordRecoverySource(pool, config, numbers)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := source.prepare(ctx, r)
			if err != nil {
				t.Fatal("actual recovery authority cannot be selected", err)
			}
			metadata, err := selected.factor.Metadata()
			retained, e := selected.flow.Bindings()
			if err != nil || e != nil || metadata.FactorID != string(factor) || selected.recipient.User.ID != user || selected.credential.Credential.UserID != user || retained.Binding.ID != id || retained.Cookie != digest {
				t.Fatal("selection lost original account/browser/factor", err, e)
			}
			testPhonePasswordRecoveryRisk(t, ctx, pool, config, selected, r, c, keys, rollback, profile >= phoneResetKeyedProfile, numbers, profile, secret)
			for name, change := range map[string]func(*phone.PasswordResetRequestRequestSpec){
				"cookie": func(r *phone.PasswordResetRequestRequestSpec) {
					r.Flow, _ = otp.NewPreAuthSendFlow(id, auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
				},
				"number": func(r *phone.PasswordResetRequestRequestSpec) {
					r.Number, _ = numbers.Canonicalize(ctx, "+12025550124")
				},
				"origin": func(r *phone.PasswordResetRequestRequestSpec) { r.Origin = "https://foreign.test" },
			} {
				t.Run(name, func(t *testing.T) {
					candidate := r
					change(&candidate)
					if _, err := source.prepare(ctx, candidate); err == nil {
						t.Fatal("foreign recovery scope admitted")
					}
				})
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user)); err != nil {
				t.Fatal(err)
			}
			if _, err := source.prepare(ctx, r); err == nil {
				t.Fatal("disabled password admitted for phone recovery")
			}
		})
	})
}
