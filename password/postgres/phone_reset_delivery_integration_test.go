//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Actual verified phone, current password and confirmed independent factor
// precede canonical bearer preparation. This proves original encrypted output,
// not risk admission, protected persistence, SMS dispatch or the full reset.
func TestNativePhoneResetCanonicalGrantDelivery(t *testing.T) {
	testNativeSigninPhaseIntegration(t, "phone reset canonical delivery", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
		testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, session.CredentialBearer, "normal", func(config SigninConfig, policy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID) {
			factor, secret := testNativeEnrolledPhoneTOTP(t, ctx, pool, config, registration, user, keys)
			defer clear(secret)
			directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: registration.TenantID, Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123", Eligibility: kernel.RecipientVerified})
			if err != nil || recipient.Suppressed {
				t.Fatal("actual verified phone", err)
			}
			repository, err := NewRepository(pool, config.Repository)
			if err != nil {
				t.Fatal(err)
			}
			material, err := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: registration.TenantID, SubjectID: user})
			if err != nil {
				t.Fatal(err)
			}
			reader, err := mfapg.NewTOTPFactorReader(pool, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := reader.ReadForPhoneRecovery(ctx, registration.TenantID, user, string(factor))
			if err != nil {
				t.Fatal(err)
			}
			metadata, _ := snapshot.Metadata()
			id, _ := identity.NewCommandID()
			flow, _ := identity.NewPreAuthTransactionID()
			op := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			b := identity.CommandBinding{CommandID: id, TenantID: registration.TenantID, UserID: user, RecordID: string(id), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: config.PolicyID, PolicyVersion: 3, CorrelationID: string(id)}
			now := time.Now().UTC().Truncate(time.Second)
			authority := material.Authority()
			original := password.ResetGrantSpec{TenantID: b.TenantID, UserID: user, CredentialID: authority.Credential.ID, CredentialVersion: authority.Credential.Version, CredentialAuthorityVersion: recipient.CredentialAuthorityVersion, UserAuthorityVersion: recipient.UserAuthorityVersion, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, FactorVersion: metadata.FactorAuthorityVersion, OriginCommandID: id, RecoveryPath: auth.RecoveryPathPhone, CallbackURL: "https://identity.test/reset", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Phone: password.PhoneResetBinding{PreAuthTransaction: string(flow), OTPChallengeID: string(id), AttemptID: id, NumberDigest: [32]byte{201}, NumberKeyVersion: 1, VerificationVersion: recipient.Verification.Version, FactorID: string(factor), FactorVersion: metadata.EnrollmentVersion, RiskPolicyVersion: 3}}
			profile, err := password.NewPhoneResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: config.Profile.Audience, MaximumLifetime: time.Minute, Callbacks: []string{original.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {202}}})
			if err != nil {
				t.Fatal(err)
			}
			child := testPhoneMFAChallengeConfig(t, config)
			issuer, err := issuerpg.NewIssuer(child.Issuer)
			if err != nil {
				t.Fatal(err)
			}
			codec, err := issuerpg.NewIssuancePreparationCodec(issuer, child.Custody)
			if err != nil {
				t.Fatal(err)
			}
			crypto, err := envelope.NewService(keys)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "phone-reset-test", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {203}}, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "sms", PolicyVersion: 1}}}, crypto)
			if err != nil {
				t.Fatal(err)
			}
			renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "phone-reset-link", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096}})
			if err != nil {
				t.Fatal(err)
			}
			preparation := resetRequestDeliveryPreparation{issuer: issuer, codec: codec, profile: profile, owner: owner, renderer: renderer, resolver: child.Issuer.Crypto.Resolver.(*capability.KeySet), endpoint: "https://identity.test/reset", template: "phone-reset-link", templateVersion: 1, providerVersion: 2, locales: []string{"en"}, scopeKey: [32]byte{204}, timeout: time.Second}
			got, err := repository.generatePhoneResetRequestDelivery(ctx, b, original, recipient, 1, preparation)
			if err != nil {
				t.Fatal("canonical phone reset cannot enter original encrypted SMS", err)
			}
			defer clear(got.issuanceWire)
			defer clear(got.deliveryWire)
			issue, err := got.issuance.Plan()
			if err != nil || len(issue.Grants) != 1 || issue.ResetRecipientUserID != "" || issue.Grants[0].Purpose != "identity.phone.password-reset-complete" || !issue.Grants[0].ExpiresAt.Equal(original.ExpiresAt) {
				t.Fatal("canonical grant changed owner, purpose or expiry", err)
			}
			message, err := got.delivery.Plan()
			if err != nil || len(message.Intents) != 1 || message.Intents[0].EffectIndex != 1 || message.Intents[0].SubjectID != string(user) || !message.Intents[0].ExpiresAt.Equal(original.ExpiresAt) {
				t.Fatal("reset link overwrote SMS code intent or renewed expiry", err)
			}
			restored, err := codec.RestorePreparation(ctx, b, 1, issue, got.issuanceWire)
			if err != nil {
				t.Fatal("original canonical grant restoration", err)
			}
			if restored.TransferForDelivery(ctx, 0, func(context.Context, []byte) error { t.Error("restored canonical bearer disclosed twice"); return nil }) == nil {
				t.Fatal("restored grant became revealable")
			}
			mail, err := owner.RestorePreparation(ctx, b, 1, got.deliveryWire)
			again, pe := mail.Plan()
			if err != nil || pe != nil || !reflect.DeepEqual(again, message) {
				t.Fatal("encrypted link restoration changed intent", err)
			}
			if bytes.Contains(got.deliveryWire, []byte(recipient.Identifier.CanonicalValue)) {
				t.Fatal("checkpoint contains raw phone")
			}
			for _, change := range []func(*password.ResetGrantSpec){func(s *password.ResetGrantSpec) { s.RecoveryPath = auth.RecoveryPathEmail }, func(s *password.ResetGrantSpec) { s.UserID = "foreign" }, func(s *password.ResetGrantSpec) { s.Phone = password.PhoneResetBinding{} }, func(s *password.ResetGrantSpec) { s.IdentifierVersion++ }} {
				bad := original
				change(&bad)
				if out, e := repository.generatePhoneResetRequestDelivery(ctx, b, bad, recipient, 1, preparation); e == nil || len(out.issuanceWire) != 0 || len(out.deliveryWire) != 0 {
					t.Fatal("foreign phone grant retained delivery custody", e)
				}
			}
		})
	})
}
