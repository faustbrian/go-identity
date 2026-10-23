package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestMFAActiveIssuerRetainsDistinctActionBoundChallenge(t *testing.T) {
	codec, old, spec, bearer, authority := mfaEnrollmentIssuanceFixture(t)
	s, _ := old.Bindings()
	b, _ := s.Continuation.Bindings()
	spec.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-step-up-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.SchemaID = spec.Operation.SchemaID
	spec.Fields = []identity.FeatureField{{Name: "factor.action", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "identity.mfa.factor-update"}}}
	b.Scope.Purpose, b.Scope.AuthorizationBinding = otp.PurposeStepUp, [32]byte{}
	continuation, err := otp.NewContinuation(b.Scope, b.Authorization, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeStepUp, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = codec
	owner := issuanceDeliveryOwner(t)
	config := MFAActiveIssuerConfig{Store: native.ContributorConfig, Session: *native.Session, Delivery: owner,
		Policy: policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: preparedSendTemplates("{{.code}}")}
	issuer, err := NewMFAActiveIssuer(config)
	if err != nil {
		t.Fatal("explicit step-up owner unavailable", err)
	}
	root, err := identity.NewFeatureSessionCommand(spec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Verified: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: s.IssuedAt, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: s.IssuedAt}
	input := MFAEnrollmentSendInput{Continuation: continuation, Authority: authority, Recipient: recipient, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}
	record, err := input.record(policy, spec.Binding)
	if err != nil {
		t.Fatal("step-up purpose cannot bind its actual root", err)
	}
	inputWire, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(inputWire)
	output, err := issuer.GenerateStepUpSend(context.Background(), root, inputWire, 1)
	if err != nil || len(output) == 0 || bytes.Contains(output, []byte(bearer.Token())) {
		t.Fatal("active OTP generation failed or retained submitted bearer", err)
	}
	defer clear(output)
	if prepared, err := issuer.RestoreStepUpSend(t.Context(), root, inputWire, 1, output); err != nil || prepared == nil {
		t.Fatal("same active OTP output cannot restore", err)
	}
	verification, err := issuer.RestoreStepUpVerification(t.Context(), root, inputWire, 1, output)
	if err != nil || verification == nil {
		t.Fatal("original active send cannot supply consuming custody", err)
	}
	verifySpec := spec
	verifySpec.Operation.OperationID, verifySpec.Operation.SchemaID = "identity.mfa.otp-verify", "mfa-otp-step-up"
	verifySpec.Binding.OperationID, verifySpec.Binding.SchemaID = verifySpec.Operation.OperationID, verifySpec.Operation.SchemaID
	verifySpec.Binding.CommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
	verifySpec.Binding.CorrelationID = string(verifySpec.Binding.CommandID)
	verifyRoot, err := identity.NewFeatureSessionCommand(verifySpec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	nativeVerification := verification.(*mfaEnrollmentConfirmation)
	mapped, attempt, err := nativeVerification.prepare(t.Context(), verifyRoot, code, 1, 7)
	if err != nil || attempt.Mode != kernel.OTPConsume || attempt.ChallengeID != string(spec.Binding.CommandID) {
		t.Fatal("active verification lost original consuming challenge", err)
	}
	projected, _ := mapped.Feature()
	if projected.Operation != verifySpec.Operation || projected.Binding != verifySpec.Binding {
		t.Fatal("active verification changed root operation or actor")
	}
	// Pending enrollment and active action are intentionally disjoint profiles.
	config.Policy = s.Policy
	if old, err := NewMFAActiveIssuer(config); err == nil || old != nil {
		t.Fatal("MFA enrollment purpose selected active step-up owner")
	}
	bad := spec
	bad.Fields = []identity.FeatureField{{Name: "factor.action", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "identity.mfa.disable"}}}
	wrong, _ := identity.NewFeatureSessionCommand(bad, bearer)
	if wire, err := issuer.GenerateStepUpSend(t.Context(), wrong, inputWire, 1); err == nil || len(wire) != 0 {
		t.Fatal("active OTP code generated for an unselected action")
	}
}
