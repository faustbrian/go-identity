package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func mfaEnrollmentIssuanceFixture(t *testing.T) (*AttemptCodec, otp.Challenge, identity.FeatureCommandSpec, auth.BearerCredential, AttemptAuthority) {
	t.Helper()
	codec, old, spec, bearer, authority := issuanceCustodyFixture(t, true)
	s, _ := old.Bindings()
	b, _ := s.Continuation.Bindings()
	spec.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.RecordID = "AwMDAwMDAwMDAwMDAwMDAw"
	spec.Binding.ActorID = identity.ActorID(spec.Binding.UserID)
	b.Scope.Purpose, b.Scope.TargetID, b.Scope.ChallengeID = otp.PurposeMFA, spec.Binding.RecordID, string(spec.Binding.CommandID)
	b.Scope.AuthorizationBinding = [32]byte{}
	continuation, err := otp.NewContinuation(b.Scope, b.Authorization, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	scope, _ := continuation.DigestScope()
	digest, err := codec.verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	s.Continuation, s.Policy, s.Digest = continuation, policy, digest.Storage()
	draft, err := otp.NewChallenge(s)
	if err != nil {
		t.Fatal(err)
	}
	return codec, draft, spec, bearer, authority
}

func TestMFAEnrollmentIssuerRestoresOneOpaqueNativeDelivery(t *testing.T) {
	codec, draft, spec, bearer, authority := mfaEnrollmentIssuanceFixture(t)
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = codec
	s, _ := draft.Bindings()
	c, _ := s.Continuation.Bindings()
	parent := "BAQEBAQEBAQEBAQEBAQEBA"
	spec.Fields = []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: parent}}}
	root, err := identity.NewFeatureSessionCommand(spec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: c.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: spec.Binding.UserID, Kind: identity.IdentifierEmail, CanonicalValue: c.Scope.Destination.Value(), Verified: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: s.IssuedAt, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: s.IssuedAt}
	owner := issuanceDeliveryOwner(t)
	issuer, err := NewMFAEnrollmentIssuer(MFAEnrollmentIssuerConfig{Store: native.ContributorConfig, Session: *native.Session, Delivery: owner,
		Policy: s.Policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: preparedSendTemplates("{{.code}}")})
	if err != nil {
		t.Fatal(err)
	}
	input := MFAEnrollmentSendInput{Continuation: s.Continuation, Authority: authority, Recipient: recipient, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}
	if err := issuer.ValidateConfirmationKey(7); err != nil {
		t.Fatal("actual retained attempt key unavailable", err)
	}
	if err := issuer.ValidateConfirmationKey(99); err == nil {
		t.Fatal("missing confirmation key accepted")
	}
	wire, err := issuer.Generate(context.Background(), root, input, 1)
	if err != nil || len(wire) == 0 || bytes.Contains(wire, []byte(bearer.Token())) {
		t.Fatal("native MFA send generation failed or retained bearer", err)
	}
	prepared, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal("native MFA send checkpoint cannot restore", err)
	}
	record, err := input.record(s.Policy, spec.Binding)
	if err != nil {
		t.Fatal(err)
	}
	inputWire, err := encodeSendRequestRecord(record, spec.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(inputWire)
	confirmation, err := issuer.RestoreEnrollmentConfirmation(context.Background(), root, inputWire, 1, wire)
	if err != nil {
		t.Fatal("original issuance cannot prepare native enrollment confirmation", err)
	}
	verifySpec := spec
	verifySpec.Operation = mfaEnrollmentConfirmationOperation()
	verifySpec.Binding.OperationID, verifySpec.Binding.SchemaID = verifySpec.Operation.OperationID, verifySpec.Operation.SchemaID
	verifySpec.Binding.CommandID = "BQUFBQUFBQUFBQUFBQUFBQ"
	verifySpec.Binding.CorrelationID = string(verifySpec.Binding.CommandID)
	verifySpec.Fields = []identity.FeatureField{{Name: "factor.source-send", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.Binding.CommandID)}}}
	verifyRoot, err := identity.NewFeatureSessionCommand(verifySpec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	nativeConfirmation := confirmation.(*mfaEnrollmentConfirmation)
	consuming, attemptPlan, err := nativeConfirmation.prepare(context.Background(), verifyRoot, code, 1, 7)
	if err != nil || attemptPlan.Mode != kernel.OTPConsume || attemptPlan.ChallengeID != string(spec.Binding.CommandID) || confirmation.Contributor() == nil {
		t.Fatal("MFA confirmation did not retain the real consuming owner/scope", err)
	}
	projected, _ := consuming.Feature()
	if projected.Binding != verifySpec.Binding || projected.Operation != verifySpec.Operation || projected.Fields[0].Name != "factor.source-send" {
		t.Fatal("OTP mapping replaced the native MFA root intent")
	}
	if err := confirmation.Contributor().ValidateOTPAttemptCommand(consuming, attemptPlan); err != nil {
		t.Fatal("prepared confirmation cannot enter native OTP consumption", err)
	}
	restoredAttempt, restoredPlan, err := confirmation.RestorePrepared(context.Background(), verifyRoot, code, projected)
	if err != nil || restoredPlan != attemptPlan {
		t.Fatal("confirmation did not conserve its original retained attempt", err)
	}
	if err := confirmation.Contributor().ValidateOTPAttemptCommand(restoredAttempt, restoredPlan); err != nil {
		t.Fatal("restored original attempt lost code binding", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, _, err := confirmation.RestorePrepared(cancelled, verifyRoot, code, projected); !errors.Is(err, context.Canceled) {
		t.Fatal("retained confirmation restoration lost cancellation", err)
	}
	changedRootSpec := verifySpec
	changedRootSpec.Fields = nil
	changedRoot, _ := identity.NewFeatureSessionCommand(changedRootSpec, bearer)
	if _, _, err := confirmation.RestorePrepared(context.Background(), changedRoot, code, projected); err == nil {
		t.Fatal("retained attempt replaced static MFA root intent")
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "BgYGBgYGBgYGBgYGBgYGBg" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "mfa-otp-verify"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Binding.CommandID = spec.Binding.CommandID
			s.Binding.CorrelationID = string(s.Binding.CommandID)
		},
	} {
		bad := verifySpec
		change(&bad)
		changed, e := identity.NewFeatureSessionCommand(bad, bearer)
		if e == nil {
			if _, _, e = nativeConfirmation.prepare(context.Background(), changed, code, 1, 7); e == nil {
				t.Fatal("confirmation adopted another target/schema/source command")
			}
		}
	}
	if _, _, err := nativeConfirmation.prepare(context.Background(), verifyRoot, code, 1, 99); err == nil {
		t.Fatal("confirmation silently selected another attempt key")
	}
	if _, err := issuer.RestoreEnrollmentConfirmation(context.Background(), root, inputWire, 2, wire); err == nil {
		t.Fatal("confirmation renewed original issuance generation")
	}
	plan, err := prepared.Plan()
	if err != nil || plan.Contributor != owner.Descriptor() || len(plan.Intents) != 1 || plan.Intents[0].SubjectID != string(spec.Binding.UserID) {
		t.Fatal("MFA send lost sole original native delivery", err)
	}
	again, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := again.Plan()
	if second.Intents[0] != plan.Intents[0] {
		t.Fatal("MFA retry replaced challenge or delivery")
	}
	if _, err := issuer.Restore(context.Background(), root, input, 2, wire); err == nil {
		t.Fatal("MFA send renewed generation")
	}
	changed := spec
	changed.Fields = []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "BQUFBQUFBQUFBQUFBQUFBQ"}}}
	substituted, _ := identity.NewFeatureSessionCommand(changed, bearer)
	if _, err := issuer.Restore(context.Background(), substituted, input, 1, wire); err == nil {
		t.Fatal("MFA send adopted another enrollment parent")
	}
	if err := prepared.Persist(context.Background(), kernel.Work{}, nil, root); err == nil {
		t.Fatal("unowned MFA send Work accepted")
	}
}

func TestMFAEnrollmentIssuanceKeepsFactorAndChallengeIdentitiesDistinct(t *testing.T) {
	codec, draft, spec, bearer, authority := mfaEnrollmentIssuanceFixture(t)
	command, err := codec.MapIssuanceSession(context.Background(), draft, spec, bearer, authority)
	if err != nil {
		t.Fatal("OTP owner cannot map exact MFA enrollment issuance", err)
	}
	got, _ := command.Feature()
	restored, err := codec.restoreIssuance(got)
	if err != nil {
		t.Fatal("MFA issuance lost authenticated original custody", err)
	}
	s, _ := restored.challenge.Bindings()
	c, _ := s.Continuation.Bindings()
	if got.Binding != spec.Binding || got.Operation != spec.Operation || c.Scope.ChallengeID != string(spec.Binding.CommandID) || c.Scope.TargetID != spec.Binding.RecordID || c.Scope.Purpose != otp.PurposeMFA {
		t.Fatal("MFA enrollment factor or challenge changed on restoration")
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "unrelated" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "mfa-otp-verify"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = string(s.Binding.CommandID) },
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "BAQEBAQEBAQEBAQEBAQEBA" },
	} {
		bad := spec
		change(&bad)
		if _, err := codec.MapIssuanceSession(context.Background(), draft, bad, bearer, authority); err == nil {
			t.Fatal("unrelated owner, operation or target entered MFA issuance")
		}
	}
}

func TestMFAEnrollmentIssuerConfigurationBindsNativeOwners(t *testing.T) {
	codec, draft, _, _, _ := mfaEnrollmentIssuanceFixture(t)
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = codec
	s, _ := draft.Bindings()
	c := MFAEnrollmentIssuerConfig{Store: native.ContributorConfig, Session: *native.Session, Delivery: issuanceDeliveryOwner(t), Policy: s.Policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: preparedSendTemplates("{{.code}}")}
	owner, err := NewMFAEnrollmentIssuer(c)
	if err != nil {
		t.Fatal(err)
	}
	base, err := owner.Configuration()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*MFAEnrollmentIssuerConfig){
		func(c *MFAEnrollmentIssuerConfig) { c.Store.Schema = "other_otp" },
		func(c *MFAEnrollmentIssuerConfig) { c.Store.LockoutKey = [32]byte{119} },
		func(c *MFAEnrollmentIssuerConfig) { c.Session.FreshnessLimit += time.Minute },
		func(c *MFAEnrollmentIssuerConfig) { c.Session.Store.Schema = "other_sessions" },
		func(c *MFAEnrollmentIssuerConfig) {
			c.Session.RetainedTokenKeys = map[uint32][]byte{1: bytes.Repeat([]byte{118}, 32)}
		},
		func(c *MFAEnrollmentIssuerConfig) {
			profile, checks, _ := c.Policy.Bindings()
			profile.TTL += time.Minute
			p, _ := otp.NewCodeProfile(profile)
			c.Policy, _ = otp.NewAttemptPolicy(p, checks)
		},
	} {
		changed := c
		change(&changed)
		other, err := NewMFAEnrollmentIssuer(changed)
		if err != nil {
			t.Fatal("valid alternate profile rejected", err)
		}
		got, err := other.Configuration()
		if err != nil || got == base {
			t.Fatal("original MFA send configuration silently adopted another native owner", err)
		}
	}
}

func TestMFAEnrollmentConfirmationZeroHasNoContributor(t *testing.T) {
	if (&MFAEnrollmentIssuer{}).ConfirmationContributor() != nil {
		t.Fatal("zero issuer exported a native consuming contributor")
	}
	if (&mfaEnrollmentConfirmation{issuer: &MFAEnrollmentIssuer{}}).Contributor() != nil {
		t.Fatal("zero confirmation exported a native consuming contributor")
	}
}
