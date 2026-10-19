package postgres

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This is a custody/generation test, not a live session or phone-change consumer.
// Actual protected use must fence the old recipient inside the native Work.
func TestPhoneChangeIssuerKeepsOldTargetDistinctFromNewSMS(t *testing.T) {
	codec, draft, spec, bearer, authority := phoneEnrollmentIssuanceFixture(t)
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = codec
	challenge, _ := draft.Bindings()
	spec.Operation.SchemaID = "identity.phone.send-verification.change.native-v1"
	spec.Binding.SchemaID = spec.Operation.SchemaID
	change := kernel.PhoneChangeIntent{Change: identity.IdentifierChange{
		TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, ID: identity.IdentifierID(spec.Binding.RecordID),
		Action: identity.IdentifierReplaceVerifiedPhone, Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123",
		NormalizationProfile: "identity.phone.e164-ascii-v1.metadata-v9.0.40", NormalizationVersion: 1,
		ExpectedUserVersion: 9, ExpectedAuthorityVersion: authority.IdentifierAuthorityVersion,
		ExpectedIdentifierVersion: 2, ExpectedVerificationVersion: 2},
		PreviousNumber: "+12025550124", PreviousNormalizationProfile: "identity.phone.e164-ascii-v1.metadata-v9.0.40",
		PreviousNormalizationVersion: 1, SendCommandID: spec.Binding.CommandID, Reason: "user-request"}
	// Sending creates a challenge, not a new version of the unchanged old
	// identifier. The command's audit/lifecycle aggregate is that challenge;
	// the independently retained target stays the old identifier.
	spec.Binding.RecordID = string(spec.Binding.CommandID)
	previous := kernel.RecipientRecord{
		Query: kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID,
			Kind: identity.IdentifierPhone, CanonicalValue: change.PreviousNumber, Eligibility: kernel.RecipientVerified,
			NormalizationProfile: change.PreviousNormalizationProfile, NormalizationVersion: 1},
		User: identity.User{ID: spec.Binding.UserID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 9},
		Identifier: identity.Identifier{ID: change.Change.ID, UserID: spec.Binding.UserID, Kind: identity.IdentifierPhone,
			CanonicalValue: change.PreviousNumber, Verified: true, Primary: true, Version: 2,
			NormalizationProfile: change.PreviousNormalizationProfile, NormalizationVersion: 1},
		Verification: identity.Verification{IdentifierID: change.Change.ID, State: identity.VerificationVerified,
			VerifiedAt: challenge.IssuedAt, Version: 2},
		UserAuthorityVersion: authority.UserAuthorityVersion, IdentifierAuthorityVersion: authority.IdentifierAuthorityVersion,
		CredentialAuthorityVersion: authority.CredentialAuthorityVersion, ObservedAt: challenge.IssuedAt,
	}
	if previous.Validate() != nil {
		t.Fatal("invalid prior recipient fixture")
	}
	fields, err := kernel.PhoneChangeFields(change)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = append(fields, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 9}})
	root, err := identity.NewFeatureSessionCommand(spec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	templates := preparedSendTemplates("{{.code}}")
	templates[0].Channel, templates[0].Subject = delivery.ChannelSMS, ""
	config := PhoneEnrollmentIssuerConfig{Store: native.ContributorConfig, Session: *native.Session, Delivery: issuanceDeliveryOwner(t),
		Policy: challenge.Policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates}
	issuer, err := NewPhoneChangeIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := challenge.Continuation.Bindings()
	original, _ := flow.Authorization.AuthenticatedSession()
	input, err := issuer.CaptureInput(context.Background(), spec.Binding, change, previous, original, challenge.IssuedAt, challenge.ExpiresAt)
	if err != nil {
		t.Fatal("new-number request failed before generation", err)
	}
	wrongAggregate := spec.Binding
	wrongAggregate.RecordID = string(change.Change.ID)
	if _, err := issuer.CaptureInput(context.Background(), wrongAggregate, change, previous, original, challenge.IssuedAt, challenge.ExpiresAt); err == nil {
		t.Fatal("new challenge was attributed to an unchanged identifier")
	}
	wire, err := issuer.Generate(context.Background(), root, input, 1)
	if err != nil {
		t.Fatal("new-number SMS generation failed", err)
	}
	prepared, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal("original replacement SMS failed restoration", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].Purpose != "otp-phone-verification" ||
		!plan.Intents[0].ExpiresAt.Equal(challenge.ExpiresAt) {
		t.Fatal("replacement SMS changed purpose/deadline", err)
	}
	retained := prepared.state().state()
	custody, _, err := issuer.state().state().store.authenticateIssuance(context.Background(), retained.generated)
	if err != nil || custody.recipient != nil {
		t.Fatal("old recipient was incorrectly used as new SMS destination", err)
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := issued.Continuation.Bindings()
	if err != nil || continuation.Scope.Destination.Value() != change.Change.CanonicalValue ||
		continuation.Scope.TargetID != string(change.Change.ID) || continuation.Scope.ChallengeID != string(spec.Binding.CommandID) ||
		*retained.previous != previous || retained.candidate != (kernel.PhoneEnrollmentIntent{}) {
		t.Fatal("replacement retargeted the old identifier or lost original SMS scope", err)
	}
	again, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	againPlan, err := again.Plan()
	if err != nil || !reflect.DeepEqual(plan, againPlan) {
		t.Fatal("replacement restore regenerated delivery", err)
	}
	alteredPrevious := previous
	alteredPrevious.Verification.VerifiedAt = alteredPrevious.Verification.VerifiedAt.Add(-time.Microsecond)
	altered, err := issuer.CaptureInput(context.Background(), spec.Binding, change, alteredPrevious, original, challenge.IssuedAt, challenge.ExpiresAt)
	if err != nil {
		t.Fatal("valid-but-different original snapshot fixture rejected before restore", err)
	}
	if _, err := issuer.Restore(context.Background(), root, altered, 1, wire); err == nil {
		t.Fatal("restoration reinterpreted the original old-recipient snapshot")
	}
	if _, err := issuer.Restore(context.Background(), root, input, 2, wire); err == nil {
		t.Fatal("restoration changed acknowledged generation")
	}
	foreignSpec := spec
	foreignSpec.Operation = phoneEnrollmentSendOperation()
	foreignSpec.Binding.SchemaID = foreignSpec.Operation.SchemaID
	foreign, err := identity.NewFeatureSessionCommand(foreignSpec, bearer)
	if err != nil {
		t.Fatal("valid foreign-profile fixture failed construction", err)
	}
	if _, err := issuer.Generate(context.Background(), foreign, input, 1); err == nil {
		t.Fatal("ordinary enrollment schema admitted replacement issuance")
	}
	for name, alter := range map[string]func(*kernel.RecipientRecord){
		"new-number-not-old": func(r *kernel.RecipientRecord) {
			r.Query.CanonicalValue, r.Identifier.CanonicalValue = change.Change.CanonicalValue, change.Change.CanonicalValue
		},
		"foreign-user":        func(r *kernel.RecipientRecord) { r.User.ID = "foreign" },
		"unverified":          func(r *kernel.RecipientRecord) { r.Identifier.Verified = false },
		"different-version":   func(r *kernel.RecipientRecord) { r.Identifier.Version++ },
		"different-authority": func(r *kernel.RecipientRecord) { r.IdentifierAuthorityVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := previous
			alter(&other)
			if _, err := issuer.CaptureInput(context.Background(), spec.Binding, change, other, original, challenge.IssuedAt, challenge.ExpiresAt); err == nil {
				t.Fatal("changed predecessor entered original replacement input")
			}
		})
	}
	if err := prepared.Persist(context.Background(), kernel.Work{}, nil, root); err == nil {
		t.Fatal("generation custody fabricated current native admission")
	}
	confirmation, err := issuer.RestoreChangeConfirmation(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal("replacement cannot restore its consuming continuation", err)
	}
	intent, err := confirmation.Intent()
	if err != nil || intent != change {
		t.Fatal("sending SMS advanced the original predecessor", err)
	}
	update := spec
	update.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.update",
		SchemaID: "identity.phone.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	update.Binding.OperationID, update.Binding.SchemaID, update.Binding.CommandID = update.Operation.OperationID, update.Operation.SchemaID, "AgICAgICAgICAgICAgICAg"
	update.Binding.RecordID = string(change.Change.ID)
	update.Fields, err = confirmation.Fields()
	if err != nil {
		t.Fatal(err)
	}
	// Native proof fields have a distinct owner. This mapping test checks their
	// coexistence, not their authenticity; real proof admission belongs to the
	// password-native workflow and must precede OTP metering in its Work.
	sessionFields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	update.Fields = append(update.Fields, sessionFields...)
	update.Fields = append(update.Fields, identity.FeatureField{Name: "password.action-primary.fixture", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	// Only these exact names belong to the independently validated native
	// counter participant. OTP conserves their command envelope, not allowance.
	update.Fields = append(update.Fields,
		identity.FeatureField{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "192.0.2.10"}},
		identity.FeatureField{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-session"}},
		identity.FeatureField{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: challenge.IssuedAt}},
		identity.FeatureField{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 0, 0, 1}}})
	updateRoot, err := identity.NewFeatureSessionCommand(update, bearer)
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	mapped, attempt, err := confirmation.enrollment().prepare(context.Background(), updateRoot, code, 1, 7)
	if err != nil || attempt.ChallengeID != string(spec.Binding.CommandID) || attempt.Mode != kernel.OTPConsume {
		t.Fatal("replacement lost original consuming OTP", err)
	}
	owner := confirmation.Contributor()
	if owner == nil || owner.ValidateOTPAttemptCommand(mapped, attempt) != nil {
		t.Fatal("original replacement continuation rejected its actual OTP owner")
	}
	if issuer.state().state().store.ValidateOTPAttemptCommand(mapped, attempt) == nil {
		t.Fatal("ordinary unselected OTP owner admitted replacement")
	}
	aliased := update
	aliased.Fields = append(slices.Clone(update.Fields), identity.FeatureField{Name: "counter.other", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unowned"}})
	aliasedRoot, err := identity.NewFeatureSessionCommand(aliased, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = confirmation.enrollment().prepare(context.Background(), aliasedRoot, code, 1, 7); err == nil {
		t.Fatal("unowned counter field entered consuming OTP")
	}
	mappedSpec, _ := mapped.Feature()
	restored, originalAttempt, err := confirmation.RestorePrepared(context.Background(), updateRoot, code, mappedSpec)
	restoredSpec, restoredOK := restored.Feature()
	if err != nil || !restoredOK || !reflect.DeepEqual(restoredSpec, mappedSpec) || originalAttempt != attempt {
		t.Fatal("keyed replacement did not restore its original attempt", err)
	}
	otherCode, err := auth.NewOneTimeCode("654321")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := confirmation.RestorePrepared(context.Background(), updateRoot, otherCode, mappedSpec); err == nil {
		t.Fatal("restored replacement accepted a changed submitted code")
	}
	changedSpec := mappedSpec
	changedSpec.Binding.CommandID = "AwMDAwMDAwMDAwMDAwMDAw"
	if _, _, err := confirmation.RestorePrepared(context.Background(), updateRoot, code, changedSpec); err == nil {
		t.Fatal("restored replacement accepted foreign command custody")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, _, err := confirmation.RestorePrepared(canceled, updateRoot, code, mappedSpec); err == nil {
		t.Fatal("restored replacement ignored cancellation")
	}
	actual, err := confirmation.enrollment().state().executionAuthority(mappedSpec, authority)
	if err != nil || actual != authority {
		t.Fatal("replacement readopted an authority epoch during send", err)
	}
	if err := confirmation.Admit(context.Background(), kernel.Work{}, nil, mapped); err == nil {
		t.Fatal("continuation fabricated live proof/session admission")
	}
}
