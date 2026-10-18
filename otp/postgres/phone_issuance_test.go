package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestPhoneEnrollmentIssuerRestoresOriginalSMSWithoutVerifiedRecipient(t *testing.T) {
	codec, draft, spec, bearer, authority := phoneEnrollmentIssuanceFixture(t)
	native, _, _, _ := nativeSessionFixture(t)
	native.Codec = codec
	challenge, _ := draft.Bindings()
	candidate := kernel.PhoneEnrollmentIntent{Change: identity.IdentifierChange{
		TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, ID: identity.IdentifierID(spec.Binding.RecordID),
		Action: identity.IdentifierAttach, Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123",
		NormalizationProfile: "identity.phone.e164-ascii-v1.metadata-v9.0.40", NormalizationVersion: 1,
		ExpectedUserVersion: 9, ExpectedAuthorityVersion: authority.IdentifierAuthorityVersion,
	}}
	fields, err := kernel.PhoneEnrollmentFields(candidate)
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
	config := PhoneEnrollmentIssuerConfig{Store: native.ContributorConfig, Session: *native.Session, Delivery: issuanceDeliveryOwner(t), Policy: challenge.Policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates}
	issuer, err := NewPhoneEnrollmentIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	input := newPhoneEnrollmentSendInput(phoneEnrollmentSendInput{Candidate: candidate, Continuation: challenge.Continuation, Authority: authority, IssuedAt: challenge.IssuedAt, ExpiresAt: challenge.ExpiresAt})
	flow, _ := challenge.Continuation.Bindings()
	originalSession, _ := flow.Authorization.AuthenticatedSession()
	captured, err := issuer.CaptureInput(context.Background(), spec.Binding, candidate, originalSession, challenge.IssuedAt, challenge.ExpiresAt)
	if err != nil || captured.state().Authority != authority || captured.state().Candidate != candidate || captured.state().ExpiresAt.After(challenge.ExpiresAt) {
		t.Fatal("phone input did not conserve actual original session expectations", err)
	}
	wire, err := issuer.Generate(context.Background(), root, input, 1)
	if err != nil || len(wire) == 0 || bytes.Contains(wire, []byte(bearer.Token())) {
		t.Fatal("native phone send failed or retained bearer", err)
	}
	prepared, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal("original SMS could not restore", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].Purpose != "otp-phone-verification" || plan.Intents[0].SubjectID != string(spec.Binding.UserID) || !plan.Intents[0].ExpiresAt.Equal(challenge.ExpiresAt) {
		t.Fatal("SMS changed original phone scope/deadline", err)
	}
	again, err := issuer.Restore(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	againPlan, err := again.Plan()
	if err != nil || !reflect.DeepEqual(plan, againPlan) {
		t.Fatal("restoration regenerated SMS delivery", err)
	}
	confirmation, err := issuer.RestoreEnrollmentConfirmation(context.Background(), root, input, 1, wire)
	if err != nil {
		t.Fatal("original phone enrollment cannot continue", err)
	}
	intent, err := confirmation.Intent()
	if err != nil || intent.Change.ExpectedUserVersion != candidate.Change.ExpectedUserVersion+1 ||
		intent.Change.ExpectedAuthorityVersion != candidate.Change.ExpectedAuthorityVersion+1 || intent.EnrollmentCommandID != spec.Binding.CommandID {
		t.Fatal("phone confirmation adopted a new observation instead of original successor", err)
	}
	verify := spec
	verify.Operation = phoneConfirmationOperation()
	verify.Binding.OperationID, verify.Binding.SchemaID = verify.Operation.OperationID, verify.Operation.SchemaID
	verify.Binding.CommandID = "AgICAgICAgICAgICAgICAg"
	verify.Fields, err = confirmation.Fields()
	if err != nil {
		t.Fatal(err)
	}
	verifyRoot, err := identity.NewFeatureSessionCommand(verify, bearer)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	mapped, attempt, err := confirmation.prepare(context.Background(), verifyRoot, code, 1, 7)
	if err != nil {
		t.Fatal("original phone confirmation failed mapping", err)
	}
	if attempt.Mode != kernel.OTPConsume || attempt.ChallengeID != string(spec.Binding.CommandID) {
		t.Fatal("phone lost original consuming challenge")
	}
	original, err := confirmation.state().store.codec.restoreAuthority(func() identity.FeatureCommandSpec { s, _ := mapped.Feature(); return s }())
	if err != nil || original != authority {
		t.Fatal("confirmation rewrote original session custody", err)
	}
	current, err := confirmation.state().executionAuthority(func() identity.FeatureCommandSpec { s, _ := mapped.Feature(); return s }(), original)
	wantAuthority := authority
	wantAuthority.IdentifierAuthorityVersion++
	if err != nil || current != wantAuthority {
		t.Fatal("confirmation renewed more than enrollment epoch", err)
	}
	for _, mutate := range []func(*AttemptAuthority){
		func(a *AttemptAuthority) { a.Directory.GlobalVersion++ },
		func(a *AttemptAuthority) { a.Directory.TenantVersion++ },
		func(a *AttemptAuthority) { a.UserAuthorityVersion++ },
		func(a *AttemptAuthority) { a.IdentifierAuthorityVersion++ },
		func(a *AttemptAuthority) { a.CredentialAuthorityVersion++ },
		func(a *AttemptAuthority) { a.Credential.Version++ },
		func(a *AttemptAuthority) { a.UserAuthorization.Version++ },
	} {
		changed := original
		mutate(&changed)
		if _, err := confirmation.state().executionAuthority(func() identity.FeatureCommandSpec { s, _ := mapped.Feature(); return s }(), changed); err == nil {
			t.Fatal("confirmation replaced original authority dimensions")
		}
	}
	if confirmation.Contributor() == nil {
		t.Fatal("actual phone continuation lost its OTP participant")
	}
	if version, err := confirmation.FactorVersion(); err != nil || version != 9 {
		t.Fatal("original MFA generation was not retained", err)
	}
	if err := confirmation.Admit(context.Background(), kernel.Work{}, nil, mapped); err == nil {
		t.Fatal("original metadata fabricated current admission")
	}
	if err := confirmation.Check(context.Background(), kernel.Work{}, nil, mapped); err == nil {
		t.Fatal("original metadata fabricated final admission")
	}
	if confirmation.state().store.ValidateOTPAttemptCommand(mapped, attempt) != nil {
		t.Fatal("phone's exact native OTP owner rejects original command")
	}
	if issuer.state().store.ValidateOTPAttemptCommand(mapped, attempt) == nil {
		t.Fatal("ordinary OTP owner admitted unselected phone successor")
	}
	foreignVerify := verify
	foreignVerify.Fields = append([]identity.FeatureField(nil), verify.Fields...)
	foreignVerify.Fields[0].Value.Text += "other"
	foreignRoot, err := identity.NewFeatureSessionCommand(foreignVerify, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := confirmation.prepare(context.Background(), foreignRoot, code, 1, 7); err == nil {
		t.Fatal("foreign phone target retained confirmation authority")
	}
	if err := prepared.Persist(context.Background(), kernel.Work{}, nil, root); err == nil {
		t.Fatal("unowned candidate persisted")
	}
	changed := input.state()
	changed.Candidate.Change.CanonicalValue = "+12025550124"
	if _, err := issuer.Restore(context.Background(), root, newPhoneEnrollmentSendInput(changed), 1, wire); err == nil {
		t.Fatal("SMS destination substituted")
	}
	if _, err := issuer.Restore(context.Background(), root, input, 2, wire); err == nil {
		t.Fatal("generation reset retained SMS")
	}
	changedRoot := spec
	changedRoot.Fields = append(append([]identity.FeatureField(nil), spec.Fields...), identity.FeatureField{Name: "phone.other", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "changed"}})
	foreign, err := identity.NewFeatureSessionCommand(changedRoot, bearer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Restore(context.Background(), foreign, input, 1, wire); err == nil {
		t.Fatal("SMS moved to another original command")
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 1
	if _, err := issuer.Restore(context.Background(), root, input, 1, tampered); err == nil {
		t.Fatal("modified encrypted SMS restored")
	}
	if _, err := issuer.Restore(context.Background(), root, input, 1, wire[:len(wire)/2]); err == nil {
		t.Fatal("truncated encrypted SMS restored")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.Generate(canceled, root, input, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("generation lost cancellation", err)
	}
	if _, err := issuer.Restore(canceled, root, input, 1, wire); !errors.Is(err, context.Canceled) {
		t.Fatal("restoration lost cancellation", err)
	}
	for _, value := range []interface{ MarshalJSON() ([]byte, error) }{config, *issuer, input, prepared} {
		if _, err := value.MarshalJSON(); err == nil {
			t.Fatal("phone custody implicitly exported")
		}
		if got := fmt.Sprintf("%#v", value); !strings.Contains(got, "redacted") {
			t.Fatal("phone custody not redacted")
		}
	}
	for _, value := range []any{*issuer, input, prepared, confirmation} {
		for _, verb := range []string{"%s", "%v", "%#v"} {
			out := fmt.Sprintf(verb, struct{ private any }{value})
			if strings.Contains(out, "+12025550123") || strings.Contains(out, bearer.Token()) {
				t.Fatal("opaque phone custody leaked through an enclosing private diagnostic field")
			}
		}
	}
	old := config
	old.Policy = func() otp.AttemptPolicy {
		_, mfadraft, _, _, _ := mfaEnrollmentIssuanceFixture(t)
		b, _ := mfadraft.Bindings()
		return b.Policy
	}()
	if _, err := NewPhoneEnrollmentIssuer(old); err == nil {
		t.Fatal("MFA-purpose issuer became phone verification")
	}
}

func TestPhoneEnrollmentIssuerZeroDenies(t *testing.T) {
	var issuer PhoneEnrollmentIssuer
	if err := issuer.Initialize(context.Background(), nil); err == nil {
		t.Fatal("zero issuer initialized storage")
	}
	if _, err := issuer.Configuration(); err == nil {
		t.Fatal("zero issuer supplied configuration identity")
	}
	if issuer.DeliveryContributor() != nil {
		t.Fatal("zero issuer supplied delivery owner")
	}
	if _, err := issuer.Generate(context.Background(), identity.Command{}, PhoneEnrollmentSendInput{}, 1); err == nil {
		t.Fatal("zero issuer generated SMS")
	}
	if _, err := issuer.Restore(context.Background(), identity.Command{}, PhoneEnrollmentSendInput{}, 1, nil); err == nil {
		t.Fatal("zero issuer restored SMS")
	}
	if status, err := issuer.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil || status != kernel.RecoveryUnknown {
		t.Fatal("zero issuer established recovery evidence")
	}
	if _, err := (PreparedPhoneEnrollmentSend{}).Plan(); err == nil {
		t.Fatal("zero prepared SMS supplied delivery plan")
	}
	var confirmation PhoneEnrollmentConfirmation
	if _, err := confirmation.Intent(); err == nil {
		t.Fatal("zero confirmation supplied identifier intent")
	}
	if _, err := confirmation.Fields(); err == nil {
		t.Fatal("zero confirmation supplied fields")
	}
	if _, err := confirmation.FactorVersion(); err == nil {
		t.Fatal("zero confirmation supplied factor generation")
	}
	if confirmation.Contributor() != nil {
		t.Fatal("zero confirmation supplied participant")
	}
	if _, _, err := confirmation.Prepare(context.Background(), nil, identity.Command{}, auth.OneTimeCode{}, 7); err == nil {
		t.Fatal("zero confirmation prepared an attempt")
	}
}

// Mapping proves retained issuance custody only, never ownership or permission
// to persist a phone candidate. The actual kernel/native Work supplies those.
func phoneEnrollmentIssuanceFixture(t *testing.T) (*AttemptCodec, otp.Challenge, identity.FeatureCommandSpec, auth.BearerCredential, AttemptAuthority) {
	t.Helper()
	codec, old, spec, bearer, authority := issuanceCustodyFixture(t, true)
	s, _ := old.Bindings()
	b, _ := s.Continuation.Bindings()
	spec.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.send-verification", SchemaID: "identity.phone.send-verification.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.RecordID = spec.Operation.OperationID, spec.Operation.SchemaID, "pending-phone"
	spec.Binding.ActorID = identity.ActorID(spec.Binding.UserID)
	destination, err := otp.NewDestinationInput("+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	b.Scope.Purpose, b.Scope.Channel, b.Scope.Destination = otp.PurposePhoneVerification, otp.ChannelSMS, destination
	b.Scope.TargetID, b.Scope.ChallengeID, b.Scope.AuthorizationBinding = spec.Binding.RecordID, string(spec.Binding.CommandID), [32]byte{}
	continuation, err := otp.NewContinuation(b.Scope, b.Authorization, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePhoneVerification, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
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

func TestPhoneEnrollmentIssuanceConservesSessionSMSPurposeAndTarget(t *testing.T) {
	codec, draft, spec, bearer, authority := phoneEnrollmentIssuanceFixture(t)
	command, err := codec.MapIssuanceSession(context.Background(), draft, spec, bearer, authority)
	if err != nil {
		t.Fatal("closed phone candidate cannot map its original SMS issuance", err)
	}
	actual, _ := command.Feature()
	retained, err := codec.restoreIssuance(actual)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := retained.challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	if retained.recipient != nil || b.Scope.Purpose != otp.PurposePhoneVerification || b.Scope.Channel != otp.ChannelSMS || b.Scope.Destination.Value() != "+12025550123" || b.Scope.TargetID != "pending-phone" || b.Scope.ChallengeID != string(spec.Binding.CommandID) {
		t.Fatal("candidate mapping fabricated recipient or changed challenge binding")
	}
	if _, has := command.OneTimeCode(); has {
		t.Fatal("issuance retained a submitted code")
	}
	if _, has := command.PreAuthCookie(); has {
		t.Fatal("authenticated enrollment invented public pre-auth")
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other-phone" },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other-user" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/mfa" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "phone-other"
			s.Binding.SchemaID = "phone-other"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.phone.verify"
			s.Binding.OperationID = "identity.phone.verify"
		},
	} {
		foreign := spec
		mutate(&foreign)
		if _, err := codec.MapIssuanceSession(context.Background(), draft, foreign, bearer, authority); err == nil {
			t.Fatal("foreign phone operation/actor/target mapped enrollment issuance")
		}
	}
	if _, err := codec.MapIssuancePreAuth(context.Background(), draft, spec, bearer, authority); err == nil {
		t.Fatal("public preauth substituted for original enrollment session")
	}
}
