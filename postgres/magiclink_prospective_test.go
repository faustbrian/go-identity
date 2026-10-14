package postgres

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/faustbrian/go-capability"
)

func TestMagicLinkProspectiveIssuanceBindsCreationWithoutExistingRecipient(t *testing.T) {
	b, _, plan := magicLinkIssuanceFixture(t)
	intent := magicLinkRegistrationIntentFixture()
	intent.Creation.Binding = b
	intent.Creation.Binding.OperationID, intent.Creation.Binding.AnonymousFlowID, intent.Creation.Binding.UserID, intent.Creation.Binding.SchemaID = "identity.user.create", "", "prospective-user", "fields"
	intent.Identifier.UserID = intent.Creation.Binding.UserID
	digest, err := MagicLinkRegistrationDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan.CapabilityIssuance.MagicLinkRecipientUserID = intent.Creation.Binding.UserID
	phase := &magicLinkIssuancePhase{resetIssuancePhase{operation: plan.Feature.Operation}}
	payload := capability.Payload{Subject: string(intent.Creation.Binding.UserID), Tenant: string(b.TenantID), Resource: "identity.magiclink/" + string(intent.Identifier.ID), CorrelationID: string(b.CommandID), Caveats: map[string]string{
		"magiclink.prospective": "1", "magiclink.intent": "signup-if-allowed", "magiclink.creation-digest": hex.EncodeToString(digest[:]), "magiclink.email-policy-version": strconv.FormatUint(intent.EmailPossessionPolicyVersion, 10),
		"magiclink.identifier": string(intent.Identifier.ID), "magiclink.canonical-email": intent.Identifier.CanonicalValue,
		"magiclink.identifier-version": "1", "magiclink.verification-version": "1", "magiclink.identifier-authority-version": "1", "magiclink.user-authority-version": "1", "magiclink.credential-authority-version": "1",
	}}
	s := &workState{binding: b, featureInvocation: phase, magicLinkRecipient: &magicLinkRecipientAdmission{owner: phase, prospective: &intent}}
	if user, err := magicLinkIssuanceSubject(s, plan, payload); err != nil || user != intent.Creation.Binding.UserID {
		t.Fatal("fenced prospective issuance unavailable", err)
	}
	for _, key := range []string{"magiclink.prospective", "magiclink.intent", "magiclink.creation-digest", "magiclink.email-policy-version", "magiclink.identifier", "magiclink.canonical-email", "magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
		changed := payload
		changed.Caveats = make(map[string]string, len(payload.Caveats))
		for k, v := range payload.Caveats {
			changed.Caveats[k] = v
		}
		changed.Caveats[key] = "foreign"
		if _, err := magicLinkIssuanceSubject(s, plan, changed); err == nil {
			t.Fatal("foreign signed prospective field accepted", key)
		}
	}
	s.featureInvocation = &magicLinkIssuancePhase{}
	if _, err := magicLinkIssuanceSubject(s, plan, payload); err == nil {
		t.Fatal("foreign invocation borrowed prospective custody")
	}
}
