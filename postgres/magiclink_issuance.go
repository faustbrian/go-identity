package postgres

import (
	"context"
	"encoding/hex"
	"strconv"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// Selection exists only after this invocation's locked primary admission.
type magicLinkRecipientAdmission struct {
	owner       FeatureExecutionContributor
	recipient   RecipientRecord
	prospective *MagicLinkRegistrationIntent
}

// RequireMagicLinkRecipient fences the original verified email recipient only
// during the native anonymous magic-link request invocation. User, identifier,
// verification and independent security versions must remain unchanged; primary
// share locks persist until the sole coordinator ends Work. Missing, blocked,
// stale or unverified recipients deny and poison Work. It never changes the
// original anonymous command, signs a link, authenticates a user or issues a
// session. Risk, original-flow intent and current factor policy remain mandatory
// workflow checks. The handle is serial-use and must not escape its invocation.
func (w Work) RequireMagicLinkRecipient(ctx context.Context, p FeatureExecutionContributor, expected RecipientRecord) error {
	if w.state == nil {
		return invalidWork()
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	b, f, _, err := w.FeatureScope(p)
	if err != nil || !magicLinkRequestOperation(f.Operation) || f.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || expected.Query.Kind != identity.IdentifierEmail || expected.Query.Eligibility != RecipientVerified {
		return w.fail(ctx, invalidWork())
	}
	if err := w.RequireRecipient(ctx, p, expected); err != nil {
		return err
	}
	w.state.magicLinkRecipient = &magicLinkRecipientAdmission{owner: p, recipient: expected}
	return nil
}

func magicLinkIssuanceSubject(s *workState, p CommandPlan, payload capability.Payload) (identity.UserID, error) {
	if s == nil || s.magicLinkRecipient == nil || p.CapabilityIssuance == nil || !validMagicLinkRecipientIssuance(s.binding, p) || p.CapabilityIssuance.MagicLinkRecipientUserID == "" || !sameParticipant(s.featureInvocation, s.magicLinkRecipient.owner) {
		return "", invalidWork()
	}
	if intent := s.magicLinkRecipient.prospective; intent != nil {
		digest, err := MagicLinkRegistrationDigest(*intent)
		user := intent.Creation.Binding.UserID
		if err != nil || user != p.CapabilityIssuance.MagicLinkRecipientUserID || payload.Subject != string(user) || payload.Tenant != string(s.binding.TenantID) || payload.Resource != "identity.magiclink/"+string(intent.Identifier.ID) || payload.CorrelationID != string(s.binding.CommandID) || payload.Caveats["magiclink.prospective"] != "1" || payload.Caveats["magiclink.intent"] != "signup-if-allowed" || payload.Caveats["magiclink.creation-digest"] != hex.EncodeToString(digest[:]) || payload.Caveats["magiclink.email-policy-version"] != strconv.FormatUint(intent.EmailPossessionPolicyVersion, 10) || payload.Caveats["magiclink.identifier"] != string(intent.Identifier.ID) || payload.Caveats["magiclink.canonical-email"] != intent.Identifier.CanonicalValue {
			return "", invalidWork()
		}
		for _, field := range []string{"magiclink.identifier-version", "magiclink.verification-version", "magiclink.identifier-authority-version", "magiclink.user-authority-version", "magiclink.credential-authority-version"} {
			if payload.Caveats[field] != "1" {
				return "", invalidWork()
			}
		}
		return user, nil
	}
	if _, exists := payload.Caveats["magiclink.prospective"]; exists {
		return "", invalidWork()
	}
	r := s.magicLinkRecipient.recipient
	if r.Validate() != nil || r.Suppressed || r.Query.TenantID != s.binding.TenantID || r.Query.Eligibility != RecipientVerified || r.Query.Kind != identity.IdentifierEmail || r.User.ID != p.CapabilityIssuance.MagicLinkRecipientUserID || payload.Subject != string(r.User.ID) || payload.Tenant != string(s.binding.TenantID) || payload.Resource != "identity.magiclink/"+string(r.Identifier.ID) || payload.CorrelationID != string(s.binding.CommandID) || payload.Caveats["magiclink.identifier"] != string(r.Identifier.ID) || payload.Caveats["magiclink.identifier-version"] != strconv.FormatUint(r.Identifier.Version, 10) || payload.Caveats["magiclink.verification-version"] != strconv.FormatUint(r.Verification.Version, 10) || payload.Caveats["magiclink.identifier-authority-version"] != strconv.FormatUint(r.IdentifierAuthorityVersion, 10) || payload.Caveats["magiclink.user-authority-version"] != strconv.FormatUint(r.UserAuthorityVersion, 10) || payload.Caveats["magiclink.credential-authority-version"] != strconv.FormatUint(r.CredentialAuthorityVersion, 10) || payload.Caveats["magiclink.canonical-email"] != r.Query.CanonicalValue {
		return "", invalidWork()
	}
	return r.User.ID, nil
}
