package postgres

import (
	"strconv"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// Only successful primary recipient/credential admission can create this
// invocation-bound selection. A public plan's target is never its substitute.
type resetRecipientAdmission struct {
	owner      FeatureExecutionContributor
	recipient  RecipientRecord
	credential CredentialAdmission
}

func resetIssuanceSubject(s *workState, p CommandPlan, payload capability.Payload) (identity.UserID, error) {
	if s == nil || s.resetRecipient == nil || !validResetRecipientIssuance(s.binding, p) || p.CapabilityIssuance.ResetRecipientUserID == "" || !sameParticipant(s.featureInvocation, s.resetRecipient.owner) {
		return "", invalidWork()
	}
	a := s.resetRecipient
	r, c := a.recipient, a.credential
	if r.Suppressed || r.Query.Eligibility != RecipientVerified || r.Query.Kind != identity.IdentifierEmail || c.Credential.Kind != identity.CredentialPassword || c.Credential.Owner != "identity/password" || r.User.ID != p.CapabilityIssuance.ResetRecipientUserID || payload.Subject != string(r.User.ID) || payload.Tenant != string(s.binding.TenantID) || payload.Resource != "identity.password/"+string(c.Credential.ID) || payload.CorrelationID != string(s.binding.CommandID) || payload.Caveats["password.identifier"] != string(r.Identifier.ID) || payload.Caveats["password.identifier-version"] != strconv.FormatUint(r.Identifier.Version, 10) || payload.Caveats["password.credential-version"] != strconv.FormatUint(c.Credential.Version, 10) || payload.Caveats["password.credential-authority-version"] != strconv.FormatUint(c.CredentialAuthorityVersion, 10) || payload.Caveats["password.user-authority-version"] != strconv.FormatUint(c.UserAuthorityVersion, 10) {
		return "", invalidWork()
	}
	return r.User.ID, nil
}
