package postgres

import (
	"crypto/subtle"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLIDPConfirmationPurpose = "identity.sso.saml-idp-init"

// SSOSAMLIDPConfirmationOperation identifies confirmation of a pending,
// unsolicited SAML response for a resolved linked user. It has no SP start,
// request ID or anonymous flow. The record is the pending confirmation, not
// the SAML subject or a browser-provided account. This descriptor grants no
// authority and does not make the operation available to HTTP callers.
func SSOSAMLIDPConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/saml", OperationID: ssoSAMLIDPConfirmationPurpose, SchemaID: "sso-enterprise-saml-idp-init-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

func ssoSAMLIDPConfirmationDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.saml-idp-confirmation", Version: 1}
}

func ssoSAMLIDPConfirmationClaim(q claimRequest) bool {
	return q.feature != nil && q.purpose == ssoSAMLIDPConfirmationPurpose && *q.feature == SSOSAMLIDPConfirmationOperation()
}

func validSSOSAMLIDPConfirmationBinding(b identity.CommandBinding) bool {
	return b.ActorKind == authorization.SubjectServiceAccount && b.ValidateFor(SSOSAMLIDPConfirmationOperation()) == nil
}

func sameSSOSAMLIDPConfirmationCustody(original, restored identity.Command) bool {
	a, b, before := original.SAMLIDPConfirmationCustody()
	c, d, after := restored.SAMLIDPConfirmationCustody()
	return before && after && (subtle.ConstantTimeCompare([]byte(a.Token()), []byte(c.Token()))&
		subtle.ConstantTimeCompare([]byte(b.Token()), []byte(d.Token()))) == 1
}

func encodeSSOSAMLIDPConfirmationCustody(c identity.Command, key [32]byte, payload map[string][]byte) error {
	browser, form, present := c.SAMLIDPConfirmationCustody()
	if !present {
		return codecError()
	}
	// Each submitted value has its own fingerprint domain, separate from
	// pre-auth and ordinary bearer use. The safe collision scope omits both.
	for _, input := range [...]struct{ member, label, value string }{
		{"saml_idp_browser", "saml-idp-confirmation-browser", browser.Token()},
		{"saml_idp_form", "saml-idp-confirmation-form", form.Token()},
	} {
		secret := []byte(input.value)
		digest, err := commandSecret(key, input.label, secret, 43)
		clear(secret)
		if err != nil {
			return err
		}
		payload[input.member] = cborBytes(digest)
	}
	return nil
}
