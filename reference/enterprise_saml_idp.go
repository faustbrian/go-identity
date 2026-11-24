package reference

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

const samlIDPSessionIssuanceConstraint = "session_issuances.session_issuances_purpose_sso_saml_idp_v1"

type enterpriseSAMLIDPState struct {
	arrival      *ssopg.ProviderSAMLIDPArrivalService
	confirmation *ssopg.ProviderSAMLIDPConfirmationService
}

func composeEnterpriseSAMLIDP(router *ssopg.ProviderRouter, n EnterpriseSAMLConfiguration, h HTTPEnterpriseSAMLConfiguration, custody *ssopg.SAMLLogoutSubjectCustody) (*enterpriseSAMLIDPState, error) {
	selected := n.IDPInitiated
	if !hasSeparateSAMLStateAndConfirmationKeys(n, selected.ConfirmationKeys) {
		return nil, identity.InvalidInputError{Field: "reference_enterprise_saml_idp"}
	}
	admissionConfig := ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: n.Login.TenantID,
		Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: n.Profile, MaximumAge: selected.MaximumAge}},
	}
	var admission *ssopg.ProviderSAMLIDPAdmissionService
	var err error
	if custody == nil {
		admissionConfig.Verify = enterpriseSAMLIDPPOSTVerifier(n.ClockSkew)
		admission, err = ssopg.NewProviderSAMLIDPAdmissionService(router, admissionConfig)
	} else {
		admission, err = ssopg.NewProviderSAMLIDPAdmissionServiceWithLogoutSubject(router, admissionConfig, enterpriseSAMLIDPPOSTLogoutVerifier(n.ClockSkew))
	}
	if err != nil {
		return nil, err
	}
	admission, err = admission.WithLinkedRecipientPolicy(n.Completion.PolicyNamespace)
	if err != nil {
		return nil, err
	}
	arrival, err := ssopg.NewProviderSAMLIDPArrivalService(admission, ssopg.ProviderSAMLIDPArrivalConfig{
		ActorID: n.Login.ActorID, PolicyID: n.Login.PolicyID, PolicyVersion: n.Login.Coordinator.QueryPolicy.PolicyVersion,
		GlobalAuthorityID: n.Login.GlobalAuthorityID, KeyReference: n.Login.KeyReference,
		Coordinator: n.Login.Coordinator, Capability: n.Login.Capability, AuditRetentionPolicyVersion: n.Login.AuditRetentionPolicyVersion,
		CurrentConfirmationKey: selected.CurrentConfirmationKey, ConfirmationKeys: selected.ConfirmationKeys,
	})
	if err != nil {
		return nil, err
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, h.Lifetime)
	if err != nil {
		return nil, err
	}
	confirmation, err := ssopg.NewProviderSAMLIDPConfirmationService(arrival, ssopg.ProviderSAMLIDPConfirmationConfig{
		Audience: n.Completion.Audience, Session: n.Login.Session, Issuer: n.Completion.Issuer, CSRFKey: n.Completion.CSRFKey, Remember: remember,
	})
	if err != nil {
		return nil, err
	}
	if custody != nil {
		confirmation, err = confirmation.WithLogoutSubjectCustody(custody)
		if err != nil {
			return nil, err
		}
	}
	return &enterpriseSAMLIDPState{arrival: arrival, confirmation: confirmation}, nil
}

func hasSeparateSAMLStateAndConfirmationKeys(n EnterpriseSAMLConfiguration, confirmation map[uint32][32]byte) bool {
	for _, key := range confirmation {
		for _, stateKey := range n.Login.StateKeys {
			if key == stateKey {
				return false
			}
		}
		for _, pkceKey := range n.Login.PKCEKeys {
			if key == pkceKey {
				return false
			}
		}
	}
	return true
}

func enterpriseSAMLIDPPOSTVerifier(skew time.Duration) ssopg.SAMLIDPResponseVerifier {
	return func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
		verified, err := verifyEnterpriseSAMLIDPPOST(ctx, input, skew)
		if err != nil {
			return ssopg.SAMLVerifiedResponse{}, err
		}
		evidence, err := verified.Evidence()
		return ssopg.SAMLVerifiedResponse(evidence), err
	}
}

func enterpriseSAMLIDPPOSTLogoutVerifier(skew time.Duration) ssopg.SAMLIDPResponseWithLogoutSubjectVerifier {
	return func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedLoginResponse, error) {
		verified, err := verifyEnterpriseSAMLIDPPOST(ctx, input, skew)
		if err != nil {
			return ssopg.SAMLVerifiedLoginResponse{}, err
		}
		return enterpriseSAMLLoginWithLogoutSubject(verified)
	}
}

func verifyEnterpriseSAMLIDPPOST(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput, skew time.Duration) (saml.VerifiedIDPInitiatedPOSTResponse, error) {
	profile, err := saml.NewIDPInitiatedPOSTResponseProfile(saml.IDPInitiatedPOSTResponseConfig{
		SPEntityID: input.SPEntityID, IdentityProviderEntityID: input.IdentityProviderEntityID, ExternalOrigin: input.ExternalOrigin,
		ProviderID: string(input.ProviderID), SigningCertificates: input.SigningCertificates, MaximumAge: input.MaximumAge, ClockSkew: skew,
	})
	if err != nil {
		return saml.VerifiedIDPInitiatedPOSTResponse{}, err
	}
	return profile.Validate(ctx, saml.IDPInitiatedPOSTResponseInput{SAMLResponse: input.SAMLResponse, Now: input.Now})
}
