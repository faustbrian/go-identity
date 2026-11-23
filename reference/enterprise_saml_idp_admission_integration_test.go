//go:build integration

package reference_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/reference"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

// Exercise the two published owner APIs with real installed PostgreSQL trust
// and independently signed fixture XML; this is not browser confirmation or
// a claim that the IdP-initiated HTTP endpoint is present.
func proveReferenceSAMLIDPAdmission(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, idp referenceSAMLIdPFixture) {
	t.Helper()
	selected := c.EnterpriseSAML
	clock := c.Session.Native.Execution.Clock
	routing := selected.Routing
	crypto, err := envelope.NewService(deps.EnvelopeKeys)
	if err != nil {
		t.Fatal("compose native encrypted SAML custody", err)
	}
	routing.Clock, routing.Envelope = clock, crypto
	router, err := ssopg.NewProviderRouter(deps.PostgreSQL, routing)
	if err != nil {
		t.Fatal("compose current provider router", err)
	}
	router, err = router.WithProtocolRegistry()
	if err != nil {
		t.Fatal("select provider protocol registry", err)
	}
	router, err = router.WithSAMLRouteValidation(saml.ValidateSPSigningCredential)
	if err != nil {
		t.Fatal("select real installed signer validation", err)
	}
	base := selected.Profile.TrustedOrigin + "/saml2/" + string(selected.Profile.ProviderID)
	owner, err := ssopg.NewProviderSAMLIDPAdmissionService(router, ssopg.ProviderSAMLIDPAdmissionConfig{
		TenantID: selected.Login.TenantID,
		Profiles: []ssopg.StaticSAMLIDPAdmissionProfile{{Provider: selected.Profile, MaximumAge: time.Minute}},
		Verify: func(ctx context.Context, input ssopg.SAMLIDPResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
			profile, err := saml.NewIDPInitiatedPOSTResponseProfile(saml.IDPInitiatedPOSTResponseConfig{
				SPEntityID: input.SPEntityID, IdentityProviderEntityID: input.IdentityProviderEntityID,
				ExternalOrigin: input.ExternalOrigin, ProviderID: string(input.ProviderID),
				SigningCertificates: input.SigningCertificates, MaximumAge: input.MaximumAge, ClockSkew: selected.ClockSkew,
			})
			if err != nil {
				return ssopg.SAMLVerifiedResponse{}, err
			}
			verified, err := profile.Validate(ctx, saml.IDPInitiatedPOSTResponseInput{SAMLResponse: input.SAMLResponse, Now: input.Now})
			if err != nil {
				return ssopg.SAMLVerifiedResponse{}, err
			}
			evidence, err := verified.Evidence()
			return ssopg.SAMLVerifiedResponse(evidence), err
		},
	})
	if err != nil {
		t.Fatal("select exact installed IdP-initiated provider", err)
	}
	now := clock.Now().UTC()
	document := referenceSAMLResponseInput{
		Issuer: referenceSAMLIdPEntity, Audience: base + "/metadata", ACS: base + "/idp-init",
		NameID: enterpriseProviderSubject, ResponseID: "_reference_idp_response", AssertionID: "_reference_idp_assertion", Now: now,
	}
	request := ssopg.SAMLIDPAdmissionRequest{TenantID: selected.Login.TenantID, ProviderID: selected.Profile.ProviderID,
		ReceivedAssertionConsumerURL: document.ACS, SAMLResponse: idp.signedUnsolicitedPOSTResponse(t, document)}
	verified, err := owner.Verify(ctx, request)
	if err != nil {
		t.Fatal("signed unsolicited response did not use installed native trust", err)
	}
	evidence, err := verified.Evidence()
	if err != nil || evidence.ProviderSubject != document.NameID || evidence.ResponseID != document.ResponseID ||
		evidence.AssertionID != document.AssertionID || !now.Before(evidence.ValidUntil) || evidence.ValidUntil.After(now.Add(20*time.Second)) {
		t.Fatal("native authority did not bound the detached signed evidence", err)
	}

	// A correctly signed SP-correlated response must still fail at the exact
	// IdP-init URL, even with the same installed IdP certificate.
	document.RequestID = "_reference_sp_request"
	request.SAMLResponse = idp.signedPOSTResponse(t, document)
	denied, err := owner.Verify(ctx, request)
	if _, evidenceErr := denied.Evidence(); !errors.Is(err, sso.ErrForbidden) || evidenceErr == nil {
		t.Fatal("SP request correlation became unsolicited login evidence", err)
	}
}
