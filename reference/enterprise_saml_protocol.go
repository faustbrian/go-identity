package reference

import (
	"context"
	"net/url"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func enterpriseSAMLSignRedirect(ctx context.Context, input ssopg.SAMLAuthnRedirectInput, bundle []byte, now time.Time) (url.URL, time.Time, error) {
	profile, err := saml.NewAuthnRedirectProfile(saml.AuthnRedirectConfig{SPEntityID: input.SPEntityID,
		AssertionConsumerURL: input.AssertionConsumerURL, IdentityProviderURL: input.IdentityProviderURL})
	if err != nil {
		return url.URL{}, time.Time{}, err
	}
	request := saml.AuthnRequest{ID: input.RequestID, IssuedAt: input.IssuedAt, RelayState: input.RelayState}
	redirect, validUntil, err := profile.RedirectWithSPSigningCredential(ctx, request, bundle, now)
	if err != nil {
		return url.URL{}, time.Time{}, err
	}
	destination, err := redirect.URL()
	if err != nil {
		return url.URL{}, time.Time{}, err
	}
	return destination, validUntil, nil
}

func enterpriseSAMLPOSTVerifier(skew time.Duration) ssopg.SAMLResponseVerifier {
	return func(ctx context.Context, input ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedResponse, error) {
		verified, err := verifyEnterpriseSAMLPOST(ctx, input, skew)
		if err != nil {
			return ssopg.SAMLVerifiedResponse{}, err
		}
		evidence, err := verified.Evidence()
		return ssopg.SAMLVerifiedResponse(evidence), err
	}
}

func enterpriseSAMLPOSTLogoutVerifier(skew time.Duration) ssopg.SAMLResponseWithLogoutSubjectVerifier {
	return func(ctx context.Context, input ssopg.SAMLResponseVerificationInput) (ssopg.SAMLVerifiedLoginResponse, error) {
		verified, err := verifyEnterpriseSAMLPOST(ctx, input, skew)
		if err != nil {
			return ssopg.SAMLVerifiedLoginResponse{}, err
		}
		return enterpriseSAMLLoginWithLogoutSubject(verified)
	}
}

func verifyEnterpriseSAMLPOST(ctx context.Context, input ssopg.SAMLResponseVerificationInput, skew time.Duration) (saml.VerifiedPOSTResponse, error) {
	// Only the native callback supplies the current signing set and original
	// transaction. XML cannot substitute keys or renew its original expiry.
	profile, err := saml.NewPOSTResponseProfile(saml.POSTResponseConfig{SPEntityID: input.SPEntityID,
		IdentityProviderEntityID: input.IdentityProviderEntityID, AssertionConsumerURL: input.AssertionConsumerURL,
		SigningCertificates: input.SigningCertificates, ClockSkew: skew})
	if err != nil {
		return saml.VerifiedPOSTResponse{}, err
	}
	return profile.Validate(ctx, saml.POSTResponseInput{SAMLResponse: input.SAMLResponse, RequestID: input.RequestID,
		IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt, Now: input.Now})
}

type enterpriseSAMLVerifiedLogin interface {
	Evidence() (saml.POSTResponseEvidence, error)
	LogoutSubject() (saml.LogoutSubjectEvidence, error)
}

func enterpriseSAMLLoginWithLogoutSubject(verified enterpriseSAMLVerifiedLogin) (ssopg.SAMLVerifiedLoginResponse, error) {
	evidence, err := verified.Evidence()
	if err != nil {
		return ssopg.SAMLVerifiedLoginResponse{}, err
	}
	subject, err := verified.LogoutSubject()
	if err != nil {
		return ssopg.SAMLVerifiedLoginResponse{}, err
	}
	return ssopg.SAMLVerifiedLoginResponse{
		Evidence: ssopg.SAMLVerifiedResponse(evidence), LogoutSubject: ssopg.SAMLLogoutSubject(subject),
	}, nil
}
