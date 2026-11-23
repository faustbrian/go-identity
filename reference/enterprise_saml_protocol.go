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
		// The native callback supplies the current installed signing set and
		// original transaction. XML input cannot add keys or renew its expiry.
		profile, err := saml.NewPOSTResponseProfile(saml.POSTResponseConfig{SPEntityID: input.SPEntityID,
			IdentityProviderEntityID: input.IdentityProviderEntityID, AssertionConsumerURL: input.AssertionConsumerURL,
			SigningCertificates: input.SigningCertificates, ClockSkew: skew})
		if err != nil {
			return ssopg.SAMLVerifiedResponse{}, err
		}
		out, err := profile.Validate(ctx, saml.POSTResponseInput{SAMLResponse: input.SAMLResponse, RequestID: input.RequestID,
			IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt, Now: input.Now})
		if err != nil {
			return ssopg.SAMLVerifiedResponse{}, err
		}
		evidence, err := out.Evidence()
		if err != nil {
			return ssopg.SAMLVerifiedResponse{}, err
		}
		return ssopg.SAMLVerifiedResponse{ResponseID: evidence.ResponseID, AssertionID: evidence.AssertionID, ProviderSubject: evidence.ProviderSubject,
			SubjectFormat: evidence.SubjectFormat, SessionIndex: evidence.SessionIndex,
			AssertionExpiresAt: evidence.AssertionExpiresAt, ValidUntil: evidence.ValidUntil}, nil
	}
}
