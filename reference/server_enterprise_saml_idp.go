package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

var _ ssohttp.SAMLIDPSigninOwner = enterpriseSAMLHTTP{}

func (a enterpriseSAMLHTTP) selectedIDP(tenant identity.TenantID, provider string) (*enterpriseSAMLIDPState, error) {
	if a.native == nil || a.native.idp == nil || tenant != a.native.tenant || provider != string(a.native.profile.ProviderID) {
		return nil, sso.ErrForbidden
	}
	return a.native.idp, nil
}

func (a enterpriseSAMLHTTP) PrepareSAMLIDP(ctx context.Context, request ssohttp.SAMLIDPArrivalRequest) (ssohttp.SAMLIDPArrivalResult, error) {
	owner, err := a.selectedIDP(request.TenantID, request.ProviderID)
	if err != nil {
		return ssohttp.SAMLIDPArrivalResult{}, err
	}
	out, err := owner.arrival.Prepare(ctx, ssopg.SAMLIDPAdmissionRequest{TenantID: request.TenantID, ProviderID: sso.ProviderID(request.ProviderID),
		ReceivedAssertionConsumerURL: request.ReceivedAssertionConsumerURL, SAMLResponse: request.SAMLResponse})
	if err != nil {
		return ssohttp.SAMLIDPArrivalResult{}, err
	}
	browser, form, expires, fresh := out.TakeConfirmation()
	if !fresh {
		return ssohttp.SAMLIDPArrivalResult{}, sso.ErrForbidden
	}
	return ssohttp.SAMLIDPArrivalResult{PendingID: out.CommandID, BrowserCookie: browser, Synchronizer: form, ExpiresAt: expires}, nil
}

func (a enterpriseSAMLHTTP) SAMLIDPConfirmationRateSource(ctx context.Context, request ssohttp.SAMLIDPConfirmationRequest) (ssohttp.SAMLIDPConfirmationRateContext, error) {
	owner, err := a.selectedIDP(request.TenantID, request.ProviderID)
	if err != nil {
		return ssohttp.SAMLIDPConfirmationRateContext{}, err
	}
	out, err := owner.confirmation.ConfirmationRateSource(ctx, enterpriseSAMLIDPConfirmation(request))
	if err != nil {
		return ssohttp.SAMLIDPConfirmationRateContext{}, err
	}
	if out.FlowID != "" || out.TransactionID != string(request.PendingID) || string(out.ProviderID) != request.ProviderID {
		return ssohttp.SAMLIDPConfirmationRateContext{}, sso.ErrUnavailable
	}
	return ssohttp.SAMLIDPConfirmationRateContext{ProviderID: string(out.ProviderID), PendingID: request.PendingID, Lifetime: out.Lifetime}, nil
}

func (a enterpriseSAMLHTTP) ConfirmSAMLIDP(ctx context.Context, request ssohttp.SAMLIDPConfirmationRequest) (ssohttp.SigninCallbackResult, error) {
	owner, err := a.selectedIDP(request.TenantID, request.ProviderID)
	if err != nil {
		return ssohttp.SigninCallbackResult{}, err
	}
	out, err := owner.confirmation.Confirm(ctx, enterpriseSAMLIDPConfirmation(request))
	if err != nil {
		return ssohttp.SigninCallbackResult{}, err
	}
	return ssohttp.SigninCallbackResult{Completion: out.Completion, Issuance: out.Issuance, CSRF: out.CSRF, RedirectURI: out.RedirectURI}, nil
}

func enterpriseSAMLIDPConfirmation(r ssohttp.SAMLIDPConfirmationRequest) ssopg.SAMLIDPConfirmationRequest {
	return ssopg.SAMLIDPConfirmationRequest{TenantID: r.TenantID, ProviderID: sso.ProviderID(r.ProviderID), PendingID: r.PendingID,
		Origin: r.Origin, Browser: r.Browser, Form: r.Form}
}
