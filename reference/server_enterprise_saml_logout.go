package reference

import (
	"context"

	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

var _ ssohttp.SAMLLogoutRequestOwner = enterpriseSAMLHTTP{}
var _ ssohttp.SAMLLogoutRequestRelayOwner = enterpriseSAMLHTTP{}
var _ ssohttp.SAMLLogoutStartOwner = enterpriseSAMLHTTP{}
var _ ssohttp.SAMLLogoutOwner = enterpriseSAMLHTTP{}

func (a enterpriseSAMLHTTP) HandleSAMLLogoutRequest(ctx context.Context, request ssohttp.SAMLLogoutRequest) (ssohttp.SAMLLogoutRequestResult, error) {
	result, err := a.HandleSAMLLogoutRequestWithRelayState(ctx, request, "")
	return result.SAMLLogoutRequestResult, err
}

func (a enterpriseSAMLHTTP) HandleSAMLLogoutRequestWithRelayState(ctx context.Context, request ssohttp.SAMLLogoutRequest, relay string) (ssohttp.SAMLLogoutRequestRelayResult, error) {
	var out ssohttp.SAMLLogoutRequestRelayResult
	n := a.native
	if n == nil || n.http == nil || !n.http.Logout || n.logout == nil ||
		request.TenantID != n.tenant || request.ProviderID != string(n.profile.ProviderID) {
		return out, sso.ErrForbidden
	}
	var values []string
	if relay != "" {
		values = []string{relay}
	}
	result, err := n.logout.requests.HandleRequestWithRelayState(ctx, ssopg.ProviderSAMLIDPLogoutRequest{
		ProviderID: n.profile.ProviderID, SAMLRequest: []string{request.SAMLRequest},
	}, values)
	if err != nil {
		return out, err
	}
	if fields, deliver := result.Response(); deliver {
		out.SAMLLogoutRequestResult = ssohttp.SAMLLogoutRequestResult{Destination: fields.Destination, SAMLResponse: fields.SAMLResponse}
		out.RelayState, _ = result.RelayState()
	}
	return out, nil
}

func (a enterpriseSAMLHTTP) StartSSOSAMLLogout(ctx context.Context, request ssohttp.ProviderLogoutStartRequest) (ssohttp.SAMLLogoutStartResult, error) {
	n := a.native
	if n == nil || n.http == nil || !n.http.LogoutStart || n.logoutStart == nil ||
		request.TenantID != n.tenant || request.ProviderID != string(n.profile.ProviderID) {
		return ssohttp.SAMLLogoutStartResult{}, sso.ErrForbidden
	}
	input := ssopg.ProviderLogoutStartRequest{ProviderID: string(n.profile.ProviderID), IdempotencyKey: request.IdempotencyKey, FinalRedirect: request.FinalRedirect}
	browser := ssopg.ProviderLogoutBrowser{Session: request.Session, CSRF: request.CSRF, Origin: request.Origin}
	if n.logoutStart.remote == nil {
		result, err := n.logoutStart.local.Start(ctx, input, browser)
		return ssohttp.SAMLLogoutStartResult{LocalRevocation: result.LocalRevocation, LocalOnly: result.LocalOnly}, err
	}
	result, err := n.logoutStart.remote.Start(ctx, input, browser)
	out := ssohttp.SAMLLogoutStartResult{LocalRevocation: result.LocalRevocation, LocalOnly: result.LocalOnly}
	if redirect, ok := result.ProviderRedirect(); err == nil && ok {
		out.ProviderRedirect = redirect.String()
	}
	return out, err
}

func (a enterpriseSAMLHTTP) SettleSAMLLogoutResponse(ctx context.Context, request ssohttp.SAMLLogoutResponseRequest) (ssohttp.SAMLLogoutResponseResult, error) {
	n := a.native
	var out ssohttp.SAMLLogoutResponseResult
	if n == nil || n.http == nil || !n.http.Logout || n.logoutStart == nil || n.logoutStart.remote == nil ||
		request.TenantID != n.tenant || request.ProviderID != string(n.profile.ProviderID) {
		return out, sso.ErrForbidden
	}
	result, err := n.logoutStart.remote.SettleResponse(ctx, ssopg.ProviderSAMLLogoutResponseRequest{
		ProviderID: n.profile.ProviderID, SAMLResponse: []string{request.SAMLResponse},
	})
	if err != nil {
		return out, err
	}
	if redirect, ok := result.FinalRedirect(); ok {
		out.FinalRedirect = redirect.String()
	}
	return out, nil
}
