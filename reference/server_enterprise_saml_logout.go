package reference

import (
	"context"

	ssohttp "github.com/faustbrian/go-identity/http/sso"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

var _ ssohttp.SAMLLogoutRequestOwner = enterpriseSAMLHTTP{}

func (a enterpriseSAMLHTTP) HandleSAMLLogoutRequest(ctx context.Context, request ssohttp.SAMLLogoutRequest) (ssohttp.SAMLLogoutRequestResult, error) {
	var out ssohttp.SAMLLogoutRequestResult
	n := a.native
	if n == nil || n.http == nil || !n.http.Logout || n.logout == nil ||
		request.TenantID != n.tenant || request.ProviderID != string(n.profile.ProviderID) {
		return out, sso.ErrForbidden
	}
	result, err := n.logout.requests.HandleRequest(ctx, ssopg.ProviderSAMLIDPLogoutRequest{
		ProviderID: n.profile.ProviderID, SAMLRequest: []string{request.SAMLRequest},
	})
	if err != nil {
		return out, err
	}
	if fields, deliver := result.Response(); deliver {
		out = ssohttp.SAMLLogoutRequestResult{Destination: fields.Destination, SAMLResponse: fields.SAMLResponse}
	}
	return out, nil
}
