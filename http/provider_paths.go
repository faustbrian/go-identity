package identityhttp

import (
	"net/http"
	"net/url"
	"strings"
)

func validProviderPaths(op OperationDescriptor) bool {
	// Bind only the catalogued finite provider profiles. Other templates
	// are not wildcard dispatch, and extension routes cannot opt into it.
	var selected bool
	switch op.Record.OperationID {
	case "identity.sso.oidc-logout":
		selected = op.Route.Method == http.MethodPost && op.Route.Path == "/sso/oidc/{provider_id}/logout"
	case "identity.sso.oidc-logout-complete":
		selected = op.Route.Method == http.MethodGet && op.Route.Path == "/sso/oidc/{provider_id}/logout/callback"
	case "identity.sso.saml-start":
		selected = op.Route.Method == http.MethodGet && op.Route.Path == "/saml2/{provider_id}/login"
	case "identity.sso.saml-metadata":
		selected = op.Route.Method == http.MethodGet && op.Route.Path == "/saml2/{provider_id}/metadata"
	case "identity.sso.saml-acs":
		selected = op.Route.Method == http.MethodPost && op.Route.Path == "/saml2/{provider_id}/acs"
	case "identity.sso.saml-idp-init":
		selected = op.Route.Method == http.MethodPost && op.Route.Path == "/saml2/{provider_id}/idp-init"
	}
	if !selected {
		return len(op.ProviderPathIDs) == 0
	}
	if len(op.ProviderPathIDs) == 0 || len(op.ProviderPathIDs) > 128 {
		return false
	}
	seen := make(map[string]bool, len(op.ProviderPathIDs))
	for _, id := range op.ProviderPathIDs {
		if !validProviderPathID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validProviderPathID(id string) bool {
	return ascii(id, 128, false) && validPath("/"+id) && !strings.ContainsAny(id, "/{}") && url.PathEscape(id) == id
}

func validSAMLACSPath(path string) bool {
	return validSAMLProviderEndpoint(path, "/acs")
}

func validSAMLProviderEndpoint(path, endpoint string) bool {
	providerAndEndpoint, ok := strings.CutPrefix(path, "/saml2/")
	if !ok {
		return false
	}
	provider, ok := strings.CutSuffix(providerAndEndpoint, endpoint)
	return ok && validProviderPathID(provider)
}

func dispatchPaths(op OperationDescriptor) []string {
	if len(op.ProviderPathIDs) == 0 {
		return []string{op.Route.Path}
	}
	paths := make([]string, len(op.ProviderPathIDs))
	for i, id := range op.ProviderPathIDs {
		paths[i] = strings.Replace(op.Route.Path, "{provider_id}", id, 1)
	}
	return paths
}
