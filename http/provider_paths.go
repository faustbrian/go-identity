package identityhttp

import (
	"net/http"
	"net/url"
	"strings"
)

func validProviderPaths(op OperationDescriptor) bool {
	// Bind only the two catalogued OIDC logout operations. Other templates
	// are not wildcard dispatch, and extension routes cannot opt into it.
	selected := op.Record.OperationID == "identity.sso.oidc-logout" && op.Route.Method == http.MethodPost && op.Route.Path == "/sso/oidc/{provider_id}/logout" ||
		op.Record.OperationID == "identity.sso.oidc-logout-complete" && op.Route.Method == http.MethodGet && op.Route.Path == "/sso/oidc/{provider_id}/logout/callback"
	if !selected {
		return len(op.ProviderPathIDs) == 0
	}
	if len(op.ProviderPathIDs) == 0 || len(op.ProviderPathIDs) > 128 {
		return false
	}
	seen := make(map[string]bool, len(op.ProviderPathIDs))
	for _, id := range op.ProviderPathIDs {
		if !ascii(id, 128, false) || !validPath("/"+id) || strings.ContainsAny(id, "/{}") || url.PathEscape(id) != id || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
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
