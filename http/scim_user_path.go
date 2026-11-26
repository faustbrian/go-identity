package identityhttp

import (
	"net/http"
	"strings"
)

const scimUserPathPrefix = "/scim/v2/Users/"

func scimUserResourceOperation(op OperationDescriptor) bool {
	if op.Route.Path != scimUserPathPrefix+"{resource_id}" {
		return false
	}
	switch op.Record.OperationID {
	case "identity.scim.user-get":
		return op.Route.Method == http.MethodGet
	case "identity.scim.user-delete":
		return op.Route.Method == http.MethodDelete
	case "identity.scim.user-patch":
		return op.Route.Method == http.MethodPatch
	case "identity.scim.user-replace":
		return op.Route.Method == http.MethodPut
	default:
		return false
	}
}

func scimUserPathID(path string) string {
	id, hasPrefix := strings.CutPrefix(path, scimUserPathPrefix)
	if !hasPrefix || len(id) == 0 || len(id) > 128 || id == "." || id == ".." || id == ".search" {
		return ""
	}
	// The managed PostgreSQL owner issues URL-safe IDs. Accept one unreserved
	// segment without decoding it; neither SCIM's reserved Search endpoint nor
	// other URL delimiters can become a resource target through this route.
	for i := range len(id) {
		b := id[i]
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || strings.IndexByte("-._~", b) >= 0) {
			return ""
		}
	}
	return id
}
