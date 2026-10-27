package organizationhttp

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// PermissionChecker owns current member-only effective custom-role evaluation.
// It must authenticate the same human, enforce exact organization policy epochs,
// current membership and selected team bindings, and retain final authority
// fences. Static management roles grant no implicit application access. Calls
// honor ctx and support concurrency; returned decisions grant no access lease.
type PermissionChecker interface {
	CheckPermission(context.Context, organization.PermissionCheckRequest) (authorization.Decision, error)
}

// PermissionCheckResponse is an explicit current native allow/deny decision at
// the requested organization epoch. It is neither a token nor cached authority.
type PermissionCheckResponse struct {
	Decision            string `json:"decision"`
	OrganizationVersion uint64 `json:"organizationVersion"`
}

func decodePermissionQuery(in *requestInput, q url.Values) error {
	if len(q) != 5 {
		return identityhttp.ErrInvalidInput
	}
	for _, key := range []string{"organizationID", "organizationVersion", "action", "resourceType", "resourceID"} {
		if len(q[key]) != 1 {
			return identityhttp.ErrInvalidInput
		}
	}
	in.org = organization.ID(q.Get("organizationID"))
	in.permissionAction, in.permissionType, in.permissionResource = q.Get("action"), q.Get("resourceType"), q.Get("resourceID")
	if !boundedID(string(in.org)) || !boundedID(in.permissionAction) || !boundedID(in.permissionType) || !boundedID(in.permissionResource) || strings.ContainsAny(in.permissionAction+in.permissionType+in.permissionResource, "*?") {
		return identityhttp.ErrInvalidInput
	}
	version := q.Get("organizationVersion")
	n, err := strconv.ParseUint(version, 10, 64)
	// This read observes an epoch without advancing it: the terminal uint64
	// epoch remains valid, unlike mutation requests that require a successor.
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != version {
		return identityhttp.ErrInvalidInput
	}
	in.orgVersion = n
	return nil
}

func (in *requestInput) permissionCheck() organization.PermissionCheckRequest {
	return organization.PermissionCheckRequest{Authentication: in.auth, OrganizationID: in.org, OrganizationVersion: in.orgVersion, Action: authorization.Action(in.permissionAction), ResourceType: authorization.ResourceType(in.permissionType), ResourceID: authorization.ResourceID(in.permissionResource), CorrelationID: in.correlation}
}

func permissionResponse(in *requestInput, out authorization.Decision) (PermissionCheckResponse, error) {
	// Native evaluateRoles builds its snapshot from this exact organization
	// policy epoch. A different revision or nonterminal outcome cannot attest
	// to this request, even if a transport port accidentally supplies one.
	if out.Revision != authorization.Revision(in.orgVersion) || out.Outcome != authorization.Allow && out.Outcome != authorization.Deny {
		return PermissionCheckResponse{}, identityhttp.ErrUnavailable
	}
	return PermissionCheckResponse{Decision: out.Outcome.String(), OrganizationVersion: in.orgVersion}, nil
}
