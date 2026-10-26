package organizationhttp

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// DynamicRoleGetter owns an exact current manager-only custom-role read.
// Native role-read/session/catalog policy and final authority fences remain
// mandatory. Calls honor ctx/concurrency; a snapshot grants no access lease.
type DynamicRoleGetter interface {
	GetDynamicRole(context.Context, organization.DynamicRoleReadRequest) (organization.View, error)
}

// DynamicRoleLister owns bounded current manager-only custom-role pages.
// Static roles are not fabricated as custom rows. Native policy/currentness
// and pagination remain authoritative; failures disclose no partial page.
type DynamicRoleLister interface {
	ListDynamicRoles(context.Context, organization.DynamicRoleReadRequest) (organization.View, error)
}

// RoleStatementView preserves an exact registered permission/resource/effect.
// Effects are only "allow" or "deny"; order and deny precedence stay native.
type RoleStatementView struct {
	PermissionID string                   `json:"permissionID"`
	ResourceID   authorization.ResourceID `json:"resourceID"`
	Effect       string                   `json:"effect"`
}

// DynamicRoleView is bounded custom-role metadata, not effective permission.
// Statements is always an array; an empty array grants nothing.
type DynamicRoleView struct {
	ID         organization.ID     `json:"id"`
	Name       string              `json:"name"`
	Version    uint64              `json:"version"`
	Statements []RoleStatementView `json:"statements"`
}

// RoleResponse discloses one authorized role and its observed organization
// policy epoch, not a binding, membership or reusable authorization result.
type RoleResponse struct {
	OrganizationVersion uint64          `json:"organizationVersion"`
	Role                DynamicRoleView `json:"role"`
}

// RoleListResponse is a bounded ordered page with an exclusive native cursor.
// Roles is always an array. An epoch/cursor grants no mutation authority.
type RoleListResponse struct {
	OrganizationVersion uint64            `json:"organizationVersion"`
	Roles               []DynamicRoleView `json:"roles"`
	NextCursor          string            `json:"nextCursor,omitempty"`
}

func roleReadOperation(op organization.Operation) bool {
	return op == organization.GetDynamicRole || op == organization.ListDynamicRoles
}
func (in *requestInput) readRole() organization.DynamicRoleReadRequest {
	return organization.DynamicRoleReadRequest{Authentication: in.auth, OrganizationID: in.org, RoleID: in.dynamicRole, Cursor: in.roleCursor, Limit: in.limit, CorrelationID: in.correlation}
}
func decodeRoleQuery(in *requestInput, q url.Values) error {
	exact := in.op == organization.GetDynamicRole
	for key, values := range q {
		if len(values) != 1 || key != "organizationID" && (exact && key != "roleID" || !exact && key != "limit" && key != "cursor") {
			return identityhttp.ErrInvalidInput
		}
	}
	in.org = organization.ID(q.Get("organizationID"))
	if !boundedID(string(in.org)) {
		return identityhttp.ErrInvalidInput
	}
	if exact {
		in.dynamicRole = organization.ID(q.Get("roleID"))
		if len(q) != 2 || !boundedID(string(in.dynamicRole)) || organization.Role(in.dynamicRole).Valid() {
			return identityhttp.ErrInvalidInput
		}
		return nil
	}
	if len(q["limit"]) != 1 {
		return identityhttp.ErrInvalidInput
	}
	limit := q.Get("limit")
	n, err := strconv.ParseUint(limit, 10, 32)
	if err != nil || n < 1 || n > 100 || strconv.FormatUint(n, 10) != limit {
		return identityhttp.ErrInvalidInput
	}
	in.limit = uint32(n)
	if cursor, ok := q["cursor"]; ok {
		if !boundedID(cursor[0]) {
			return identityhttp.ErrInvalidInput
		}
		in.roleCursor = cursor[0]
	}
	return nil
}

func validDynamicRoleMetadata(in *requestInput, role organization.DynamicRole) bool {
	if role.TenantID != in.auth.TenantID || role.OrganizationID != in.org || !boundedID(string(role.ID)) || organization.Role(role.ID).Valid() || role.Version == 0 || len(role.Name) < 1 || len(role.Name) > 256 || !utf8.ValidString(role.Name) || strings.TrimSpace(role.Name) != role.Name || len(role.Statements) > 64 {
		return false
	}
	for _, r := range role.Name {
		if r < ' ' || r == 127 {
			return false
		}
	}
	seen := make(map[organization.RoleStatement]bool, len(role.Statements))
	for _, s := range role.Statements {
		if !boundedID(s.PermissionID) || !boundedID(string(s.ResourceID)) || strings.ContainsAny(string(s.ResourceID), "*?") || s.Effect != authorization.Allow && s.Effect != authorization.Deny || seen[s] {
			return false
		}
		seen[s] = true
	}
	// Match the native RoleStatement encoding budget before allocating the
	// transport projection. Syntax checks are not a replacement catalog lookup.
	wire, err := json.Marshal(role.Statements)
	return err == nil && len(wire) <= 8192
}
func projectDynamicRole(role organization.DynamicRole) DynamicRoleView {
	out := DynamicRoleView{ID: role.ID, Name: role.Name, Version: role.Version, Statements: make([]RoleStatementView, len(role.Statements))}
	for i, s := range role.Statements {
		out.Statements[i] = RoleStatementView{PermissionID: s.PermissionID, ResourceID: s.ResourceID, Effect: s.Effect.String()}
	}
	return out
}
func roleReadResponse(in *requestInput, v organization.View) (any, error) {
	if !validScopedReadView(in, v) || v.Actor.Role != organization.RoleOwner && v.Actor.Role != organization.RoleAdministrator {
		return nil, identityhttp.ErrUnavailable
	}
	if in.op == organization.GetDynamicRole {
		if !validDynamicRoleMetadata(in, v.DynamicRole) || v.DynamicRole.ID != in.dynamicRole {
			return nil, identityhttp.ErrUnavailable
		}
		return RoleResponse{OrganizationVersion: v.Organization.Version, Role: projectDynamicRole(v.DynamicRole)}, nil
	}
	if len(v.DynamicRoles) > int(in.limit) {
		return nil, identityhttp.ErrUnavailable
	}
	out := RoleListResponse{OrganizationVersion: v.Organization.Version, Roles: make([]DynamicRoleView, len(v.DynamicRoles)), NextCursor: v.NextRoleCursor}
	for i, role := range v.DynamicRoles {
		if !validDynamicRoleMetadata(in, role) || string(role.ID) <= in.roleCursor || i > 0 && v.DynamicRoles[i-1].ID >= role.ID {
			return nil, identityhttp.ErrUnavailable
		}
		out.Roles[i] = projectDynamicRole(role)
	}
	if out.NextCursor != "" && (len(v.DynamicRoles) == 0 || len(v.DynamicRoles) != int(in.limit) || out.NextCursor != string(v.DynamicRoles[len(v.DynamicRoles)-1].ID)) {
		return nil, identityhttp.ErrUnavailable
	}
	return out, nil
}
