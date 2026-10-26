package organizationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/faustbrian/go-authorization/v3"
	identityhttp "github.com/faustbrian/go-identity/http"
	organization "github.com/faustbrian/go-organization"
)

// DynamicRoleCreator owns original-key custom-role creation. Current manager,
// catalog, role-write/query authority, quotas and atomic effects stay native.
// Calls honor ctx and concurrency; unknown outcomes never authorize reexecution.
type DynamicRoleCreator interface {
	CreateDynamicRole(context.Context, organization.CreateDynamicRoleOperationRequest, string) (organization.StoreResult, error)
}

// DynamicRoleUpdater owns original-key exact-epoch replacement of the complete
// ordered statements. Empty statements grant nothing. Implementations copy
// borrowed intent before callbacks and retain native current authority.
type DynamicRoleUpdater interface {
	UpdateDynamicRole(context.Context, organization.UpdateDynamicRoleOperationRequest, string) (organization.StoreResult, error)
}

// DynamicRoleDeleter owns naturally repeated exact-version terminal retirement.
// Only original native history proves success; missing rows never do. Current
// manager/session/action/query authority remains mandatory on every recovery.
// Calls honor ctx and concurrency without renewing admission or redispatching.
type DynamicRoleDeleter interface {
	DeleteDynamicRole(context.Context, organization.DeleteDynamicRoleOperationRequest, string) (organization.StoreResult, error)
}

func roleCRUDMutation(op organization.Operation) bool {
	return op == organization.CreateDynamicRole || op == organization.UpdateDynamicRole || op == organization.DeleteDynamicRole
}
func roleCRUDKeyed(op organization.Operation) bool {
	return op == organization.CreateDynamicRole || op == organization.UpdateDynamicRole
}
func (in *requestInput) createRole() organization.CreateDynamicRoleOperationRequest {
	return organization.CreateDynamicRoleOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, RoleID: in.dynamicRole, OrganizationVersion: in.orgVersion, Name: in.name, Statements: in.statements, CorrelationID: in.correlation}
}
func (in *requestInput) updateRole() organization.UpdateDynamicRoleOperationRequest {
	return organization.UpdateDynamicRoleOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, RoleID: in.dynamicRole, OrganizationVersion: in.orgVersion, RoleVersion: in.roleVersion, Name: in.name, Statements: in.statements, CorrelationID: in.correlation}
}
func (in *requestInput) deleteRole() organization.DeleteDynamicRoleOperationRequest {
	return organization.DeleteDynamicRoleOperationRequest{Authentication: in.auth, OrganizationID: in.org, RoleID: in.dynamicRole, OrganizationVersion: in.orgVersion, RoleVersion: in.roleVersion, CorrelationID: in.correlation}
}

func decodeRoleMutation(in *requestInput, body map[string]json.RawMessage) error {
	names := []string{"organizationID", "roleID", "organizationVersion"}
	if in.op != organization.CreateDynamicRole {
		names = append(names, "roleVersion")
	}
	if in.op != organization.DeleteDynamicRole {
		names = append(names, "name", "statements")
	}
	if len(body) != len(names) {
		return identityhttp.ErrInvalidInput
	}
	for _, name := range names {
		value, ok := body[name]
		if !ok || string(value) == "null" {
			return identityhttp.ErrInvalidInput
		}
	}
	decode := func(name string, target any) bool { return json.Unmarshal(body[name], target) == nil }
	if !decode("organizationID", &in.org) || !decode("roleID", &in.dynamicRole) || !decode("organizationVersion", &in.orgVersion) || in.op != organization.CreateDynamicRole && !decode("roleVersion", &in.roleVersion) {
		return identityhttp.ErrInvalidInput
	}
	if in.op != organization.DeleteDynamicRole {
		if !decode("name", &in.name) {
			return identityhttp.ErrInvalidInput
		}
		var err error
		in.statements, err = decodeRoleStatements(body["statements"])
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeRoleStatements(raw json.RawMessage) ([]organization.RoleStatement, error) {
	// The shared decoder has already bounded bytes/depth and rejected duplicate
	// names at every depth. Stream the native 64-statement limit before growing
	// an output slice; native request validation then enforces its 8192-byte
	// canonical statement encoding and leaves catalog membership native-owned.
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return nil, identityhttp.ErrInvalidInput
	}
	out := make([]organization.RoleStatement, 0)
	for d.More() {
		if len(out) == 64 {
			return nil, identityhttp.ErrInvalidInput
		}
		var fields map[string]json.RawMessage
		if d.Decode(&fields) != nil || len(fields) != 3 {
			return nil, identityhttp.ErrInvalidInput
		}
		for _, key := range []string{"permissionID", "resourceID", "effect"} {
			value, ok := fields[key]
			if !ok || string(value) == "null" {
				return nil, identityhttp.ErrInvalidInput
			}
		}
		var statement organization.RoleStatement
		var effect string
		if json.Unmarshal(fields["permissionID"], &statement.PermissionID) != nil || json.Unmarshal(fields["resourceID"], &statement.ResourceID) != nil || json.Unmarshal(fields["effect"], &effect) != nil {
			return nil, identityhttp.ErrInvalidInput
		}
		switch effect {
		case "allow":
			statement.Effect = authorization.Allow
		case "deny":
			statement.Effect = authorization.Deny
		default:
			return nil, identityhttp.ErrInvalidInput
		}
		out = append(out, statement)
	}
	end, err := d.Token()
	var trailing any
	if err != nil || end != json.Delim(']') || d.Decode(&trailing) != io.EOF {
		return nil, identityhttp.ErrInvalidInput
	}
	return out, nil
}
