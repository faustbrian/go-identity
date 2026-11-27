package scimhttp

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedGroupsDeleteOperation = "identity.scim.group-delete"

// ManagedGroupsDeleteExecutor owns issued bearer/current authority, strong
// original preconditions, deletion of the exact Group, and replay by canonical
// request with an optional key alias. It invokes admission once synchronously
// after authorization and preflight, before durable command effects. A success
// is exactly an empty 204. Honor ctx and do not retain the borrowed invocation.
type ManagedGroupsDeleteExecutor interface {
	ExecuteManagedAdmittedGroupDelete(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedGroupsDeleteConfig selects only conditional Group DELETE. Network,
// Limits, deadline and borrowed quota match ManagedUsersDeleteConfig;
// MaximumMembers is the trusted explicit native Group ceiling, including zero.
type ManagedGroupsDeleteConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedGroupsDeleteExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
	MaximumMembers  int
}

// Format redacts borrowed runtime composition.
func (ManagedGroupsDeleteConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedGroupsDeleteConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedGroupsDeleteConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedGroupsDeleteConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedGroupsDeleteFeature selects only DELETE /scim/v2/Groups/{resource_id}.
// An issued bearer and exact original If-Match are forwarded. One optional
// Idempotency-Key can alias the canonical request; absence does not disable
// native replay. User DELETE remains unchanged. No body, query, cookie
// authority, other route, new replay owner or retry mechanism is selected.
func NewManagedGroupsDeleteFeature(c ManagedGroupsDeleteConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) || c.MaximumMembers < 0 || c.MaximumMembers > scim.DefaultGroupMembers {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	execute := func(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
		return c.Executor.ExecuteManagedAdmittedGroupDelete(ctx, tenant, request, c.MaximumMembers, admit)
	}
	return newManagedDeleteFeature(managedDeleteConfig{
		network: c.Network, rate: c.Rate, limits: c.Limits, duration: c.MaximumDuration,
	}, scim.GroupDelete, execute)
}
