package scimhttp

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scim "github.com/faustbrian/go-scim"
)

const managedGroupsPatchOperation = "identity.scim.group-patch"

// ManagedGroupsPatchExecutor owns native Group PatchOp validation, issued
// bearer and current policy authority, exact original command, replay and
// atomic CAS. The executor invokes admission once synchronously with the
// configured client after validation and before mapping or command effects.
// Inputs and callback are borrowed; return detached data and honor ctx with no
// detached work. An error does not establish rollback of an uncertain effect.
type ManagedGroupsPatchExecutor interface {
	ExecuteManagedAdmittedGroupPatch(context.Context, identity.TenantID, scim.Request, int, scim.ProtocolAdmission) (scim.Response, error)
}

// ManagedGroupsPatchConfig selects only the managed Group PATCH port. Network,
// Limits, native canonical BaseURL, member ceiling and borrowed quota follow
// ManagedGroupsReplaceConfig. Zero MaximumMembers is explicit, not a default.
type ManagedGroupsPatchConfig struct {
	Network         identityhttp.NetworkConfig
	Executor        ManagedGroupsPatchExecutor
	Rate            ProtocolRateConfig
	Limits          scim.Limits
	MaximumDuration time.Duration
	MaximumMembers  int
}

// Format redacts borrowed native, network and rate-key custody.
func (ManagedGroupsPatchConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedGroupsPatchConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedGroupsPatchConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime configuration export.
func (ManagedGroupsPatchConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// NewManagedGroupsPatchFeature selects only PATCH /scim/v2/Groups/{resource_id}.
// It forwards bounded raw PatchOp and the exact original If-Match; query and
// caller idempotency keys are forbidden. Native authority, one shared quota
// admission, typed members, replay and mutation stay native-owned. Success
// discloses the complete native Group with validated ETag and Location. No
// cookie authority, other route or retry is enabled. The returned feature
// can combine disjoint operations under canonical feature ID "scim".
func NewManagedGroupsPatchFeature(c ManagedGroupsPatchConfig) (identityhttp.Feature, error) {
	if missingManagedOwner(c.Executor) {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return newManagedGroupsConditionalFeature(managedGroupsConditionalConfig{
		network: c.Network, rate: c.Rate, limits: c.Limits, duration: c.MaximumDuration, maximumMembers: c.MaximumMembers,
	}, scim.GroupPatch, c.Executor.ExecuteManagedAdmittedGroupPatch)
}
