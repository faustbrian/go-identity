package reference

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

const managedSCIMGroupsReadField = "reference_http_managed_scim_groups_read"
const managedSCIMGroupsCreateField = "reference_http_managed_scim_groups_create"
const managedSCIMGroupsReplaceField = "reference_http_managed_scim_groups_replace"
const managedSCIMGroupsPatchField = "reference_http_managed_scim_groups_patch"

// HTTPManagedSCIMGroupsReadConfiguration opts independently into managed
// Group Get and List, without selecting Group writes or connection lifecycle.
// At least one read must be enabled. MaximumMembers is explicit; zero permits
// only empty Groups. If a managed User route is selected, leave Native and
// the rate settings zero to share its exact owner and quota. Without a User
// route, select Native only if managed connection creation is disabled, and
// select a dedicated rate namespace and key only when SCIM Bulk is disabled.
type HTTPManagedSCIMGroupsReadConfiguration struct {
	Native         *ManagedSCIMConnectionConfiguration
	RateNamespace  string
	RateKey        [32]byte
	MaximumMembers int
	EnableGet      bool
	EnableList     bool
}

func (HTTPManagedSCIMGroupsReadConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMGroupsReadConfiguration(redacted)")
}

func (HTTPManagedSCIMGroupsReadConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMGroupsReadField}
}

func (c HTTPManagedSCIMGroupsReadConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

// HTTPManagedSCIMGroupsCreateConfiguration selects only managed Group Create.
// With Group reads or a User route, leave Native and rate fields zero to
// reuse its owner and quota. Co-selected Group reads must use the same
// explicit MaximumMembers; zero permits only empty Groups.
type HTTPManagedSCIMGroupsCreateConfiguration struct {
	Native         *ManagedSCIMConnectionConfiguration
	RateNamespace  string
	RateKey        [32]byte
	MaximumMembers int
}

func (HTTPManagedSCIMGroupsCreateConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMGroupsCreateConfiguration(redacted)")
}

func (HTTPManagedSCIMGroupsCreateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMGroupsCreateField}
}

func (c HTTPManagedSCIMGroupsCreateConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

// HTTPManagedSCIMGroupsReplaceConfiguration selects only conditional Group
// PUT. Leave Native and the rate fields zero when another selected Group or
// User route owns them. Co-selected Group routes use the same explicit member
// ceiling; zero permits only empty Groups.
type HTTPManagedSCIMGroupsReplaceConfiguration HTTPManagedSCIMGroupsCreateConfiguration

func (HTTPManagedSCIMGroupsReplaceConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMGroupsReplaceConfiguration(redacted)")
}

func (HTTPManagedSCIMGroupsReplaceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMGroupsReplaceField}
}

func (c HTTPManagedSCIMGroupsReplaceConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

// HTTPManagedSCIMGroupsPatchConfiguration selects only conditional Group PATCH.
// Reuse the selected managed owner, quota and explicit member ceiling when
// composing other Group or User operations.
type HTTPManagedSCIMGroupsPatchConfiguration HTTPManagedSCIMGroupsCreateConfiguration

func (HTTPManagedSCIMGroupsPatchConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMGroupsPatchConfiguration(redacted)")
}

func (HTTPManagedSCIMGroupsPatchConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMGroupsPatchField}
}

func (c HTTPManagedSCIMGroupsPatchConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

type referenceManagedGroupsExecutor struct {
	state  *storeState
	native *scimpg.ManagedConnectionService
}

func (s referenceManagedGroupsExecutor) ExecuteManagedAdmittedGroupRead(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedGroupRead(bounded, tenant, request, maximumMembers, admit)
}

func (s referenceManagedGroupsExecutor) ExecuteManagedAdmittedGroupCreate(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedGroupCreate(bounded, tenant, request, maximumMembers, admit)
}

func (s referenceManagedGroupsExecutor) ExecuteManagedAdmittedGroupReplace(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedGroupReplace(bounded, tenant, request, maximumMembers, admit)
}

func (s referenceManagedGroupsExecutor) ExecuteManagedAdmittedGroupPatch(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedGroupPatch(bounded, tenant, request, maximumMembers, admit)
}
