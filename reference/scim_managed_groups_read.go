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
