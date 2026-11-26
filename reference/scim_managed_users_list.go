package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

const (
	managedSCIMUsersListField    = "reference_http_managed_scim_users_list"
	managedSCIMUsersGetField     = "reference_http_managed_scim_users_get"
	managedSCIMUsersCreateField  = "reference_http_managed_scim_users_create"
	managedSCIMUsersDeleteField  = "reference_http_managed_scim_users_delete"
	managedSCIMUsersPatchField   = "reference_http_managed_scim_users_patch"
	managedSCIMUsersReplaceField = "reference_http_managed_scim_users_replace"
)

// HTTPManagedSCIMUsersListConfiguration selects GET /scim/v2/Users using
// existing managed SCIM bearers. Supply Native only when managed HTTP Create
// is disabled; otherwise borrow that exact native owner. If SCIMBulk is
// selected leave RateNamespace and RateKey zero to reuse its protocol quota.
// Without Bulk, supply a stable dedicated namespace and key for all instances.
type HTTPManagedSCIMUsersListConfiguration struct {
	Native        *ManagedSCIMConnectionConfiguration
	RateNamespace string
	RateKey       [32]byte
}

// HTTPManagedSCIMUsersGetConfiguration selects only
// GET /scim/v2/Users/{resource_id} with a managed bearer. With List selected,
// all fields must be zero to adopt the same native owner and protocol quota.
// Otherwise the native and rate settings follow the List configuration rules.
type HTTPManagedSCIMUsersGetConfiguration HTTPManagedSCIMUsersListConfiguration

// HTTPManagedSCIMUsersCreateConfiguration selects only POST /scim/v2/Users
// with an issued managed bearer. With List or Get selected, all fields must
// be zero to adopt their exact native owner and protocol quota. Otherwise
// native and rate settings follow the List configuration rules.
type HTTPManagedSCIMUsersCreateConfiguration HTTPManagedSCIMUsersListConfiguration

// HTTPManagedSCIMUsersDeleteConfiguration selects only conditional
// DELETE /scim/v2/Users/{resource_id} with an issued managed bearer. With List,
// Get or Create selected, leave all fields zero to use their native owner and
// protocol quota. Otherwise follow the List configuration rules.
type HTTPManagedSCIMUsersDeleteConfiguration HTTPManagedSCIMUsersListConfiguration

// HTTPManagedSCIMUsersPatchConfiguration selects only conditional
// PATCH /scim/v2/Users/{resource_id} with an issued managed bearer. With List,
// Get, Create or Delete selected, leave all fields zero to use that route's
// native owner and protocol quota. Otherwise follow the List rules.
type HTTPManagedSCIMUsersPatchConfiguration HTTPManagedSCIMUsersListConfiguration

// HTTPManagedSCIMUsersReplaceConfiguration selects only conditional
// PUT /scim/v2/Users/{resource_id} with an issued managed bearer. If another
// User route is selected, leave all fields zero to use its native owner and
// quota. For standalone use, follow the List configuration rules.
type HTTPManagedSCIMUsersReplaceConfiguration HTTPManagedSCIMUsersListConfiguration

// ManagedSCIMConnectionConfiguration selects the primary owner and retained
// credential/profile keys for an existing managed SCIM connection. Provisioning
// supplies field policy and the current service principal, not a configured
// connection or plaintext bearer. It must match the issuance deployment.
type ManagedSCIMConnectionConfiguration struct {
	Authorization      authorization.Service
	PolicyVersion      uint64
	MaximumDuration    time.Duration
	CursorKey          [32]byte
	Provisioning       scimpg.Config
	CredentialKey      [32]byte
	CredentialLifetime time.Duration
}

func (HTTPManagedSCIMUsersListConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersListConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersListConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersListField}
}

func (c HTTPManagedSCIMUsersListConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

func (HTTPManagedSCIMUsersGetConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersGetConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersGetConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersGetField}
}

func (c HTTPManagedSCIMUsersGetConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

func (HTTPManagedSCIMUsersCreateConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersCreateConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersCreateConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersCreateField}
}

func (c HTTPManagedSCIMUsersCreateConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

func (HTTPManagedSCIMUsersDeleteConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersDeleteConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersDeleteConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersDeleteField}
}

func (c HTTPManagedSCIMUsersDeleteConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

func (HTTPManagedSCIMUsersPatchConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersPatchConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersPatchConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersPatchField}
}

func (c HTTPManagedSCIMUsersPatchConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

func (HTTPManagedSCIMUsersReplaceConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.HTTPManagedSCIMUsersReplaceConfiguration(redacted)")
}

func (HTTPManagedSCIMUsersReplaceConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersReplaceField}
}

func (c HTTPManagedSCIMUsersReplaceConfiguration) MarshalText() ([]byte, error) {
	return c.MarshalJSON()
}

func (ManagedSCIMConnectionConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.ManagedSCIMConnectionConfiguration(redacted)")
}

func (ManagedSCIMConnectionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersListField}
}

func (c ManagedSCIMConnectionConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

type managedSCIMUsersState struct {
	native          *scimpg.ManagedConnectionService
	rate            scimhttp.ProtocolRateConfig
	limits          scim.Limits
	maximum         time.Duration
	get             bool
	list            bool
	createUser      bool
	deleteUser      bool
	patchUser       bool
	replaceUser     bool
	getGroup        bool
	listGroups      bool
	maxGroupMembers int
}

func managedSCIMUsersOptions(c StoreConfiguration) (*HTTPManagedSCIMUsersListConfiguration, string, error) {
	// The first enabled route owns the common profile. Additional enabled
	// routes must adopt that owner, never supply a competing native/rate graph.
	var owner *HTTPManagedSCIMUsersListConfiguration
	field := managedSCIMUsersListField
	for _, option := range [...]struct {
		profile *HTTPManagedSCIMUsersListConfiguration
		field   string
	}{
		{c.HTTPManagedSCIMUsersList, managedSCIMUsersListField},
		{(*HTTPManagedSCIMUsersListConfiguration)(c.HTTPManagedSCIMUsersGet), managedSCIMUsersGetField},
		{(*HTTPManagedSCIMUsersListConfiguration)(c.HTTPManagedSCIMUsersCreate), managedSCIMUsersCreateField},
		{(*HTTPManagedSCIMUsersListConfiguration)(c.HTTPManagedSCIMUsersDelete), managedSCIMUsersDeleteField},
		{(*HTTPManagedSCIMUsersListConfiguration)(c.HTTPManagedSCIMUsersPatch), managedSCIMUsersPatchField},
		{(*HTTPManagedSCIMUsersListConfiguration)(c.HTTPManagedSCIMUsersReplace), managedSCIMUsersReplaceField},
	} {
		if option.profile == nil {
			continue
		}
		if owner == nil {
			profile := *option.profile
			owner, field = &profile, option.field
			continue
		}
		if *option.profile != (HTTPManagedSCIMUsersListConfiguration{}) {
			return nil, option.field, identity.InvalidInputError{Field: option.field}
		}
	}
	if groups := c.HTTPManagedSCIMGroupsRead; groups != nil {
		invalid := identity.InvalidInputError{Field: managedSCIMGroupsReadField}
		if !groups.EnableGet && !groups.EnableList || groups.MaximumMembers < 0 || groups.MaximumMembers > scim.DefaultGroupMembers {
			return nil, managedSCIMGroupsReadField, invalid
		}
		profile := HTTPManagedSCIMUsersListConfiguration{
			Native: groups.Native, RateNamespace: groups.RateNamespace, RateKey: groups.RateKey,
		}
		if owner == nil {
			return &profile, managedSCIMGroupsReadField, nil
		}
		if profile != (HTTPManagedSCIMUsersListConfiguration{}) {
			return nil, managedSCIMGroupsReadField, invalid
		}
	}
	return owner, field, nil
}

func validateManagedSCIMUsers(c StoreConfiguration) error {
	n, field, err := managedSCIMUsersOptions(c)
	if err != nil {
		return err
	}
	if n == nil {
		return nil
	}
	invalid := identity.InvalidInputError{Field: field}
	if c.HTTPRate == nil || c.Organization == nil || c.Session == nil || c.OTP == nil ||
		c.ProviderDiscovery != nil || c.OAuthWorkload != nil || c.Passkey != nil && c.Passkey.Standalone != nil {
		return invalid
	}
	if (n.Native != nil) == (c.HTTPManagedSCIMCreate != nil) {
		return invalid
	}
	if c.SCIMBulk != nil {
		if n.RateNamespace != "" || n.RateKey != ([32]byte{}) {
			return invalid
		}
	} else if !validDirectorySelector(n.RateNamespace) || n.RateKey == ([32]byte{}) {
		return invalid
	}
	return nil
}

func composeManagedSCIMConnection(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, org *organizationState, n ManagedSCIMConnectionConfiguration) (*scimpg.ManagedConnectionService, error) {
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || sessions == nil || !sessions.reader.Configured() || org == nil || nilServerDependency(n.Authorization) {
		return nil, scimpg.ErrInvalidConfiguration
	}
	execution := c.Session.Native.Execution
	if n.Provisioning.GlobalAuthorityID != c.OTP.Store.GlobalAuthorityID || n.Provisioning.AuthorityNamespace != execution.Profile.PolicyNamespace {
		return nil, scimpg.ErrInvalidConfiguration
	}
	return scimpg.NewManagedConnectionService(d.PostgreSQL, scimpg.ManagedConnectionServiceConfig{
		Sessions: sessions.reader, Authorization: n.Authorization, PolicyVersion: n.PolicyVersion,
		MaximumDuration: n.MaximumDuration, CursorKey: n.CursorKey, Limits: n.Provisioning.Limits,
		Writes: &scimpg.ManagedConnectionWriteConfig{SessionStorage: execution.Repository, Provisioning: n.Provisioning,
			Keyring: keys, CredentialKey: n.CredentialKey, CredentialLifetime: n.CredentialLifetime},
	})
}

func (s *storeState) composeManagedSCIMUsers(c StoreConfiguration, d ReferenceDependencies, sessions *sessionState, org *organizationState, create *managedSCIMCreateState, bulk *scimBulkState) (*managedSCIMUsersState, error) {
	n, field, err := managedSCIMUsersOptions(c)
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, nil
	}
	if s.httpRate == nil {
		return nil, identity.InvalidInputError{Field: field}
	}
	selected := managedSCIMUsersState{
		get:         c.HTTPManagedSCIMUsersGet != nil,
		list:        c.HTTPManagedSCIMUsersList != nil,
		createUser:  c.HTTPManagedSCIMUsersCreate != nil,
		deleteUser:  c.HTTPManagedSCIMUsersDelete != nil,
		patchUser:   c.HTTPManagedSCIMUsersPatch != nil,
		replaceUser: c.HTTPManagedSCIMUsersReplace != nil,
	}
	if groups := c.HTTPManagedSCIMGroupsRead; groups != nil {
		selected.getGroup, selected.listGroups = groups.EnableGet, groups.EnableList
		selected.maxGroupMembers = groups.MaximumMembers
	}
	if bulk != nil {
		selected.rate = bulk.rate
	} else {
		selected.rate = scimhttp.ProtocolRateConfig{Shared: s.httpRate.backend, Namespace: n.RateNamespace,
			Key: n.RateKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration}
	}
	if create != nil {
		selected.native, selected.limits, selected.maximum = create.native, create.limits, create.maximum
		return &selected, nil
	}
	profile := *n.Native
	native, err := composeManagedSCIMConnection(c, d, sessions, org, profile)
	if err != nil {
		return nil, identity.InvalidInputError{Field: field}
	}
	selected.native, selected.limits, selected.maximum = native, profile.Provisioning.Limits, profile.MaximumDuration
	return &selected, nil
}

type referenceManagedUsersExecutor struct {
	state  *storeState
	native *scimpg.ManagedConnectionService
}

func (s referenceManagedUsersExecutor) ExecuteManagedAdmittedRead(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedRead(bounded, tenant, request, admit)
}

func (s referenceManagedUsersExecutor) ExecuteManagedAdmittedCreate(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedCreate(bounded, tenant, request, admit)
}

func (s referenceManagedUsersExecutor) ExecuteManagedAdmittedDelete(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedDelete(bounded, tenant, request, admit)
}

func (s referenceManagedUsersExecutor) ExecuteManagedAdmittedPatch(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedPatch(bounded, tenant, request, admit)
}

func (s referenceManagedUsersExecutor) ExecuteManagedAdmittedReplace(ctx context.Context, tenant identity.TenantID, request scim.Request, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteManagedAdmittedReplace(bounded, tenant, request, admit)
}

func (s *Server) managedSCIMUsersOperations(network identityhttp.NetworkConfig) ([]identityhttp.OperationDescriptor, error) {
	selected := s.state.features.httpManagedSCIMUsers
	executor := referenceManagedUsersExecutor{state: s.state, native: selected.native}
	var operations []identityhttp.OperationDescriptor
	if selected.list {
		feature, err := scimhttp.NewManagedUsersListFeature(scimhttp.ManagedUsersListConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersListField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.get {
		feature, err := scimhttp.NewManagedUsersGetFeature(scimhttp.ManagedUsersGetConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersGetField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.createUser {
		feature, err := scimhttp.NewManagedUsersCreateFeature(scimhttp.ManagedUsersCreateConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersCreateField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.deleteUser {
		feature, err := scimhttp.NewManagedUsersDeleteFeature(scimhttp.ManagedUsersDeleteConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersDeleteField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.patchUser {
		feature, err := scimhttp.NewManagedUsersPatchFeature(scimhttp.ManagedUsersPatchConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersPatchField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.replaceUser {
		feature, err := scimhttp.NewManagedUsersReplaceFeature(scimhttp.ManagedUsersReplaceConfig{
			Network: network, Executor: executor, Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMUsersReplaceField}
		}
		operations = append(operations, feature.Operations()...)
	}
	if selected.getGroup || selected.listGroups {
		feature, err := scimhttp.NewManagedGroupsReadFeature(scimhttp.ManagedGroupsReadConfig{
			Network: network, Executor: referenceManagedGroupsExecutor{state: s.state, native: selected.native},
			Rate: selected.rate, Limits: selected.limits, MaximumDuration: selected.maximum,
			MaximumMembers: selected.maxGroupMembers, EnableGet: selected.getGroup, EnableList: selected.listGroups,
		})
		if err != nil {
			return nil, identity.InvalidInputError{Field: managedSCIMGroupsReadField}
		}
		operations = append(operations, feature.Operations()...)
	}
	return operations, nil
}
