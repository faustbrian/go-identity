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
	managedSCIMUsersListField = "reference_http_managed_scim_users_list"
	managedSCIMUsersGetField  = "reference_http_managed_scim_users_get"
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

func (ManagedSCIMConnectionConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.ManagedSCIMConnectionConfiguration(redacted)")
}

func (ManagedSCIMConnectionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: managedSCIMUsersListField}
}

func (c ManagedSCIMConnectionConfiguration) MarshalText() ([]byte, error) { return c.MarshalJSON() }

type managedSCIMUsersState struct {
	native  *scimpg.ManagedConnectionService
	rate    scimhttp.ProtocolRateConfig
	limits  scim.Limits
	maximum time.Duration
	get     bool
	list    bool
}

func managedSCIMUsersOptions(c StoreConfiguration) (*HTTPManagedSCIMUsersListConfiguration, string, error) {
	get, list := c.HTTPManagedSCIMUsersGet, c.HTTPManagedSCIMUsersList
	if get == nil {
		return list, managedSCIMUsersListField, nil
	}
	if list == nil {
		profile := HTTPManagedSCIMUsersListConfiguration(*get)
		return &profile, managedSCIMUsersGetField, nil
	}
	if *get != (HTTPManagedSCIMUsersGetConfiguration{}) {
		return nil, managedSCIMUsersGetField, identity.InvalidInputError{Field: managedSCIMUsersGetField}
	}
	return list, managedSCIMUsersListField, nil
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
	selected := managedSCIMUsersState{get: c.HTTPManagedSCIMUsersGet != nil, list: c.HTTPManagedSCIMUsersList != nil}
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
	return operations, nil
}
