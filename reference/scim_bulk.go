package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// SCIMBulkConfiguration selects one preprovisioned native SCIM client and its
// Bulk and matching discovery routes. Reference owns the shared PostgreSQL
// rate backend; RateNamespace and RateKey are stable deployment settings
// shared by all instances. Native scope must name an existing organization
// in a Reference tenant and use that graph's directory authority and keyring.
// No route issues, rotates or grants a bearer, or installs resource CRUD.
type SCIMBulkConfiguration struct {
	Native              scimpg.Config
	MaximumGroupMembers int
	Request             scim.BulkPolicy
	Response            scim.BulkResponsePolicy
	RateNamespace       string
	RateKey             [32]byte
}

// Format redacts bearer digest and quota key custody.
func (SCIMBulkConfiguration) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "reference.SCIMBulkConfiguration(redacted)")
}

// MarshalJSON forbids serialization of deployment credential custody.
func (SCIMBulkConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "reference_scim_bulk"}
}

type scimBulkState struct {
	native   *scimpg.Service
	executor *scimpg.BulkService
	tenant   identity.TenantID
	rate     scimhttp.ProtocolRateConfig
	maximum  time.Duration
}

func (s *storeState) composeSCIMBulk(c StoreConfiguration, d ReferenceDependencies) (*scimBulkState, error) {
	if c.SCIMBulk == nil {
		return nil, nil
	}
	selected := *c.SCIMBulk
	tenant := selected.Native.Scope.TenantID
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	invalid := identity.InvalidInputError{Field: "reference_scim_bulk"}
	if !ok || keys == nil || s.tenants[string(tenant)] == nil || s.httpRate == nil ||
		!validDirectorySelector(selected.RateNamespace) || selected.RateKey == ([32]byte{}) {
		return nil, invalid
	}
	native, err := scimpg.NewService(d.PostgreSQL, selected.Native, keys)
	if err != nil {
		return nil, invalid
	}
	groups, err := scimpg.NewGroupsService(native, selected.MaximumGroupMembers)
	if err != nil {
		return nil, invalid
	}
	bulk, err := scimpg.NewBulkService(groups, selected.Request, selected.Response)
	if err != nil {
		return nil, invalid
	}
	return &scimBulkState{
		native: native, executor: bulk.WithTypedValidation(), tenant: tenant, maximum: selected.Native.MaximumDuration,
		rate: scimhttp.ProtocolRateConfig{Shared: s.httpRate.backend, Namespace: selected.RateNamespace,
			Key: selected.RateKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration},
	}, nil
}

// InitializeSCIMBulkConnection provisions the selected native connection
// explicitly after migrations, organization creation, and service-account
// authority provisioning. It does not create or reset any authority.
// Repeat the same call to recover an uncertain original outcome; it cannot
// rotate, reactivate, or overwrite a connection. No bearer is returned.
func (s StoreSet) InitializeSCIMBulkConnection(ctx context.Context) (scimpg.ConfiguredConnectionResult, error) {
	bounded, done, err := s.state.enterFeature(ctx, false)
	if err != nil {
		return scimpg.ConfiguredConnectionResult{}, err
	}
	defer done()
	selected := s.state.features.scimBulk
	if selected == nil {
		return scimpg.ConfiguredConnectionResult{}, identity.UnavailableError{}
	}
	return selected.native.InitializeConfiguredConnection(bounded)
}

type referenceSCIMBulkExecutor struct {
	state  *storeState
	native *scimpg.BulkService
}

func (s referenceSCIMBulkExecutor) BulkPolicies() (scim.BulkPolicy, scim.BulkResponsePolicy) {
	return s.native.BulkPolicies()
}

func (s referenceSCIMBulkExecutor) ExecuteBulkProtocol(ctx context.Context, r scim.BulkRequest, admit scim.ProtocolAdmission) ([]byte, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return nil, scim.NewError(503, "")
	}
	defer done()
	return s.native.ExecuteBulkProtocol(bounded, r, admit)
}

func (s referenceSCIMBulkExecutor) ReadBulkServiceProviderConfig(ctx context.Context, credential authentication.BearerCredential, admit scim.ProtocolAdmission) (scim.Response, error) {
	bounded, done, err := s.state.enterFeature(ctx, true)
	if err != nil {
		return scim.Response{}, scim.NewError(503, "")
	}
	defer done()
	return s.native.ReadBulkServiceProviderConfig(bounded, credential, admit)
}

func (s *Server) scimBulkFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	selected := s.state.features.scimBulk
	if selected == nil {
		return nil, nil
	}
	if !slices.ContainsFunc(network.TenantHosts, func(host identityhttp.TenantHost) bool { return host.TenantID == selected.tenant }) {
		return nil, identity.InvalidInputError{Field: "reference_scim_bulk_host"}
	}
	feature, err := scimhttp.NewBulkFeature(scimhttp.BulkFeatureConfig{Network: network,
		Executor: referenceSCIMBulkExecutor{state: s.state, native: selected.executor},
		Rate:     selected.rate, MaximumDuration: selected.maximum})
	if err != nil {
		return nil, identity.InvalidInputError{Field: "reference_scim_bulk"}
	}
	return &feature, nil
}

func writeSCIMBulkGuardError(w http.ResponseWriter, status int) {
	body, _ := json.Marshal(scim.NewError(status, ""))
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
