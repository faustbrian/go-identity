package reference

import (
	"context"
	"fmt"
	"io"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// HTTPOrganizationConfiguration opts into each bearer-only organization route
// independently. It requires native Organization and the shared strong HTTPRate
// owner; invitation selections additionally require native Invitations. Safe
// read degradation and administrative denial auditing are synchronous bounded
// callbacks with exactly the native transport contracts. Denied must durably
// record every rejection/unavailable event without secrets. Namespace/key changes
// reset effective budgets and must be coordinated across administrative routes.
type HTTPOrganizationConfiguration struct {
	Create, Get, MemberList, MemberAdd, MemberRemove bool
	Update, MemberUpdate                             bool
	InvitationGet, InvitationListMine                bool
	InvitationSend, InvitationAccept                 bool
	InvitationResend                                 bool
	InvitationCancel                                 bool
	InvitationReject                                 bool
	SafeNamespace                                    string
	EmergencyMaximumKeys                             int
	Degraded                                         func(context.Context, identityhttp.SafeRateEvent) error
	AdminNamespace                                   string
	AdminKey                                         [32]byte
	Denied                                           func(context.Context, organizationhttp.AdminRateEvent) error
	SecretNamespace                                  string
	SecretKey                                        [32]byte
}

// Format redacts shared rate keys and deployment callbacks.
func (HTTPOrganizationConfiguration) Format(s fmt.State, _ rune) {
	io.WriteString(s, "reference.HTTPOrganizationConfiguration(redacted)")
}

// MarshalJSON rejects serialization of deployment secrets.
func (HTTPOrganizationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects serialization of deployment secrets.
func (HTTPOrganizationConfiguration) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

type organizationHTTPState struct {
	config HTTPOrganizationConfiguration
	safe   *identityhttp.SafeRateLimiter
	admin  *organizationhttp.AdminRateLimiter
	secret *identityhttp.KeyedSecretRateLimiter
}

func (h *organizationHTTPState) close() {
	if h == nil {
		return
	}
	if h.safe != nil {
		h.safe.Close()
	}
	if h.admin != nil {
		h.admin.Close()
	}
	if h.secret != nil {
		h.secret.Close()
	}
}

func composeOrganizationHTTP(c StoreConfiguration, owner *organizationState, shared *httpRateState) (out *organizationHTTPState, err error) {
	if c.HTTPOrganization == nil {
		return nil, nil
	}
	h := *c.HTTPOrganization
	invalid := identity.InvalidInputError{Field: "reference_http_organization"}
	if owner == nil || c.Organization == nil || c.Session == nil || shared == nil || c.HTTPRate == nil || (!h.Create && !h.Update && !h.Get && !h.MemberList && !h.MemberAdd && !h.MemberUpdate && !h.MemberRemove && !h.InvitationGet && !h.InvitationListMine && !h.InvitationSend && !h.InvitationAccept && !h.InvitationResend && !h.InvitationCancel && !h.InvitationReject) || (h.InvitationGet || h.InvitationListMine || h.InvitationSend || h.InvitationAccept || h.InvitationResend || h.InvitationCancel || h.InvitationReject) && owner.invitations == nil {
		return nil, invalid
	}
	out = &organizationHTTPState{config: h}
	defer func() {
		if err != nil {
			out.close()
			out = nil
		}
	}()
	if h.Get || h.MemberList || h.InvitationGet || h.InvitationListMine || h.InvitationReject {
		out.safe, err = identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: h.SafeNamespace, Now: time.Now, Degraded: h.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: h.EmergencyMaximumKeys})
		if err != nil {
			return out, invalid
		}
	}
	if h.Create || h.Update || h.MemberAdd || h.MemberUpdate || h.MemberRemove || h.InvitationSend || h.InvitationResend || h.InvitationCancel {
		out.admin, err = organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: shared.backend, Namespace: h.AdminNamespace, Key: h.AdminKey, Now: time.Now, Denied: h.Denied, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return out, invalid
		}
	}
	if h.InvitationAccept {
		out.secret, err = identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: shared.backend, Namespace: h.SecretNamespace, Key: h.SecretKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			return out, invalid
		}
	}
	return out, nil
}

func (s *Server) organizationFeature(network identityhttp.NetworkConfig) (*identityhttp.Feature, error) {
	f := s.state.features
	if f == nil || f.httpOrganization == nil {
		return nil, nil
	}
	h, n := f.httpOrganization, f.organization
	if n == nil || f.session == nil {
		return nil, identity.InvalidInputError{Field: "reference_http_organization"}
	}
	selected := h.config
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: organizationhttp.Config{Network: network, Sessions: f.session.reader, Service: n.operations, MetadataUpdater: n.operations, MemberUpdater: n.operations, Invitations: n.invitations, InvitationSender: n.sender, InvitationResender: n.sender, InvitationCanceller: n.invitations, InvitationRejecter: n.invitations, InvitationAccepter: n.invitations, InvitationProofLimits: n.limits, SafeRate: h.safe, AdminRate: h.admin, SecretRate: h.secret, Now: time.Now, MaximumDuration: n.maximum}, Create: selected.Create, Update: selected.Update, Get: selected.Get, MemberList: selected.MemberList, MemberAdd: selected.MemberAdd, MemberUpdate: selected.MemberUpdate, MemberRemove: selected.MemberRemove, InvitationGet: selected.InvitationGet, InvitationListMine: selected.InvitationListMine, InvitationSend: selected.InvitationSend, InvitationAccept: selected.InvitationAccept, InvitationResend: selected.InvitationResend, InvitationCancel: selected.InvitationCancel, InvitationReject: selected.InvitationReject})
	if err != nil {
		return nil, err
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		return nil, err
	}
	for i := range ops {
		// Reuse the graph's existing drain wrapper, including binding the leaf's
		// real middleware phases. It neither prepares nor renews native custody.
		ops[i].Handler = &passkeyLifetimeHandler{state: s.state, next: ops[i].Handler}
	}
	feature, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "organization", Operations: ops})
	return &feature, err
}
