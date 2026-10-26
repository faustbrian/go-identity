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
	Create, Get, MemberList, MemberAdd, MemberRemove      bool
	Update, MemberUpdate                                  bool
	InvitationGet, InvitationListMine, InvitationList     bool
	InvitationSend, InvitationAccept                      bool
	InvitationResend                                      bool
	InvitationCancel                                      bool
	InvitationExpire                                      bool
	InvitationReject                                      bool
	SlugAvailable                                         bool
	List                                                  bool
	MemberLeave                                           bool
	OwnerTransfer                                         bool
	Archive, Restore                                      bool
	TeamMemberAdd, TeamMemberRemove                       bool
	TeamListMine, TeamMemberList                          bool
	TeamCreate, TeamUpdate, TeamDelete, TeamList          bool
	RoleCreate, RoleUpdate, RoleDelete, RoleGet, RoleList bool
	SafeNamespace                                         string
	EmergencyMaximumKeys                                  int
	Degraded                                              func(context.Context, identityhttp.SafeRateEvent) error
	AdminNamespace                                        string
	AdminKey                                              [32]byte
	Denied                                                func(context.Context, organizationhttp.AdminRateEvent) error
	SecretNamespace                                       string
	SecretKey                                             [32]byte
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
	roleRead := h.RoleGet || h.RoleList
	roleWrite := h.RoleCreate || h.RoleUpdate || h.RoleDelete
	if (roleRead || roleWrite) && (owner == nil || !owner.dynamicRoles) {
		return nil, invalid
	}
	if owner == nil || c.Organization == nil || c.Session == nil || shared == nil || c.HTTPRate == nil || (!h.Create && !h.Update && !h.Get && !h.MemberList && !h.MemberAdd && !h.MemberUpdate && !h.MemberRemove && !h.MemberLeave && !h.OwnerTransfer && !h.Archive && !h.Restore && !h.InvitationGet && !h.InvitationListMine && !h.InvitationList && !h.InvitationSend && !h.InvitationAccept && !h.InvitationResend && !h.InvitationCancel && !h.InvitationExpire && !h.InvitationReject && !h.SlugAvailable && !h.List && !h.TeamMemberAdd && !h.TeamMemberRemove && !h.TeamListMine && !h.TeamMemberList && !h.TeamCreate && !h.TeamUpdate && !h.TeamDelete && !h.TeamList && !roleRead && !roleWrite) || (h.InvitationGet || h.InvitationListMine || h.InvitationList || h.InvitationSend || h.InvitationAccept || h.InvitationResend || h.InvitationCancel || h.InvitationExpire || h.InvitationReject) && owner.invitations == nil || h.OwnerTransfer && (owner.transferProofs == nil || owner.transferAudience == "") || (h.Archive || h.Restore) && (owner.lifecycle == nil || owner.lifecycleProofs == nil || owner.lifecycleAudience == "") || h.InvitationExpire && (c.Organization.Invitations == nil || len(c.Organization.Invitations.Policy.ExpirationReasons) == 0) || (h.TeamMemberAdd || h.TeamMemberRemove || h.TeamListMine || h.TeamMemberList || h.TeamCreate || h.TeamList) && !owner.teams || (h.TeamUpdate || h.TeamDelete) && !owner.teamLifecycle {
		return nil, invalid
	}
	out = &organizationHTTPState{config: h}
	defer func() {
		if err != nil {
			out.close()
			out = nil
		}
	}()
	if h.Get || h.MemberList || h.MemberLeave || h.InvitationGet || h.InvitationListMine || h.InvitationList || h.InvitationReject || h.SlugAvailable || h.List || h.TeamListMine || h.TeamMemberList || h.TeamList || roleRead {
		out.safe, err = identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: shared.backend, Namespace: h.SafeNamespace, Now: time.Now, Degraded: h.Degraded, MaximumDuration: c.HTTPRate.MaximumDuration, EmergencyMaximumKeys: h.EmergencyMaximumKeys})
		if err != nil {
			return out, invalid
		}
	}
	if h.Create || h.Update || h.MemberAdd || h.MemberUpdate || h.MemberRemove || h.InvitationSend || h.InvitationResend || h.InvitationCancel || h.InvitationExpire || h.OwnerTransfer || h.Archive || h.Restore || h.TeamMemberAdd || h.TeamMemberRemove || h.TeamCreate || h.TeamUpdate || h.TeamDelete || roleWrite {
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
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: organizationhttp.Config{Network: network, Sessions: f.session.reader, Service: n.operations, SlugAvailability: n.operations, OrganizationLister: n.operations, MemberLeaver: n.operations, TeamMemberAdder: n.operations, TeamMemberRemover: n.operations, MyTeamLister: n.operations, TeamMemberLister: n.operations, TeamCreator: n.operations, TeamUpdater: n.operations, TeamDeleter: n.operations, TeamLister: n.teamsNative, RoleCreator: n.operations, RoleUpdater: n.operations, RoleDeleter: n.operations, RoleGetter: n.operations, RoleLister: n.operations, OwnerTransferer: n.operations, OwnerTransferProofs: n.transferProofs, OwnerTransferAudience: n.transferAudience, Archiver: n.operations, Restorer: n.operations, LifecycleProofs: n.lifecycleProofs, LifecycleAudience: n.lifecycleAudience, MetadataUpdater: n.operations, MemberUpdater: n.operations, Invitations: n.invitations, InvitationLister: n.invitations, InvitationSender: n.sender, InvitationResender: n.sender, InvitationCanceller: n.invitations, InvitationExpirer: n.invitations, InvitationRejecter: n.invitations, InvitationAccepter: n.invitations, InvitationProofLimits: n.limits, SafeRate: h.safe, AdminRate: h.admin, SecretRate: h.secret, Now: time.Now, MaximumDuration: n.maximum}, Create: selected.Create, Update: selected.Update, Get: selected.Get, MemberList: selected.MemberList, MemberAdd: selected.MemberAdd, MemberUpdate: selected.MemberUpdate, MemberRemove: selected.MemberRemove, MemberLeave: selected.MemberLeave, OwnerTransfer: selected.OwnerTransfer, Archive: selected.Archive, Restore: selected.Restore, TeamMemberAdd: selected.TeamMemberAdd, TeamMemberRemove: selected.TeamMemberRemove, TeamListMine: selected.TeamListMine, TeamMemberList: selected.TeamMemberList, TeamCreate: selected.TeamCreate, TeamUpdate: selected.TeamUpdate, TeamDelete: selected.TeamDelete, TeamList: selected.TeamList, RoleCreate: selected.RoleCreate, RoleUpdate: selected.RoleUpdate, RoleDelete: selected.RoleDelete, RoleGet: selected.RoleGet, RoleList: selected.RoleList, InvitationGet: selected.InvitationGet, InvitationListMine: selected.InvitationListMine, InvitationList: selected.InvitationList, InvitationSend: selected.InvitationSend, InvitationAccept: selected.InvitationAccept, InvitationResend: selected.InvitationResend, InvitationCancel: selected.InvitationCancel, InvitationExpire: selected.InvitationExpire, InvitationReject: selected.InvitationReject, SlugAvailable: selected.SlugAvailable, List: selected.List})
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
