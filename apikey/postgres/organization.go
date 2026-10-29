package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

type organizationComposition struct {
	repository  *organizationpg.Repository
	observation *organization.CredentialAuthorityObservation
}

// NewOrganizationService explicitly selects the actual native organization
// authority owner in addition to the existing session/key owners. Install both
// owners' optional organization-credential migrations before use. The repository
// and pool remain caller-owned; no domain-store callbacks or worker are created.
func NewOrganizationService(pool *database.Pool, config ServiceConfig, repository *organizationpg.Repository) (*Service, error) {
	if repository == nil {
		return nil, apikey.ErrInvalid
	}
	service, err := NewService(pool, config)
	if err != nil {
		return nil, err
	}
	service.organization = &organizationComposition{repository: repository}
	return service, nil
}

// CreateOrganization selects a genuine current human manager independently of
// credential ownership. An unselected service denies; no fallback self key is
// issued. Original idempotency, reveal-once and unknown recovery remain native.
func (s *Service) CreateOrganization(ctx context.Context, request apikey.OrganizationCreateRequest) (apikey.IssuanceResult, error) {
	if ctx == nil || s == nil || s.organization == nil || request.Validate() != nil {
		return apikey.IssuanceResult{}, apikey.ErrDenied
	}
	selected := *s
	selected.organizationID = request.OrganizationID
	result, err := selected.manage(ctx, request.CreateRequest, nil, false, nil)
	return selected.issuance(result, err)
}

// RecoverOrganization authorizes the exact target organization and original
// human scope without requiring an already committed key row. Preserve the
// target alongside original recovery metadata: a missing key does not prove
// noncommit. The target is bound by original authenticated request custody;
// another organization cannot decode that preparation or disclose its result.
func (s *Service) RecoverOrganization(ctx context.Context, id apikey.OrganizationID, request apikey.RecoveryRequest) (identity.CommandResult, error) {
	if s == nil || s.organization == nil || id == "" {
		return identity.CommandResult{}, apikey.ErrDenied
	}
	selected := *s
	selected.organizationID = id
	return selected.Recover(ctx, request)
}

func organizationManagementOperation(id string) identity.FeatureOperation {
	op := operationFor(id)
	switch id {
	case "identity.apikey.create":
		op.SchemaID = "apikey-create-organization-v1"
	case "identity.apikey.rotate":
		op.SchemaID = "apikey-rotate-organization-v1"
	case "identity.apikey.delete":
		op.SchemaID = "apikey-revoke-organization-v1"
	case "identity.apikey.import":
		op.SchemaID = "apikey-import-organization-v1"
	}
	return op
}

func managementOperationForBinding(b identity.CommandBinding) identity.FeatureOperation {
	op := organizationManagementOperation(b.OperationID)
	if op.SchemaID == b.SchemaID {
		return op
	}
	return operationFor(b.OperationID)
}

func (s *Service) managementOperation(id string) identity.FeatureOperation {
	if s != nil && s.organizationID != "" {
		return organizationManagementOperation(id)
	}
	return operationFor(id)
}

func (s *Service) selectOrganization(ctx context.Context, tenant identity.TenantID, actor identity.UserID, id apikey.OrganizationID, action, correlation string) (*Service, error) {
	if s.organization == nil || s.organization.repository == nil || id == "" {
		return nil, apikey.ErrDenied
	}
	query := organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: organization.ID(id), ActorID: actor}
	observed, err := s.organization.repository.ObserveCredentialAuthority(ctx, query)
	if errors.Is(err, organization.ErrForbidden) {
		return nil, apikey.ErrDenied
	}
	if err != nil {
		return nil, nativeError(ctx, err)
	}
	if observed.Validate(query, s.config().Clock.Now()) != nil {
		return nil, apikey.ErrDenied
	}
	selected := *s
	selected.organizationID = id
	selected.organization = &organizationComposition{repository: s.organization.repository, observation: &observed}
	if err := selected.allow(ctx, selected.organizationDecision(tenant, authorization.SubjectUser, string(actor), action, correlation)); err != nil {
		return nil, err
	}
	return &selected, nil
}

func (s *Service) organizationDecision(tenant identity.TenantID, kind authorization.SubjectKind, actor, action, correlation string) authorization.DecisionContext {
	version := uint64(0)
	credential := uint64(0)
	if s.organization != nil && s.organization.observation != nil {
		version = s.organization.observation.Version
		credential = s.organization.observation.CredentialVersion
	}
	return authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config().PolicyVersion), CorrelationID: correlation, Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: kind, ID: authorization.SubjectID(actor)}, Action: authorization.Action(action), Resource: authorization.Resource{Type: "organization-api-key", ID: authorization.ResourceID(s.organizationID), Attributes: authorization.Attributes{"organization.version": authorization.StringValue(strconv.FormatUint(version, 10)), "organization.credential-version": authorization.StringValue(strconv.FormatUint(credential, 10)), "api-key.configuration-id": authorization.StringValue(s.config().Configuration.Spec().ID), "api-key.configuration-revision": authorization.StringValue(strconv.FormatUint(s.config().Configuration.Spec().Revision, 10)), "api-key.policy-version": authorization.StringValue(strconv.FormatUint(s.config().PolicyVersion, 10))}}}}
}

func (s *Service) organizationCreateIntent(r apikey.CreateRequest) (identity.RequestIntent, error) {
	base, err := s.createIntent(r)
	fields, ok := base.Fields()
	if err != nil || !ok {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	wire, err := json.Marshal(struct {
		Owner  apikey.OrganizationID
		Fields []identity.FeatureField
	}{s.organizationID, fields})
	if err != nil {
		return identity.RequestIntent{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return identity.NewRequestIntent([]identity.FeatureField{{Name: "apikey.create.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}})
}

func (s *Service) managementOwnerMatches(record apikey.Record, b identity.CommandBinding) bool {
	owner := record.Owner.Spec()
	if owner.Kind == apikey.OwnerUser {
		return owner.UserID == b.UserID && managementOperationForBinding(b) == operationFor(b.OperationID)
	}
	return owner.Kind == apikey.OwnerOrganization && s.organization != nil && s.organizationID != "" && owner.OrganizationID == s.organizationID && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID) && managementOperationForBinding(b) == organizationManagementOperation(b.OperationID)
}
