package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// ProviderRefreshResult is the immutable original outcome, not a grant or
// an assertion about the provider's current state. Rejected means that the
// provider refused the original grant and it was retired locally. An unknown
// error may include the original CommandID but does not include any result.
type ProviderRefreshResult struct {
	CommandID       identity.CommandID
	BeforeVersion   uint64
	AfterVersion    uint64
	AccessExpiresAt time.Time
	Rejected        bool
}

// ProviderRefreshService opts selected existing ordinary OAuth2 providers into
// stored refresh without adding refresh to LinkService defaults or installing
// any HTTP route. The original LinkService and its providers are borrowed.
type ProviderRefreshService struct {
	link      *LinkService
	providers map[string]*oauth.OAuth2RefreshProvider
	profile   [32]byte
}

// NewProviderRefreshService selects refresh only for the named providers
// already configured on link. It performs no I/O and keeps a private selection.
func NewProviderRefreshService(link *LinkService, providerIDs []string) (*ProviderRefreshService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_refresh_configuration"}
	if link == nil || link.config == nil || len(providerIDs) == 0 || len(providerIDs) > 64 {
		return nil, invalid
	}
	if link.counters.ValidateCounterOnlyOperation(risk.Action(providerRefreshOperation().OperationID)) != nil {
		// This service has no external signal producer. A richer configured
		// risk policy must not silently fall back to counters.
		return nil, invalid
	}
	ids := slices.Clone(providerIDs)
	slices.Sort(ids)
	providers, err := selectProviderRefreshProviders(link.config().Providers, ids)
	if err != nil {
		return nil, err
	}
	s := &ProviderRefreshService{link: link, providers: providers}
	encoding, err := json.Marshal(struct {
		Profile   [32]byte
		Providers []string
	}{link.profile, ids})
	if err != nil {
		return nil, invalid
	}
	s.profile = sha256.Sum256(encoding)
	return s, nil
}

func selectProviderRefreshProviders(configured []oauth.Provider, ids []string) (map[string]*oauth.OAuth2RefreshProvider, error) {
	invalid := identity.InvalidInputError{Field: "oauth_refresh_providers"}
	if len(ids) == 0 {
		return nil, invalid
	}
	providers := make(map[string]*oauth.OAuth2RefreshProvider, len(ids))
	for _, id := range ids {
		if id == "" || providers[id] != nil {
			return nil, invalid
		}
		var selected *oauth.OAuth2UserInfoProvider
		for _, p := range configured {
			if p.ID() == id {
				selected, _ = p.(*oauth.OAuth2UserInfoProvider)
				break
			}
		}
		refresh, err := oauth.NewOAuth2RefreshProvider(selected)
		if err != nil {
			return nil, invalid
		}
		providers[id] = refresh
	}
	return providers, nil
}

func (*ProviderRefreshService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.ProviderRefreshService(redacted)"))
}

func (*ProviderRefreshService) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "oauth_refresh_service"}
}

func (*ProviderRefreshService) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "oauth_refresh_service"}
}

func (s *ProviderRefreshService) intent(r ProviderRefreshRequest) (identity.RequestIntent, error) {
	return identity.NewRequestIntent([]identity.FeatureField{
		{Name: "refresh.account", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.Account)}},
		{Name: "refresh.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}},
		{Name: "refresh.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedVersion}},
	})
}

func (s *ProviderRefreshService) coordinator(p *providerRefreshPhase) (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	link := s.link
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{link.directory, auditing, lifecycle, link.counters, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(link.pool, registry, link.config().Coordinator, link.requestKey)
	return coordinator, registry, err
}

// Refresh authenticates the current owner before reading history. The account
// and original grant version identify exactly one possible provider attempt.
// A fresh session can read an already committed result but cannot replace the
// original session or deadline for unfinished work.
func (s *ProviderRefreshService) Refresh(ctx context.Context, r ProviderRefreshRequest) (out ProviderRefreshResult, err error) {
	if ctx == nil || s == nil || s.link == nil || s.link.config == nil || len(s.providers) == 0 {
		return out, identity.InvalidInputError{Field: "oauth_refresh_request"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.link.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = ProviderRefreshResult{}, identity.UnavailableError{}
		}
	}()
	observed, now, err := s.link.authenticateProviderRefresh(ctx, r)
	if err != nil {
		return out, err
	}
	intent, err := s.intent(r)
	if err != nil {
		return out, err
	}
	requestKey, err := providerRefreshRequestKey(r.Account, r.ExpectedVersion)
	if err != nil {
		return out, err
	}
	p := &providerRefreshPhase{service: s, request: r, observed: observed, started: now}
	coordinator, registry, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: providerRefreshOperation().OperationID}
	admission := r.Caller.Clone()
	admission.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}
	key, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, requestKey, intent, admission, providerRefreshRegistration(), p)
	if err != nil {
		return out, err
	}
	defer clear(wire)
	input, err := s.link.openProviderRefreshInput(ctx, key, wire)
	if err != nil || input.Account.ID != r.Account || input.GrantVersion != r.ExpectedVersion || s.providers[input.Account.Provider] == nil {
		return out, identity.ForbiddenError{}
	}
	p.input = &input
	b := input.binding()
	history, historyErr := p.queryHistory(ctx, coordinator)
	if history.Binding.CommandID != "" {
		switch history.Outcome {
		case identity.CommitOutcomeCommitted:
			if historyErr != nil {
				return out, historyErr
			}
			return p.readReceipt(ctx)
		case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeUnknown:
			// Once the original native command is terminal, never perform
			// another exchange. A local rollback proves no upstream result.
			return out, identity.UnknownCommitError{CommandID: b.CommandID}
		}
	}
	var undisclosed identity.ForbiddenError
	if historyErr != nil && !errors.As(historyErr, &undisclosed) {
		return out, historyErr
	}
	command, counters, err := s.link.providerRefreshCommand(input, r)
	if err != nil {
		return out, err
	}
	if !input.validAt(now) {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	p.command = command
	p.plan, err = p.declaration(ctx, counters, registry.Descriptors())
	if err != nil {
		return out, err
	}
	p.plan, err = coordinator.PrepareFeaturePreparationPlan(command, p.plan)
	if err != nil {
		return out, err
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, command, p.plan)
	if result.Outcome == identity.CommitOutcomeCommitted && err == nil {
		return p.readReceipt(ctx)
	}
	if result.Outcome != 0 || err == nil {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	return out, err
}

func (p *providerRefreshPhase) queryHistory(ctx context.Context, coordinator *kernel.Coordinator) (kernel.CommandRecord, error) {
	b := p.input.binding()
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID,
		ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	caller := p.request.Caller.Clone()
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	record, err := coordinator.QueryCommand(ctx, query, caller)
	if record.Binding.CommandID != "" && (record.Binding != b || record.Feature == nil || *record.Feature != providerRefreshOperation()) {
		return kernel.CommandRecord{}, identity.UnavailableError{}
	}
	return record, err
}

type providerRefreshPhase struct {
	service  *ProviderRefreshService
	request  ProviderRefreshRequest
	observed session.GetResult
	started  time.Time
	input    *providerRefreshInput
	command  identity.Command
	plan     kernel.CommandPlan
}

func (*providerRefreshPhase) Descriptor() kernel.ContributorDescriptor {
	return providerRefreshRegistration().Contributor
}

func (*providerRefreshPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{providerRefreshOperation()}
}

func (p *providerRefreshPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, _ identity.RequestIntent) ([]byte, error) {
	link := p.service.link
	if k.Scope.TenantID != p.request.TenantID || k.Scope.ActorID != identity.ActorID(p.request.Caller.Request.Subject.ID) {
		return nil, identity.ForbiddenError{}
	}
	aad, err := link.providerRefreshInputAAD(k)
	if err != nil {
		return nil, err
	}
	input, err := link.captureProviderRefreshInput(ctx, k, p.request, p.observed, p.started, p.service.providers)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(input)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	return link.sealRP(ctx, aad, plain)
}
