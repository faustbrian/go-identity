package postgres

import (
	"context"
	"slices"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

func (s *LinkService) callbackCoordinator(p *rpLinkPhase) (*kernel.AccountLinkUnitOfWork, []kernel.ContributorDescriptor, error) {
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, capabilitypg.NewParticipant(), s.counters, p, s.issuer})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.config().Coordinator)
	if err != nil {
		return nil, nil, err
	}
	uow, err := kernel.NewAccountLinkUnitOfWork(coordinator, s.directory, kernel.AccountLinkUnitOfWorkConfig{RetentionPolicyVersion: s.config().AuditRetentionPolicyVersion})
	if err != nil {
		return nil, nil, err
	}
	return uow, registry.Descriptors()[:6], nil
}

// CallbackRateSource resolves original transaction attribution for the HTTP
// provider budget. It authenticates the same exact state/browser/configuration
// as Callback without reserving, releasing PKCE, exchanging or minting proof.
// Terminal metadata supports original retries, never new execution. Rate
// admission must precede the separate Callback call, which repeats its own
// current owners and is not authorized by this structural projection.
func (s *LinkService) CallbackRateSource(ctx context.Context, r oauth.CallbackRequest) (oauth.CallbackRateContext, error) {
	if ctx == nil || s == nil || s.config == nil {
		return oauth.CallbackRateContext{}, identity.InvalidInputError{Field: "oauth_callback"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	flow, err := s.loadRPLinkCallback(ctx, r)
	if err != nil {
		return oauth.CallbackRateContext{}, err
	}
	defer flow.destroy()
	return oauth.CallbackRateContext{ProviderID: flow.binding.Provider.ID, TransactionID: flow.binding.Input.binding().RecordID, Lifetime: flow.binding.ExpiresAt.Sub(flow.binding.IssuedAt)}, nil
}

// Callback completes only the configured explicit-self account-link profile.
// It resolves the actor from authenticated state and the original browser, never
// inbound identity fields. Existing primary owners admit and finalize authority;
// the existing root journal reserves state before releasing PKCE/exchanging.
// Unknown provider/durable outcomes retain custody and never retry exchange.
// Exact committed replay returns the original account outcome without generation.
// No session is minted, refreshed or promoted by linking. Caller owns destroying
// parsed callback custody after this bounded call, on success and failure.
func (s *LinkService) Callback(ctx context.Context, r oauth.CallbackRequest) (out oauth.CallbackResult, err error) {
	if ctx == nil || s == nil || s.config == nil || r.Validate() != nil {
		return out, identity.InvalidInputError{Field: "oauth_callback"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = oauth.CallbackResult{}, identity.UnavailableError{}
		}
	}()
	flow, err := s.loadRPLinkCallback(ctx, r)
	if err != nil {
		return out, err
	}
	defer flow.destroy()
	if r.Callback.Denied() {
		return s.deniedCallback(ctx, r, flow)
	}
	spec, err := callbackSpecification(flow)
	if err != nil {
		return out, err
	}
	// Policy is evaluated before SQL locks and only for the state-resolved self
	// subject. The native Work also fences its original user-policy epoch.
	b := spec.Binding
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Environment: authorization.Environment{Time: flow.loadedAt}}}
	decision, err := s.config().Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return out, identity.ForbiddenError{}
	}
	input, ok := r.Callback.Input()
	if !ok {
		return out, identity.ForbiddenError{}
	}
	versions, found, err := s.counters.OriginalOAuthLinkCounterKeys(ctx, s.pool, b, flow.binding.Input.Started, s.config().Session.Repository.MaximumDuration)
	if err != nil {
		return out, err
	}
	// Current HTTP IP admission still applies. Protected mutation intent uses
	// the original authenticated flow network, not a retry-selected replacement.
	subject := risk.Subject{User: string(b.UserID), Session: spec.SessionID, Network: flow.binding.Input.Network}
	var original identity.Command
	var counter kernel.CommandCounterPlan
	if found {
		original, counter, err = s.counters.PrepareAccountLinkPreparationCountersWithRetainedKeys(spec, input, r.Session, subject, flow.binding.Input.Started, versions)
	} else {
		original, counter, err = s.counters.PrepareAccountLinkPreparationCounters(spec, input, r.Session, subject, flow.binding.Input.Started)
	}
	if err != nil {
		return out, err
	}
	phase := &rpLinkPhase{service: s, flow: flow, original: original}
	phase.input, err = phase.inputDigest(ctx, original)
	if err != nil {
		return out, err
	}
	uow, owners, err := s.callbackCoordinator(phase)
	if err != nil {
		return out, err
	}
	auditing, err := rpLinkAudit(ctx, b, flow.binding.Input.Started, s.config().AuditRetentionPolicyVersion)
	if err != nil {
		return out, err
	}
	state := flow.statePlan
	audits := []kernel.AuditPlan{auditing}
	for i, action := range []string{"identity.oauth.handle_callback", "identity.oauth.link_account"} {
		plan := auditing
		plan.EventType, plan.EventIndex = action, auditing.EventIndex+uint16(i+1)
		audits = append(audits, plan)
	}
	phase.declaration = kernel.CommandPlan{Contributors: owners, Audits: audits, Lifecycle: &kernel.LifecyclePlan{EventType: "social_provider.linked.v1", BeforeVersion: 0, AfterVersion: 1}, AccountLinkState: &state, CommandCounters: &counter}
	prepared, err := uow.PrepareLink(ctx, original, phase.declaration)
	if err != nil {
		return out, err
	}
	result, observed := prepared.Observation()
	if !observed {
		command, participants, ready := prepared.Intent()
		if !ready {
			return out, identity.UnavailableError{}
		}
		var transaction oauth.LinkUnitOfWork = prepared
		linked, e := transaction.WithinLink(ctx, command, participants)
		if e != nil {
			return out, e
		}
		result, observed = linked.Receipt()
		if !observed {
			return out, identity.UnavailableError{}
		}
	}
	switch result.Outcome {
	case identity.CommitOutcomeCommitted:
	case identity.CommitOutcomeNotCommitted:
		// The root has durably refused this exact command. Do not turn a known
		// terminal refusal into exchange uncertainty or disclose collision owners.
		return out, identity.ForbiddenError{}
	case identity.CommitOutcomeConflict:
		return out, identity.ConflictError{}
	default:
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	current, err := s.directory.ListAccounts(ctx, identity.AccountQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumAccounts: 100})
	if err != nil {
		return out, err
	}
	index := slices.IndexFunc(current.Accounts, func(account identity.Account) bool { return string(account.ID) == b.RecordID })
	if !current.User.Status.AllowsAuthentication() || index < 0 || result.Link == nil || current.Accounts[index].Version != result.Link.AccountVersion || current.Accounts[index].Provider != spec.ProviderID || current.Accounts[index].Issuer != flow.binding.Provider.Issuer {
		return out, identity.ForbiddenError{}
	}
	callback, err := oauth.NewValidatedCallbackURL(flow.binding.Input.Callback, s.config().CallbackAllowlist)
	if err != nil {
		return out, err
	}
	originalSession, err := flow.original.Bindings()
	if err != nil {
		return out, err
	}
	return oauth.NewLinkedCallbackResult(result, oauth.IdentityResult{ProviderID: spec.ProviderID, ProviderSubject: current.Accounts[index].Subject, UserID: b.UserID, AccountID: identity.AccountID(b.RecordID), RememberPolicy: originalSession.Remember, Outcome: "link"}, callback)
}
