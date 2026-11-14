package postgres

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func (p *rpLinkPhase) GenerateAccountLinkPreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if err := p.validateOriginal(ctx, command); err != nil {
		return nil, err
	}
	if p.flow.erased || p.flow.stateGrant.EnvelopeDigest() != p.flow.statePlan.ProofFingerprint || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	// The coordinator calls this phase only after acknowledging durable state
	// reservation and its start marker. Provider calls never run under Work locks.
	var now time.Time
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, identity.UnavailableError{}
	}
	now = now.UTC()
	if err := p.requireFresh(now); err != nil {
		return nil, err
	}
	flow := p.flow.binding
	start := flow.Input.binding()
	binding, err := newRPVerifierBinding(string(start.TenantID), flow.Provider, start.RecordID, flow.StateDigest, start.OperationID)
	if err != nil {
		return nil, err
	}
	verifier, err := p.service.verifiers.open(ctx, binding, p.flow.pkce, flow.IssuedAt, flow.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	defer verifier.Destroy()
	if verifier.Challenge() != flow.Challenge {
		return nil, identity.ForbiddenError{}
	}
	provider, ok := p.service.providers.Lookup(flow.Provider.ID)
	if !ok || !reflect.DeepEqual(provider.Profile(), flow.Provider) || !oauth2ProviderMatches(provider, flow.OAuth2) {
		return nil, identity.ForbiddenError{}
	}
	spec, input, _, ok := command.AccountLinkPreparationInput()
	if !ok {
		return nil, identity.ForbiddenError{}
	}
	_, originalCredential, _, err := sessionpg.OriginalSessionAdmission(p.service.config().Session.Profile, p.flow.original, spec.Binding)
	if err != nil {
		return nil, err
	}
	result, err := provider.Exchange(ctx, input, verifier, protocolNonce(flow.Provider, flow.Nonce))
	defer result.Tokens.Destroy()
	if err != nil {
		var failure *oauth.Error
		if errors.As(err, &failure) && failure.Kind() == oauth.Refused {
			// A definitive provider result must reach the existing retention
			// journal before terminal cleanup. Every other exchange failure keeps
			// its established uncertainty; it must never retry the code.
			return p.sealProviderRefusal(ctx, command, generation)
		}
		return nil, err
	}
	verified := result.Identity
	if verified.ProviderID() != spec.ProviderID || verified.Issuer() != flow.Provider.Issuer || verified.Subject() == "" || !verified.EvidenceExpiresAt().After(now) {
		return nil, identity.ForbiddenError{}
	}
	account := identity.Account{ID: identity.AccountID(spec.Binding.RecordID), TenantID: spec.Binding.TenantID, UserID: spec.Binding.UserID, Provider: verified.ProviderID(), Issuer: verified.Issuer(), Subject: verified.Subject(), Version: 1}
	state, err := p.service.directory.GetAccountLinkState(ctx, identity.AccountLinkQuery{Mode: identity.AccountLinkExplicit, Account: account})
	if err != nil {
		return nil, err
	}
	if state.RecordVersion != 0 {
		return nil, identity.ConflictError{}
	}
	// The provider credential is a durable link, not an access-token/ID-token
	// lease. Native provider configuration and account/credential revocation gate
	// later signin independently; token expiry must not delete login authority.
	method := identity.LoginMethod{Credential: identity.CredentialRef{ID: identity.CredentialID(account.ID), TenantID: account.TenantID, UserID: account.UserID, Kind: identity.CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: account.ID, Usable: true}
	// A concurrent link may advance the aggregate epoch while exchange is in
	// flight. That primary read cannot renew the initiating session's authority.
	change := identity.AccountLinkChange{Mode: identity.AccountLinkExplicit, Account: account, Method: &method, ExpectedUserVersion: state.Access.User.Version, ExpectedAccountVersion: state.RecordVersion, ExpectedSocialLinkVersion: state.SocialLinkVersion, ExpectedCredentialVersion: originalCredential.CredentialAuthorityVersion}
	// This read supplies expected versions, not a durable collision decision.
	// Retain the verified output first: only the root's locked ApplyAccountLink
	// may classify a known conflict and terminally abort its original command.
	// Returning after an exchange but before retention would strand it Unknown.
	tokens, err := p.service.sealProviderTokens(ctx, rpTokenVaultBinding{TenantID: account.TenantID, UserID: account.UserID, AccountID: account.ID, ProviderID: account.Provider, Issuer: account.Issuer, ClientID: flow.Provider.ClientID, ConfigurationVersion: flow.Provider.Version, AccountVersion: account.Version, SocialLinkVersion: state.SocialLinkVersion + 1}, result.Tokens)
	if err != nil {
		return nil, err
	}
	unsigned := identity.AccountLinkCommand{Binding: spec.Binding, Change: change, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion}
	return p.sealLinkedOutput(ctx, command, generation, unsigned, tokens, p.flow.loadedAt, verified.EvidenceExpiresAt())
}

func (p *rpLinkPhase) RestoreAccountLinkPreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, kernel.CapabilityIssuancePlan, error) {
	if err := p.validateOriginal(ctx, original); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, err
	}
	_, command, issuance, err := p.restoreLinkedOutput(ctx, original, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, err
	}
	plan := p.declaration
	grant := issuance.Grants[0]
	plan.Capability = &grant
	if err := p.ValidateAccountLink(command, plan); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, kernel.CapabilityIssuancePlan{}, err
	}
	return command, plan, issuance, nil
}

func rpLinkAudit(ctx context.Context, b identity.CommandBinding, now time.Time, retention uint64) (kernel.AuditPlan, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{IDGenerator: func() (string, error) { return "oauth-link-declaration", nil }})
	if err != nil || retention == 0 {
		return kernel.AuditPlan{}, identity.InvalidInputError{Field: "oauth_link_audit"}
	}
	record, err := builder.Build(audit.RecordInput{Action: "identity.account.link", OccurredAt: now, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "account", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "standard", "aggregate.type": "account", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1"}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version"}})
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	digest, err := kernel.AuditBindingDigest(b, record)
	if err != nil {
		return kernel.AuditPlan{}, err
	}
	return kernel.AuditPlan{EventType: "identity.account.link", SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: retention, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}, nil
}
