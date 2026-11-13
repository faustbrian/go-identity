package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// SigninCompletionConfig selects existing-account, known-empty-MFA cookie
// issuance. ConfigurationID versions the immutable completion semantics;
// PolicyNamespace and Audience identify the actual session authority owners.
// Issuer.Authority must be nil: native provider/state/browser verification is
// mandatory, not a caller-supplied proof. Install OAuth session issuance history
// before selecting completion. No HTTP route is enabled by construction.
type SigninCompletionConfig struct {
	ConfigurationID, PolicyNamespace, Audience string
	Issuer                                     session.IssuerConfig
	CSRF                                       session.CSRFKey
}

// SigninCompletionService composes an existing native RP owner and session
// effects under the kernel coordinator. Dependencies are borrowed and must
// outlive bounded calls. It starts no resources, transaction or replay engine.
// Calls have independent preparation and ephemeral bearer custody.
type SigninCompletionService struct {
	start   *SigninService
	config  SigninCompletionConfig
	profile [32]byte
	policy  *authoritypg.AuthorityStore
	effect  *sessionpg.OAuthSigninEffect
}

// NewSigninCompletionService snapshots the selected native owners without IO,
// randomness or migration. Enrolled/unknown MFA, implicit signup, email matching
// and organization sessions are not selected and must never fall back to SFA.
func NewSigninCompletionService(start *SigninService, c SigninCompletionConfig) (*SigninCompletionService, error) {
	invalid := identity.InvalidInputError{Field: "oauth_signin_completion"}
	if start == nil || start.pool == nil || !rpASCII(c.ConfigurationID, 1, 128) || c.Issuer.Authority != nil || c.Issuer.MaximumDuration > start.config.MaximumDuration {
		return nil, invalid
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: start.config.GlobalAuthorityID, PolicyNamespace: c.PolicyNamespace, Audience: c.Audience, AuthenticationMethod: "oauth", CredentialKind: identity.CredentialProvider, CredentialOwner: "identity/oauth"}
	effect, err := sessionpg.NewOAuthSigninEffect(start.config.Session, profile)
	if err != nil {
		return nil, err
	}
	policy, err := authoritypg.NewAuthorityStore(start.pool.Raw(), start.config.MaximumDuration)
	if err != nil {
		return nil, invalid
	}
	if _, err := session.NewOAuthSessionIssuerWithCSRF(&signinCallbackPhase{}, c.Issuer, c.CSRF); err != nil {
		return nil, err
	}
	c.ConfigurationID, c.PolicyNamespace, c.Audience = strings.Clone(c.ConfigurationID), strings.Clone(c.PolicyNamespace), strings.Clone(c.Audience)
	frame, err := json.Marshal(struct {
		Start                   [32]byte
		ID, Namespace, Audience string
	}{start.profile, c.ConfigurationID, c.PolicyNamespace, c.Audience})
	if err != nil {
		return nil, invalid
	}
	defer clear(frame)
	return &SigninCompletionService{start: start, config: c, profile: sha256.Sum256(frame), policy: policy, effect: effect}, nil
}

func (s *SigninCompletionService) coordinator(p *signinCallbackPhase) (*kernel.Coordinator, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	l, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.start.directory, a, l, p, capabilitypg.NewParticipant()})
	if err != nil {
		return nil, err
	}
	c, err := kernel.NewCoordinator(s.start.pool, registry, s.start.config.Coordinator)
	p.coordinator, p.registry = c, registry
	return c, err
}

// Callback uses acknowledged original-state reservation before PKCE release or
// provider exchange. The selected account, known-empty factor epoch and session
// are frozen into encrypted preparation; state/browser/session/audit/lifecycle
// commit together. Unknown exchange never retries its code. Only the original
// newly committed invocation can deliver its private bearer and CSRF.
func (s *SigninCompletionService) Callback(ctx context.Context, r oauth.SigninCallbackRequest) (out oauth.SigninCallbackResult, err error) {
	if ctx == nil || s == nil || s.start == nil || r.Validate() != nil {
		return out, identity.InvalidInputError{Field: "oauth_signin_callback"}
	}
	ctx, stop := context.WithTimeout(ctx, s.start.config.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = oauth.SigninCallbackResult{}, identity.UnavailableError{}
		}
	}()
	flow, err := s.start.loadSigninCallback(ctx, r)
	if err != nil {
		return out, err
	}
	defer flow.destroy()
	if r.Callback.Denied() {
		return s.deniedCallback(ctx, r, flow)
	}
	original, err := s.start.signinCallbackCommand(ctx, r, flow)
	if err != nil {
		return out, err
	}
	spec, _ := original.Feature()
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "oauth.signin.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.profile[:]}})
	original, err = identity.NewFeaturePreAuthCommand(spec, r.FlowCookie)
	if err != nil {
		return out, err
	}
	p := &signinCallbackPhase{service: s, request: r, flow: flow, original: original}
	p.issuer, err = session.NewOAuthSessionIssuerWithCSRF(p, s.config.Issuer, s.config.CSRF)
	if err != nil {
		return out, err
	}
	coordinator, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	plan, err := p.plan()
	if err != nil {
		return out, err
	}
	receipt, err := coordinator.ExecutePreparedFeature(ctx, original, plan)
	out.Session = session.IssueResult{CommandID: spec.Binding.CommandID, CommitOutcome: receipt.Outcome, Replayed: receipt.Outcome == identity.CommitOutcomeCommitted, RetryAfter: receipt.RetryAfter}
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	if p.execution == nil {
		if !flow.erased {
			return out, identity.UnavailableError{}
		}
		p.execution, err = p.committedProjection(ctx)
		if err != nil {
			return out, err
		}
	}
	issued := out.Session
	issued.Session = p.execution.record
	var csrf session.CSRFToken
	if p.prepared != (session.PreparedIssuance{}) {
		p.receipt, p.deliverable = receipt, true
		bound, e := p.issuer.BindOAuth(p.prepared, p.command)
		if e != nil {
			return out, e
		}
		issued, e = p.issuer.Issue(ctx, bound)
		if e != nil {
			return out, e
		}
		csrf, e = bound.CSRFToken()
		if e != nil {
			return out, e
		}
	}
	callback, err := oauth.NewValidatedCallbackURL(flow.binding.Input.Callback, s.start.config.CallbackAllowlist)
	if err != nil {
		return out, err
	}
	account := p.execution.account.Account
	flowSpec, _ := flow.original.Bindings()
	result := oauth.IdentityResult{ProviderID: account.Provider, ProviderSubject: account.Subject, UserID: account.UserID, AccountID: account.ID, RememberPolicy: flowSpec.Binding.Intent.Remember, Outcome: "signin"}
	return oauth.NewSigninCallbackResult(receipt, result, callback, issued, csrf)
}

// RecoverCallback authorizes historical signin receipt disclosure using the
// configured current QueryPolicy and the original anonymous flow/service actor.
// It uses the existing coordinator's primary recovery, not provider exchange or
// browser proof. Live or uncertain exchange remains pending; expired custody is
// reconciled only by the original participants. No session, bearer, CSRF token
// or current authentication authority is returned, even after commitment.
// Provider-denial commands have a distinct profile and are not accepted here.
func (s *SigninCompletionService) RecoverCallback(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (session.IssueResult, error) {
	if ctx == nil || s == nil || s.start == nil {
		return session.IssueResult{}, identity.InvalidInputError{Field: "oauth_signin_recovery"}
	}
	if q.OperationID != signinCallbackOperation().OperationID || q.AnonymousFlowID == "" || q.UserID != "" || q.RecordID != "" || q.LinkMode != 0 || q.ActorKind != authorization.SubjectServiceAccount {
		return session.IssueResult{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.start.config.MaximumDuration)
	defer stop()
	phase := &signinCallbackPhase{service: s}
	coordinator, err := s.coordinator(phase)
	if err != nil {
		return session.IssueResult{}, err
	}
	receipt, err := coordinator.RecoverFeatureCommand(bounded, q, caller)
	if receipt.Binding.CommandID == "" {
		return session.IssueResult{}, err
	}
	if receipt.Feature == nil || receipt.Feature.Operation != signinCallbackOperation() {
		return session.IssueResult{}, identity.UnavailableError{}
	}
	return session.IssueResult{CommandID: receipt.Binding.CommandID, CommitOutcome: receipt.Outcome, Replayed: true, RetryAfter: receipt.RetryAfter}, err
}

// Format redacts session and deployment configuration.
func (SigninCompletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.SigninCompletionConfig(redacted)"))
}
func (SigninCompletionConfig) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (SigninCompletionConfig) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*SigninCompletionService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.SigninCompletionService(redacted)"))
}
func (*SigninCompletionService) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
func (*SigninCompletionService) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "sensitive_configuration"}
}
