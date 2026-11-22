package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/jackc/pgx/v5"
)

// ProviderRefreshRequest is native transport input. Account and
// ExpectedVersion select an existing grant, never a provider credential.
// The trusted transport supplies the session, origin, network and policy
// context; callers cannot supply an idempotency key or an upstream destination.
type ProviderRefreshRequest struct {
	TenantID        identity.TenantID
	Account         identity.AccountID
	ExpectedVersion uint64
	Session         auth.BearerCredential
	CSRFToken       session.CSRFToken
	Caller          authorization.DecisionContext
	Origin, Network string
}

func (ProviderRefreshRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthpostgres.ProviderRefreshRequest(redacted)"))
}

func (ProviderRefreshRequest) MarshalJSON() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "oauth_refresh_request"}
}

func (ProviderRefreshRequest) MarshalText() ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "oauth_refresh_request"}
}

func (r ProviderRefreshRequest) validateScope(origin string) error {
	invalid := identity.InvalidInputError{Field: "oauth_refresh_request"}
	addr, err := netip.ParseAddr(r.Network)
	if err != nil || addr.Unmap().String() != r.Network || addr.Zone() != "" || origin == "" || r.Origin != origin {
		return invalid
	}
	if _, err := providerRefreshRequestKey(r.Account, r.ExpectedVersion); err != nil {
		return invalid
	}
	if r.Caller.Validate() != nil || r.Caller.Request.Tenant != authorization.TenantID(r.TenantID) ||
		r.Caller.Request.Subject.Kind != authorization.SubjectUser || r.Caller.Request.Action != authorization.Action(providerRefreshOperation().OperationID) ||
		r.Caller.Request.Resource.Type != "identity.account" || r.Caller.Request.Resource.ID != authorization.ResourceID(r.Account) {
		return invalid
	}
	return nil
}

// Authenticate each call before revealing whether the version exists. Bound
// cookie possession and CSRF are verified by the existing session owner.
func (s *LinkService) authenticateProviderRefresh(ctx context.Context, r ProviderRefreshRequest) (session.GetResult, time.Time, error) {
	if ctx == nil || s == nil || s.config == nil || s.sessions == nil || s.pool == nil || r.validateScope(s.config().Origin) != nil {
		return session.GetResult{}, time.Time{}, identity.InvalidInputError{Field: "oauth_refresh_request"}
	}
	c := s.config()
	if r.Caller.PolicyRevision != authorization.Revision(c.Coordinator.AdmissionPolicy.PolicyVersion) {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	var observedAt time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observedAt); err != nil {
		return session.GetResult{}, time.Time{}, identity.UnavailableError{}
	}
	observedAt = observedAt.UTC()
	token, err := session.ParseToken(r.Session.Token())
	if err != nil {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil || !observed.Authenticated || observed.ValidateAt(c.Session.Validation.Clock.Now()) != nil {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.TenantID != r.TenantID || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || !s.possesses(r.TenantID, r.Session, r.CSRFToken, observed.Session) {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	lifetime, err := observed.Session.Lifetime(c.Session.Validation.Clock.Now())
	if err != nil || !lifetime.Fresh {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	caller := r.Caller.Clone()
	caller.Request.Environment.Time = observedAt
	decision, err := c.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, caller)
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return session.GetResult{}, time.Time{}, identity.ForbiddenError{}
	}
	return observed, observedAt, nil
}

func (s *LinkService) providerRefreshGrant(ctx context.Context, b identity.CommandBinding) (rpPreparedTokenSet, error) {
	account := identity.AccountID(b.RecordID)
	row := s.pool.Raw().QueryRow(ctx, providerRefreshVaultReadSQL(s.config().Schema), string(b.TenantID), string(b.UserID), string(account))
	grant, err := scanProviderRefreshVault(row, b.TenantID, b.UserID, account)
	return grant, providerRefreshReadError(ctx, err)
}

func providerRefreshReadError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}

func (s *LinkService) captureProviderRefreshInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, r ProviderRefreshRequest, observed session.GetResult, at time.Time, providers map[string]*oauth.OAuth2RefreshProvider) (providerRefreshInput, error) {
	actor := identity.UserID(k.Scope.ActorID)
	op := providerRefreshOperation()
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: k.Scope.TenantID, UserID: actor, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind,
		RecordID: string(r.Account), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion,
		PolicyID: s.config().PolicyID, PolicyVersion: k.PolicyVersion, CorrelationID: string(k.Admission.CommandID)}
	account, err := s.directory.GetOwnedProviderAccount(ctx, b.TenantID, b.UserID, r.Account)
	if err != nil {
		return providerRefreshInput{}, err
	}
	if providers[account.Account.Provider] == nil {
		return providerRefreshInput{}, identity.ForbiddenError{}
	}
	grant, err := s.providerRefreshGrant(ctx, b)
	if err != nil {
		return providerRefreshInput{}, err
	}
	defer clear(grant.Ciphertext)
	if grant.Version != r.ExpectedVersion {
		return providerRefreshInput{}, identity.ConflictError{}
	}
	proof, err := s.openStoredProviderRefresh(ctx, grant)
	if err != nil {
		return providerRefreshInput{}, err
	}
	proof.Destroy()
	until := at.Add(20 * time.Second)
	if observed.ValidUntil().Before(until) {
		until = observed.ValidUntil()
	}
	p := newProviderRefreshInput(b, account, grant, at, until.UTC())
	if !p.matchesGrant(grant) || !p.validAt(at) {
		return providerRefreshInput{}, identity.ForbiddenError{}
	}
	p.Session, err = sessionpg.OriginalSessionFields(observed.Session)
	if err != nil {
		return providerRefreshInput{}, err
	}
	p.Network = r.Network
	command, _, err := s.providerRefreshCommand(p, r)
	if err != nil {
		return providerRefreshInput{}, err
	}
	p.CounterKeys, err = providerRefreshCounterKeys(command)
	if err != nil {
		return providerRefreshInput{}, err
	}
	return p, nil
}
