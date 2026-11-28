package impersonationpostgres

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const (
	requestAction    = "identity.impersonation.request"
	approveAction    = "identity.impersonation.approve"
	denyAction       = "identity.impersonation.deny"
	startAction      = "identity.impersonation.start"
	revokeAction     = "identity.impersonation.revoke"
	stopAction       = "identity.impersonation.stop"
	scopeAttribute   = "impersonation.scope"
	maximumFreshness = 15 * time.Minute
)

var approvalDescriptor = kernel.ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}

func approvalOperation(name string) (identity.FeatureOperation, bool) {
	var schema string
	switch name {
	case requestAction:
		schema = "impersonation-request"
	case approveAction:
		schema = "impersonation-approve"
	case denyAction:
		schema = "impersonation-deny"
	case startAction:
		schema = "impersonation-start"
	case revokeAction:
		schema = "impersonation-revoke"
	case stopAction:
		schema = "impersonation-stop"
	default:
		return identity.FeatureOperation{}, false
	}
	return identity.FeatureOperation{Owner: "identity/impersonation", OperationID: name, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, true
}

func actorDecision(binding identity.CommandBinding, scope impersonation.Scope, now time.Time) (authorization.DecisionContext, error) {
	op, selected := approvalOperation(binding.OperationID)
	permissions := scope.Permissions()
	if !selected || binding.ValidateFor(op) != nil || binding.ActorKind != authorization.SubjectUser || identity.UserID(binding.ActorID) == binding.UserID || len(permissions) == 0 || now.IsZero() {
		return authorization.DecisionContext{}, impersonation.ErrInvalidInput
	}
	attributes := authorization.Attributes{scopeAttribute: authorization.StringSetValue(permissions)}
	if binding.OperationID == denyAction {
		attributes["impersonation.grant-id"] = authorization.StringValue(binding.RecordID)
	}
	return authorization.DecisionContext{
		PolicyRevision: authorization.Revision(binding.PolicyVersion),
		CorrelationID:  binding.CorrelationID,
		Request: authorization.Request{
			Subject:     authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(binding.ActorID)},
			Action:      authorization.Action(op.OperationID),
			Resource:    authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)},
			Tenant:      authorization.TenantID(binding.TenantID),
			Attributes:  attributes,
			Environment: authorization.Environment{Time: now.UTC()},
		},
	}, nil
}

// Authentication borrows one original MFA browser session and its CSRF
// synchronizer. It never selects a user; the authoritative reader derives that
// identity. The caller must not log the credentials or mutate them during use.
type Authentication struct {
	Tenant identity.TenantID
	Bearer authentication.BearerCredential
	CSRF   session.CSRFToken
}

// Format prevents exposing credentials with formatting verbs.
func (Authentication) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("impersonation.Authentication(redacted)"))
}

// MarshalJSON refuses implicit credential serialization.
func (Authentication) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit credential serialization as text or a map key.
func (Authentication) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type authenticatedActor struct {
	input    Authentication
	observed session.GetResult
}

func authenticateActor(ctx context.Context, reader *session.SessionService, cfg sessionpg.SessionServiceConfig, csrfKey session.CSRFKey, input Authentication) (authenticatedActor, error) {
	actor, err := authenticateOrdinaryActor(ctx, reader, cfg, input)
	if err != nil {
		return authenticatedActor{}, err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil || spec.TenantID != input.Tenant {
		return authenticatedActor{}, identity.ForbiddenError{}
	}
	csrfBinding := session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}
	if actor.observed.Session.CSRFState().Check(csrfBinding, input.CSRF, csrfKey) != nil {
		return authenticatedActor{}, identity.ForbiddenError{}
	}
	return actor, nil
}

func authenticateOrdinaryActor(ctx context.Context, reader *session.SessionService, cfg sessionpg.SessionServiceConfig, input Authentication) (authenticatedActor, error) {
	if ctx == nil || reader == nil {
		return authenticatedActor{}, impersonation.ErrInvalidInput
	}
	token, err := session.ParseToken(input.Bearer.Token())
	if err != nil {
		return authenticatedActor{}, identity.ForbiddenError{}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return authenticatedActor{}, identity.ForbiddenError{}
	}
	observation, err := reader.Get(ctx, session.GetRequest{TenantID: input.Tenant, Credential: credential})
	if err != nil {
		return authenticatedActor{}, err
	}
	now := cfg.Validation.Clock.Now()
	actor := authenticatedActor{input: input, observed: observation}
	if err := actor.requireFresh(now); err != nil {
		return authenticatedActor{}, err
	}
	return actor, nil
}

func (a authenticatedActor) requireFresh(now time.Time) error {
	if a.observed.ValidateAt(now) != nil {
		return identity.ForbiddenError{}
	}
	factor, err := a.observed.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" || now.Before(factor.VerifiedAt) || now.Sub(factor.VerifiedAt) >= maximumFreshness {
		return identity.ForbiddenError{}
	}
	lifetime, err := a.observed.Session.Lifetime(now)
	if err != nil || !lifetime.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}

func actorAdmissionBinding(binding identity.CommandBinding) identity.CommandBinding {
	// This is a local lookup key for the authenticating user, not a
	// replacement command. The real Work binding still addresses the target.
	binding.UserID = identity.UserID(binding.ActorID)
	return binding
}

func (a authenticatedActor) checkWork(ctx context.Context, work kernel.Work, owner kernel.FeatureExecutionContributor, cfg sessionpg.SessionServiceConfig, csrfKey session.CSRFKey, binding identity.CommandBinding) error {
	if a.input.Tenant != binding.TenantID {
		return identity.ForbiddenError{}
	}
	spec, err := a.observed.Session.Bindings()
	if err != nil || spec.TenantID != binding.TenantID || spec.UserID != identity.UserID(binding.ActorID) {
		return identity.ForbiddenError{}
	}
	directory, credential, policy, err := sessionpg.OriginalMFAPasswordSessionAdmission(cfg.Profile, a.observed.Session, actorAdmissionBinding(binding))
	if err != nil {
		return identity.ForbiddenError{}
	}
	token, err := session.ParseToken(a.input.Bearer.Token())
	if err != nil {
		return identity.ForbiddenError{}
	}
	matched := false
	for _, key := range cfg.Validation.LookupKeys {
		digest, digestErr := token.Digest(key, string(spec.TenantID))
		if digestErr == nil && digest.KeyVersion == spec.Lookup.KeyVersion && subtle.ConstantTimeCompare(digest.Sum[:], spec.Lookup.Sum[:]) == 1 {
			matched = true
		}
	}
	if !matched {
		return identity.ForbiddenError{}
	}
	if err := work.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := work.RequireActiveActorCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err := work.RequireActiveActorAuthorization(ctx, owner, policy); err != nil {
		return err
	}
	factor, err := a.observed.Session.MFAAuthentication().Bindings()
	if err != nil || factor.Method != "totp" {
		return identity.ForbiddenError{}
	}
	if err := mfapg.RequireImpersonationActorTOTPSessionFactor(ctx, work, owner, spec.UserID, factor.FactorID, mfapg.TOTPSessionFactorState{EnrollmentVersion: factor.EnrollmentVersion, AuthorityVersion: factor.FactorAuthorityVersion}); err != nil {
		return err
	}
	return sessionpg.RequireCSRF(ctx, work, cfg.Repository, a.observed.Session, a.input.CSRF, csrfKey)
}
