package impersonationpostgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// UseInput requests one application permission on the grant's exact target.
// Reserved identity-administration operations cannot use derived credentials.
type UseInput struct {
	Tenant     identity.TenantID
	Bearer     string
	Permission string
}

// Format never exposes a supplied bearer.
func (UseInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "impersonation.UseInput(redacted)")
}

// MarshalJSON prevents accidental serialization outside the credential transport.
func (UseInput) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// UseResult identifies one allowed use at the authoritative read. It is not a
// reusable session proof, capability, or permission for any other operation.
type UseResult struct {
	TenantID             identity.TenantID
	ActorID, TargetID    identity.UserID
	GrantID              impersonation.GrantID
	GrantVersion         uint64
	Permission           string
	StartedAt, ExpiresAt time.Time
}

// ValidateUse checks the live grant, actor and target decisions, original
// parent and participant authority without a cache. Call it for each action,
// never convert an allowed result into ordinary identity authentication.
func (s *Service) ValidateUse(ctx context.Context, input UseInput) (UseResult, error) {
	if s == nil || s.activation == nil || ctx == nil || !validStorageID(string(input.Tenant)) {
		return UseResult{}, impersonation.ErrInvalidInput
	}
	if !permittedDerivedAction(input.Permission) {
		return UseResult{}, identity.ForbiddenError{}
	}
	credential, err := parseDerivedCredential(input.Bearer)
	if err != nil {
		return UseResult{}, identity.ForbiddenError{}
	}
	digest, err := credential.lookup(s.activation.key, input.Tenant)
	if err != nil {
		return UseResult{}, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	clock := s.config.Session.Validation.Clock
	before := clock.Now()
	row, err := readActivation(bounded, s.pool, input.Tenant, digest)
	if err != nil {
		return UseResult{}, err
	}
	if row.status != impersonation.StatusActive || row.version != 3 || row.policy != s.config.Policy ||
		row.authorityNamespace != s.config.Session.Profile.PolicyNamespace ||
		before.Before(row.startedAt) || !before.Before(row.expiresAt) || !slices.Contains(row.scope.Permissions(), input.Permission) {
		return UseResult{}, identity.ForbiddenError{}
	}
	if err := s.authorizeDerivedUse(bounded, row, input.Permission, row.actor); err != nil {
		return UseResult{}, err
	}
	if err := s.authorizeDerivedUse(bounded, row, input.Permission, row.target); err != nil {
		return UseResult{}, err
	}
	approver := s.binding(approveAction, row.approvalID, row.grantID, row.tenant, row.approver, row.target)
	if err := s.authorize(bounded, approver, row.scope); err != nil {
		return UseResult{}, err
	}
	if err := s.checkUseParticipants(bounded, row); err != nil {
		return UseResult{}, err
	}
	parent, err := s.activation.parents.Observe(bounded, sessionpg.OriginalPasswordTOTPParentReference{
		TenantID: row.tenant, ActorID: row.actor, SessionID: row.parentID, SessionVersion: row.parentVersion, Lookup: row.parentDigest})
	if errors.Is(err, session.ErrUnauthenticated) {
		return UseResult{}, identity.ForbiddenError{}
	}
	if err != nil {
		return UseResult{}, err
	}
	// The final primary read follows every policy/parent callback. A committed
	// stop/revocation during those calls cannot survive this exact-state check.
	current, err := readActivation(bounded, s.pool, input.Tenant, digest)
	if err != nil {
		return UseResult{}, err
	}
	if err := bounded.Err(); err != nil {
		return UseResult{}, err
	}
	now := clock.Now()
	if !sameActiveAuthority(row, current) || now.Before(before) ||
		!now.Before(row.expiresAt) || !now.Before(parent.ValidUntil) || !now.Before(before.Add(20*time.Second)) {
		return UseResult{}, identity.ForbiddenError{}
	}
	return UseResult{TenantID: row.tenant, ActorID: row.actor, TargetID: row.target, GrantID: row.grantID,
		GrantVersion: row.version, Permission: input.Permission, StartedAt: row.startedAt, ExpiresAt: row.expiresAt}, nil
}

func permittedDerivedAction(permission string) bool {
	if len(permission) == 0 || len(permission) > 128 {
		return false
	}
	for i := range len(permission) {
		if permission[i] < 0x21 || permission[i] > 0x7e {
			return false
		}
	}
	// Application permissions cannot alias reserved identity, organization or
	// provider administration namespace actions, even by changing their case.
	normalized := strings.ToLower(permission)
	for _, namespace := range []string{"identity.", "identity:", "organization.", "organization:", "auth.", "auth:"} {
		if strings.HasPrefix(normalized, namespace) {
			return false
		}
	}
	return true
}

func (s *Service) authorizeDerivedUse(ctx context.Context, row activationRecord, permission string, subject identity.UserID) error {
	caller := authorization.DecisionContext{
		PolicyRevision: authorization.Revision(row.policy.Version()), CorrelationID: string(row.commandID),
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(subject)},
			Action:  authorization.Action(permission), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(row.target)},
			Tenant: authorization.TenantID(row.tenant), Environment: authorization.Environment{Time: s.config.Session.Validation.Clock.Now().UTC()},
			Attributes: authorization.Attributes{
				"impersonation.use":       authorization.BoolValue(true),
				"impersonation.grant-id":  authorization.StringValue(string(row.grantID)),
				"impersonation.actor-id":  authorization.StringValue(string(row.actor)),
				"impersonation.target-id": authorization.StringValue(string(row.target)),
			},
		},
	}
	if caller.Validate() != nil {
		return identity.ForbiddenError{}
	}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *Service) checkUseParticipants(ctx context.Context, row activationRecord) error {
	for _, subject := range []struct {
		id      identity.UserID
		version uint64
	}{{row.actor, row.actorVersion}, {row.target, row.targetVersion}, {row.approver, row.approverVersion}} {
		current, err := s.activeUser(ctx, row.tenant, subject.id)
		if err != nil {
			return err
		}
		if current.Version != subject.version {
			return identity.ForbiddenError{}
		}
	}
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(row.tenant), SubjectID: authorization.SubjectID(row.approver), PolicyNamespace: row.authorityNamespace}
	epoch, err := s.activation.authorities.Get(ctx, scope)
	if errors.Is(err, authority.ErrAuthorityDenied) {
		return identity.ForbiddenError{}
	}
	if err != nil {
		return identity.UnavailableError{}
	}
	if epoch.Scope != scope || epoch.Version != row.approverAuthorityVersion {
		return identity.ForbiddenError{}
	}
	return nil
}

func sameActiveAuthority(a, b activationRecord) bool {
	return a.tenant == b.tenant && a.grantID == b.grantID && a.commandID == b.commandID && a.approvalID == b.approvalID &&
		a.actor == b.actor && a.target == b.target && a.approver == b.approver && a.requestDigest == b.requestDigest &&
		a.version == b.version && a.status == b.status && a.policy == b.policy &&
		a.actorVersion == b.actorVersion && a.targetVersion == b.targetVersion && a.approverVersion == b.approverVersion &&
		a.approverAuthorityVersion == b.approverAuthorityVersion && a.authorityNamespace == b.authorityNamespace &&
		a.parentID == b.parentID && a.parentVersion == b.parentVersion && a.parentDigest == b.parentDigest &&
		a.derivedDigest == b.derivedDigest && a.startedAt.Equal(b.startedAt) && a.expiresAt.Equal(b.expiresAt) &&
		slices.Equal(a.scope.Permissions(), b.scope.Permissions())
}
