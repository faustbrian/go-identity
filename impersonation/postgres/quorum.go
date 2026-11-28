package impersonationpostgres

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

const quorumAction = "identity.impersonation.quorum"

// QuorumInput reads one grant with an original ordinary password/TOTP
// credential, within its authenticated tenant. No CSRF or command is accepted.
type QuorumInput struct {
	Tenant  identity.TenantID
	Bearer  authentication.BearerCredential
	GrantID impersonation.GrantID
}

func (QuorumInput) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("impersonation.QuorumInput(redacted)"))
}

func (QuorumInput) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (QuorumInput) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// QuorumApproval contains decision metadata only, never usable approval proof.
type QuorumApproval struct {
	ApproverID identity.UserID `json:"approverID"`
	DecidedAt  time.Time       `json:"decidedAt"`
}

// QuorumResult is a primary observation without session or approval authority.
type QuorumResult struct {
	GrantID           impersonation.GrantID `json:"grantID"`
	RequiredApprovals int                   `json:"requiredApprovals"`
	Approvals         []QuorumApproval      `json:"approvals"`
	Status            impersonation.Status  `json:"status"`
}

// Quorum reads the current fixed-one approval profile and latest retained
// state. The selected Denial profile and its complete history are required to
// distinguish all terminal states. Explicit current read permission addresses
// the exact grant. No reason, envelope, credential, or mutation is involved.
func (s *Service) Quorum(ctx context.Context, input QuorumInput) (QuorumResult, error) {
	return s.quorum(ctx, input, nil)
}

// QuorumWithAdmission adds the transport's required quota check to Quorum.
// Admit runs synchronously with the authenticated and authorized ordinary
// actor, before the grant lookup. It must honor the passed deadline and not
// retain its arguments. Errors return no grant metadata; it is never retried.
func (s *Service) QuorumWithAdmission(ctx context.Context, input QuorumInput, admit func(context.Context, identity.UserID) error) (QuorumResult, error) {
	if admit == nil {
		return QuorumResult{}, impersonation.ErrInvalidInput
	}
	return s.quorum(ctx, input, admit)
}

func (s *Service) quorum(ctx context.Context, input QuorumInput, admit func(context.Context, identity.UserID) error) (QuorumResult, error) {
	if s == nil || !s.denial || ctx == nil || !validStoredGrantKey(input.Tenant, input.GrantID) {
		return QuorumResult{}, impersonation.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	readConfig := s.config.Session
	actor, err := authenticateOrdinaryActor(bounded, s.sessions, readConfig, Authentication{Tenant: input.Tenant, Bearer: input.Bearer})
	if err != nil {
		return QuorumResult{}, err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil || spec.TenantID != input.Tenant {
		return QuorumResult{}, identity.ForbiddenError{}
	}
	policy := s.config.Policy
	request := authorization.DecisionContext{
		PolicyRevision: authorization.Revision(policy.Version()),
		Request: authorization.Request{
			Subject:     authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)},
			Action:      quorumAction,
			Resource:    authorization.Resource{Type: "identity.impersonation.grant", ID: authorization.ResourceID(input.GrantID)},
			Tenant:      authorization.TenantID(spec.TenantID),
			Environment: authorization.Environment{Time: readConfig.Validation.Clock.Now().UTC()},
		},
	}
	if err := request.Validate(); err != nil {
		return QuorumResult{}, identity.ForbiddenError{}
	}
	decision, err := s.config.Authorization.Decide(bounded, request)
	if bounded.Err() != nil {
		return QuorumResult{}, bounded.Err()
	}
	if err != nil {
		return QuorumResult{}, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != request.PolicyRevision {
		return QuorumResult{}, identity.ForbiddenError{}
	}
	if admit != nil {
		if err := actor.requireFresh(readConfig.Validation.Clock.Now()); err != nil {
			return QuorumResult{}, err
		}
		err := checkQuorumAdmission(bounded, spec.UserID, admit)
		if bounded.Err() != nil {
			return QuorumResult{}, bounded.Err()
		}
		if err != nil {
			return QuorumResult{}, err
		}
	}
	result, err := loadQuorumSnapshot(bounded, s.pool, spec.TenantID, input.GrantID, readConfig.Validation.Clock.Now().UTC())
	if bounded.Err() != nil {
		return QuorumResult{}, bounded.Err()
	}
	if err != nil {
		return QuorumResult{}, err
	}
	if err := actor.requireFresh(readConfig.Validation.Clock.Now()); err != nil {
		return QuorumResult{}, err
	}
	result.RequiredApprovals = policy.RequiredApprovals()
	return result, nil
}

func checkQuorumAdmission(ctx context.Context, actor identity.UserID, admit func(context.Context, identity.UserID) error) (err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	return admit(ctx, actor)
}
