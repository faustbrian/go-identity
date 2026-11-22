package identity

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
)

// PreparedAccountUnlinkUnitOfWork is an explicitly trusted native producer and
// transaction owner. VerifyPreparedAccountUnlink must match the complete command
// and grant to its authenticated retained issuer preparation, including the
// configured signing-key authority; a structurally valid grant alone is not
// sufficient. It must not sign, reveal a bearer, consume a proof, mutate storage
// or renew freshness. The original issuer's opaque restore path deliberately
// grants no bearer-transfer right, so it cannot use the raw-proof entry point.
//
// Execute must accept only that same prepared intent and repeat current primary
// credential/session/factor admission, final-access eligibility and atomic proof,
// token-cleanup and lifecycle effects. Recover retains the original scoped
// command observation. Concurrent calls and cancellation follow UnitOfWork;
// each native prepared execution remains single-use. This is constructor-level
// trusted composition, never a dependency supplied by an untrusted request.
type PreparedAccountUnlinkUnitOfWork interface {
	UnitOfWork
	VerifyPreparedAccountUnlink(context.Context, AccountUnlinkCommand) error
}

// PreparedAccountUnlinkRequest carries a native producer's authenticated opaque
// grant and exact intent, not a public JSON request or proof of current access.
// ActorScope comes from authenticated composition. Core policy, configured
// issuer/audience/age, last-access checks and native owner validation still run.
type PreparedAccountUnlinkRequest struct {
	Command    AccountUnlinkCommand
	ActorScope authorization.DecisionContext
}

// NewPreparedAccountUnlinkService explicitly selects retained native preparation
// instead of raw capability-proof ingress. It performs no IO. The trusted UOW
// must validate original cryptographic custody, not merely accept matching IDs.
// The repository must obtain eligibility from real credential/factor owners and
// the UOW must repeat it under its final locks. Existing raw-proof services and
// their verification contract are unchanged; neither mode silently falls back.
func NewPreparedAccountUnlinkService(repo AccountUnlinkRepository, uow PreparedAccountUnlinkUnitOfWork, auth authorization.Service, redact RedactFunc, config AccountUnlinkConfig) (*AccountUnlinkService, error) {
	if nilDependency(uow) {
		return nil, InvalidInputError{Field: "unlink_configuration"}
	}
	s, err := newAccountUnlinkService(repo, uow, auth, redact, config)
	if err != nil {
		return nil, err
	}
	s.prepared = uow
	return s, nil
}

// AccountUnlinkPrepared uses the same core policy, final-access decision,
// command observation and redaction as AccountUnlink, without reconstructing or
// transferring a restored bearer. Only services explicitly configured with the
// trusted prepared producer accept it. Native validation grants no implicit
// authorization and signature validation never consumes the one-use proof.
func (s *AccountUnlinkService) AccountUnlinkPrepared(ctx context.Context, r PreparedAccountUnlinkRequest) (AccountUnlinkResult, error) {
	if s == nil || nilDependency(s.prepared) {
		return AccountUnlinkResult{}, InvalidInputError{Field: "unlink_configuration"}
	}
	spec := r.Command
	request := AccountUnlinkRequest{CommandID: spec.Binding.CommandID, Change: spec.Change,
		SessionID: spec.SessionID, SessionVersion: spec.SessionVersion, RevokeProvider: spec.RevokeProvider,
		ActorScope: r.ActorScope, CorrelationID: spec.Binding.CorrelationID}
	return s.accountUnlink(ctx, request, &spec)
}
