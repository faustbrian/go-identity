package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// QueryPasskeyMFAChallenge observes the exact original self-user UV assertion's
// challenge-only journal profile under current query authorization. The native
// owner must derive scope from authenticated original child/browser custody,
// never an unchecked target. Only committed history discloses frozen child
// scope; pending/aborted results contain zero scope. False denotes ordinary
// passkey signin, not absence or rollback. No assertion/factor verification,
// signing, reconciliation, mutation, credential disclosure or renewal occurs.
func (c *Coordinator) QueryPasskeyMFAChallenge(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (MFAContinuationPlan, CommandRecord, bool, error) {
	if q.OperationID != passkeyMFAPrimaryOperation().OperationID || q.UserID == "" || q.AnonymousFlowID != "" || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) || q.RecordID != string(q.CommandID) {
		return MFAContinuationPlan{}, CommandRecord{}, false, identity.InvalidInputError{Field: "passkey_mfa_query"}
	}
	return c.queryPrimaryMFAChallenge(ctx, q, caller, passkeyMFAOperation)
}
