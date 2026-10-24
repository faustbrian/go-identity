package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// QueryEmailVerificationMFAChallenge returns authorized original challenge
// history for one exact separately committed verification parent. The native
// owner must derive RecordID from authenticated original child custody, not an
// unchecked caller claim. It is distinct from anonymous password/magic-link
// history. Only committed history discloses child scope; false identifies the
// ordinary known-empty-factor profile. Pending/aborted records have zero scope.
// This bounded journal query performs no reconciliation, signing, credential
// disclosure or validity renewal. Metadata is not primary or factor authority.
func (c *Coordinator) QueryEmailVerificationMFAChallenge(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (MFAContinuationPlan, CommandRecord, bool, error) {
	_, parentErr := identity.ParseCommandID(q.RecordID)
	if q.OperationID != "identity.email.verification-signin" || q.UserID == "" || q.AnonymousFlowID != "" || parentErr != nil || q.RecordID == string(q.CommandID) {
		return MFAContinuationPlan{}, CommandRecord{}, false, identity.InvalidInputError{Field: "verification_mfa_query"}
	}
	return c.queryPrimaryMFAChallenge(ctx, q, caller, emailVerificationMFAOperation)
}
