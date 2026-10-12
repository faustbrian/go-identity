package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Original cookie and trusted provenance have already been checked by the
// public recovery owner. This path uses only its original password-free query;
// no comparison, signing, factor attempt, child delivery or session is performed.
func (s *SigninService) recoverMFASignin(ctx context.Context, r password.SigninRecoveryRequest, flow session.PreAuthTransaction, caller authorization.DecisionContext) (password.SigninResult, error) {
	q, _, _ := r.Recovery.Bindings()
	p := &signinMFAChallengePhase{service: s}
	c, _, err := s.mfaCoordinator(p)
	if err != nil {
		return password.SigninResult{}, err
	}
	receipt, receiptErr := c.RecoverFeatureCommand(ctx, q, caller)
	if receipt.Feature == nil {
		return password.SigninResult{}, receiptErr
	}
	spec, _ := flow.Bindings()
	if receipt.Feature.Operation != signinOperation() || receipt.Binding.PolicyID != spec.Binding.Intent.PolicyID || receipt.Binding.PolicyVersion != spec.Binding.Intent.PolicyVersion || receipt.Binding.AnonymousFlowID != string(spec.Binding.ID) {
		return password.SigninResult{}, identity.ForbiddenError{}
	}
	out := password.SigninResult{State: auth.SignInStateRejected, Recovery: r.Recovery, Issuance: session.IssueResult{CommandID: q.CommandID, CommitOutcome: receipt.Outcome, RetryAfter: receipt.RetryAfter, Replayed: true}}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, receiptErr
	}
	scope, record, present, err := c.QueryPasswordMFAChallenge(ctx, q, caller)
	if err != nil {
		return password.SigninResult{}, err
	}
	if !present || record.Binding != receipt.Binding || record.Outcome != receipt.Outcome {
		return password.SigninResult{}, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	if err := s.requireMFASigninHistory(ctx, receipt.Binding, scope); err != nil {
		return password.SigninResult{}, err
	}
	// A slow retained read cannot keep an earlier disclosure grant alive.
	current, record, present, err := c.QueryPasswordMFAChallenge(ctx, q, caller)
	if err != nil {
		return password.SigninResult{}, err
	}
	if !present || current != scope || record.Binding != receipt.Binding || record.Outcome != receipt.Outcome {
		return password.SigninResult{}, identity.UnknownCommitError{CommandID: q.CommandID}
	}
	out.State = auth.SignInStateChallengeRequired
	out.Challenge = password.MFAChallengeResult{ID: scope.ID, Method: "totp", ExpiresAt: scope.ExpiresAt}
	return out, receiptErr
}

func (s *SigninService) requireMFASigninHistory(ctx context.Context, b identity.CommandBinding, scope kernel.MFAContinuationPlan) error {
	cmd, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(cmd) != 16 {
		return password.ErrPasswordWork
	}
	var wire, digest []byte
	err = s.pool.Raw().QueryRow(ctx, `SELECT CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END,record_digest FROM identity_password.mfa_primary_records WHERE tenant_id=$1 AND purpose='identity.password.signin' AND command_id=$2 AND user_id=$3 AND proof_id=$5`, string(b.TenantID), cmd, string(scope.UserID), maximumSigninRecordBytes, string(b.CommandID)).Scan(&wire, &digest)
	defer clear(wire)
	if err != nil {
		return readerFailure(ctx)
	}
	primary, sum, err := decodeMFASigninPrimary(wire, s.c.VerificationKeys, s.c.Issuer, s.c.Environment, auth.ProofID(b.CommandID), string(b.TenantID), string(scope.UserID))
	if err != nil || len(digest) != sha256.Size || subtle.ConstantTimeCompare(digest, sum[:]) != 1 || !primary.Proof.IssuedAt.Equal(scope.IssuedAt) || !primary.Proof.ExpiresAt.Equal(scope.ExpiresAt) {
		return password.ErrPasswordWork
	}
	return nil
}
