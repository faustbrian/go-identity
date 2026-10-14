package mfa

import (
	"context"
	"fmt"
	"log/slog"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// RecoveryUseRequest borrows the distinct opaque recovery code and original
// child/browser custody for login completion. It never selects a user, factor,
// set epoch, remember policy, expiry or authority generation. Trusted transport
// supplies tenant/caller/origin/network/device; the native owner authenticates
// the original child and consumed primary browser flow before bounded digest
// lookup under current account/factor/policy locks. No secret may be serialized,
// retained in scalar command metadata or coerced into an OTP credential.
type RecoveryUseRequest struct {
	TenantID                          identity.TenantID
	CommandID                         identity.CommandID
	ContinuationID                    ContinuationID
	RecoveryCode                      auth.RecoveryCode
	Proof                             capability.Proof
	PreAuthID                         identity.PreAuthTransactionID
	Cookie                            auth.BearerCredential
	Caller                            authorization.DecisionContext
	Origin, Callback, Network, Device string
}

// Validate checks bounded original structure only, with no IO, proof transfer,
// code comparison, charge or consumption. A well-formed wrong code still reaches
// the native shared-attempt policy. Primitive construction owns ASCII bounds;
// current key versions, set state and actual single-use burn remain native checks.
func (r RecoveryUseRequest) Validate() error {
	bad := func() error { return identity.InvalidInputError{Field: "mfa_recovery_use"} }
	if !validContinuationBrowserInput(continuationBrowserInput{tenant: r.TenantID, command: r.CommandID, continuation: r.ContinuationID, flow: r.PreAuthID, proof: r.Proof, cookie: r.Cookie, caller: r.Caller, origin: r.Origin, callback: r.Callback, network: r.Network, device: r.Device}, "identity.mfa.recovery-use") {
		return bad()
	}
	// Discarded public-key digest checks only nonzero primitive custody. It is
	// never stored or compared with a recovery-set digest to authenticate input.
	digest, err := r.RecoveryCode.KeyedDigest([32]byte{1}, []byte("mfa.recovery.input.validation"))
	clear(digest[:])
	if err != nil {
		return bad()
	}
	return nil
}

// RecoveryUseResult separates durable outcome from ephemeral credential
// delivery. Only a fresh error-free commit may carry session/CSRF custody;
// retries, cancellation, ambiguity and recovery carry neither. Session metadata
// is historical, not current authority. RecoveryRequired reports the committed
// policy's remaining remediation, not proof that any second factor was enrolled;
// false must not be interpreted as successful recovery on a noncommitted outcome.
type RecoveryUseResult struct {
	Outcome          identity.CommitOutcome
	Session          session.IssueResult
	RecoveryRequired bool
	CSRFToken        session.CSRFToken
}

// RecoveryCompletionService is the narrow recovery-code portion of the MFA
// service. Native composition owns bounded lookup, shared attempts, original
// intent/replay, atomic burn/child/session/risk/audit and rollback. Consumers
// provide policy/configuration, not missing domain stores. Recovery is code and
// proof free, reconciles the original command and can never redeliver a bearer
// or repeat original primary authentication after an uncertain outcome.
type RecoveryCompletionService interface {
	RecoveryUse(context.Context, RecoveryUseRequest) (RecoveryUseResult, error)
	RecoverRecoveryUse(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (RecoveryUseResult, error)
}

// Format redacts original code, proof and browser custody for every verb.
func (RecoveryUseRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RecoveryUseRequest(redacted)"))
}

// MarshalJSON rejects implicit request/credential export.
func (RecoveryUseRequest) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text/map-key export.
func (RecoveryUseRequest) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts correlated request custody.
func (RecoveryUseRequest) LogValue() slog.Value {
	return slog.StringValue("mfa.RecoveryUseRequest(redacted)")
}

// Format redacts ephemeral delivery and correlated result metadata.
func (RecoveryUseResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RecoveryUseResult(redacted)"))
}

// MarshalJSON rejects implicit reveal-once result export.
func (RecoveryUseResult) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText rejects implicit text/map-key export.
func (RecoveryUseResult) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts credential delivery and recovery correlation.
func (RecoveryUseResult) LogValue() slog.Value {
	return slog.StringValue("mfa.RecoveryUseResult(redacted)")
}
