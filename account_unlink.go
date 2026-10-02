package identity

import (
	"fmt"
	"io"
	"time"
)

// AccountUnlinkState is the complete primary state at the durable unlink lock
// boundary. AccountID binds SocialLinkVersion to that exact connection;
// CredentialVersion is the tenant/user credential authority dimension, not a
// credential record version. All versions are positive. Access must include
// every current account and owner-validated login eligibility observation.
// This projection is not an authentication proof and must never be client input.
type AccountUnlinkState struct {
	Access            AccountAccessSnapshot
	AccountID         AccountID
	SocialLinkVersion uint64
	CredentialVersion uint64
}

// AccountUnlinkChange specifies exact optimistic fences for one unlink. It is
// structural intent, not authorization, freshness or a command receipt. The
// command owner authorizes and validates fresh subject/session/credential proof
// independently, then locks primary state and supplies it to ApplyAccountUnlink.
type AccountUnlinkChange struct {
	TenantID                  TenantID
	UserID                    UserID
	AccountID                 AccountID
	ExpectedUserVersion       uint64
	ExpectedAccountVersion    uint64
	ExpectedSocialLinkVersion uint64
	ExpectedCredentialVersion uint64
}

// AccountUnlinkMutation is a privately copied proposed next state, not a durable
// outcome. Removed identifies the exact original link; TombstoneVersion must
// remain durable after removal, preventing stale callbacks from restoring it.
// SocialLinkVersion always advances. CredentialVersion advances exactly once
// only when an authentication link was removed, even if already expired.
// The user aggregate advances without changing the separate user-authority
// dimension. Provider cleanup and session revocation are not claimed complete.
type AccountUnlinkMutation struct {
	Access                AccountAccessSnapshot
	Removed               Account
	TombstoneVersion      uint64
	SocialLinkVersion     uint64
	CredentialVersion     uint64
	InvalidatesCredential bool
}

// Format redacts the entire primary account/credential projection.
func (AccountUnlinkState) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountUnlinkState(redacted)")
}

// Format redacts the proposed next state and removed-link metadata.
func (AccountUnlinkMutation) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.AccountUnlinkMutation(redacted)")
}

// ApplyAccountUnlink computes one all-or-nothing identity-owned transition from
// locked current state. It rechecks final access rather than trusting an earlier
// plan, fences aggregate/account/social-link/credential versions and removes all
// target-dependent credentials. It performs no I/O, mutates no input and owns no
// locks or goroutines. Do not mutate supplied slices concurrently with a call.
//
// The platform durable command owner must check same-command replay first,
// establish exact authorization/freshness and authoritative eligibility under
// locks, then persist this state, tombstone, authority events, audit, cleanup
// intents and original command receipt atomically with applicable one-use
// proofs/risk. This function alone neither consumes proofs nor proves a commit.
// Errors return no partial mutation. Clock is one trusted owner sample; expiry
// is exclusive. Provider credentials remain with their owner until enlisted
// deletion/revocation is durably initiated, never discarded by this pure step.
func ApplyAccountUnlink(state AccountUnlinkState, change AccountUnlinkChange, now time.Time) (AccountUnlinkMutation, error) {
	zero := AccountUnlinkMutation{}
	if !validDirectoryID(string(change.TenantID)) || !validDirectoryID(string(change.UserID)) || !validDirectoryID(string(change.AccountID)) || state.AccountID != change.AccountID ||
		!unlinkVersion(state.SocialLinkVersion) || !unlinkVersion(state.CredentialVersion) ||
		!unlinkVersion(change.ExpectedUserVersion) || !unlinkVersion(change.ExpectedAccountVersion) ||
		!unlinkVersion(change.ExpectedSocialLinkVersion) || !unlinkVersion(change.ExpectedCredentialVersion) {
		return zero, InvalidInputError{Field: "account_unlink_state"}
	}
	if state.Access.User.Validate(change.TenantID) != nil || state.Access.User.ID != change.UserID {
		return zero, InvalidInputError{Field: "account_unlink_scope"}
	}
	if state.Access.User.Version != change.ExpectedUserVersion || state.SocialLinkVersion != change.ExpectedSocialLinkVersion || state.CredentialVersion != change.ExpectedCredentialVersion {
		return zero, ConflictError{}
	}
	plan, err := CheckAccountUnlink(state.Access, change.TenantID, change.UserID, change.AccountID, change.ExpectedAccountVersion, now)
	if err != nil {
		return zero, err
	}
	next := AccountAccessSnapshot{User: state.Access.User, Accounts: make([]Account, 0, len(state.Access.Accounts)-1), Methods: make([]LoginMethod, 0, len(state.Access.Methods))}
	next.User.Version++
	for _, account := range state.Access.Accounts {
		if account.ID != change.AccountID {
			next.Accounts = append(next.Accounts, account)
		}
	}
	for _, method := range state.Access.Methods {
		if method.AccountID != change.AccountID {
			next.Methods = append(next.Methods, method)
		}
	}
	credentialVersion := state.CredentialVersion
	if plan.InvalidatesCredential {
		credentialVersion++
	}
	return AccountUnlinkMutation{Access: next, Removed: plan.Account, TombstoneVersion: plan.Account.Version + 1, SocialLinkVersion: state.SocialLinkVersion + 1, CredentialVersion: credentialVersion, InvalidatesCredential: plan.InvalidatesCredential}, nil
}

func unlinkVersion(v uint64) bool { return v > 0 && v < ^uint64(0) }
