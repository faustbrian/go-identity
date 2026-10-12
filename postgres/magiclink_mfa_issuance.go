package postgres

import (
	"encoding/hex"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// A signed child cannot select a customer merely from an anonymous command or
// target declaration. Only the currently invoked native challenge owner can
// borrow its already-consumed primary custody; the complete MFA scope digest
// also fixes methods, browser, remember policy and original primary expiry.
func magicLinkMFAIssuanceSubject(w Work, payload capability.Payload) (identity.UserID, error) {
	if w.state == nil || w.state.issuance == nil || w.state.issuance.plan == nil {
		return "", invalidWork()
	}
	var m MFAContinuationPlan
	var err error
	if owner, ok := w.state.featureInvocation.(PasswordMFAChallengeContributor); ok && w.state.execution != nil && w.state.execution.reservation != nil && passwordMFAOperation(w.state.execution.reservation.plan.snapshot()) {
		m, err = w.PasswordMFAChallenge(owner)
	} else if owner, ok := w.state.featureInvocation.(MagicLinkMFAChallengeContributor); ok {
		m, err = w.MagicLinkMFAChallenge(owner)
	} else {
		return "", invalidWork()
	}
	if err != nil || w.state.issuance.plan.MFAContinuationUserID != m.UserID || payload.Subject != string(m.UserID) || payload.Tenant != string(w.state.binding.TenantID) || payload.ID != string(m.ID) || payload.Operation != "identity.mfa.complete" || payload.Resource != "mfa/continuations/"+string(m.ID) || !payload.IssuedAt.Equal(m.IssuedAt) || !payload.NotBefore.Equal(m.IssuedAt) || !payload.ExpiresAt.Equal(m.ExpiresAt) || len(payload.Caveats) != 2 || payload.Caveats["mfa.profile"] != "identity-mfa-continuation-v1" || payload.Caveats["mfa.scope"] != hex.EncodeToString(m.ScopeDigest[:]) {
		return "", invalidWork()
	}
	return m.UserID, nil
}
