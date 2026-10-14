package postgres

import identity "github.com/faustbrian/go-identity"

// MagicLinkRegistrationPlan declares the prospective account and identifier,
// exact prepared creation, and admitted email-possession policy. It contains no
// address, credential or caller attributes. The IDs cannot be retargeted when
// an account appears between request and consumption. Declaration is not proof
// of email possession, policy admission or completed creation. Execution remains
// closed until the native creation and lifecycle phases are enlisted.
type MagicLinkRegistrationPlan struct {
	UserID                       identity.UserID
	IdentifierID                 string
	CreationDigest               [32]byte
	EmailPossessionPolicyVersion uint64
	CreationEventIndex           uint16
}

func cloneMagicLinkRegistrationPlan(p *MagicLinkRegistrationPlan) *MagicLinkRegistrationPlan {
	if p == nil {
		return nil
	}
	snapshot := *p
	return &snapshot
}

func validateMagicLinkRegistrationPlan(b identity.CommandBinding, p CommandPlan) error {
	r := p.MagicLinkRegistration
	if r == nil {
		return nil
	}
	user := identity.User{ID: r.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}
	identifier := user
	identifier.ID = identity.UserID(r.IdentifierID)
	if user.Validate(b.TenantID) != nil || identifier.Validate(b.TenantID) != nil || r.CreationDigest == ([32]byte{}) || r.EmailPossessionPolicyVersion == 0 || p.Lifecycle == nil || r.CreationEventIndex == p.Lifecycle.EventIndex {
		return invalidPlan()
	}
	return nil
}

func encodeMagicLinkRegistrationPlan(p *MagicLinkRegistrationPlan) []byte {
	return cborMap(map[string][]byte{
		"user_id":         cborText(string(p.UserID)),
		"event_index":     cborUint(uint64(p.CreationEventIndex)),
		"identifier_id":   cborText(p.IdentifierID),
		"policy_version":  cborUint(p.EmailPossessionPolicyVersion),
		"creation_digest": cborBytes(p.CreationDigest[:]),
	})
}
