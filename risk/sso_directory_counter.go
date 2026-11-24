package risk

import (
	"crypto/sha256"
	"encoding/hex"
)

// DirectorySyncStartCounterResource returns the stable resource dimension for
// one organization's source/provider pair. Inputs must be trusted canonical
// visible-ASCII IDs of 1..128 bytes; this pure encoding establishes no ownership
// or permission. Tenant remains a separate counter dimension. Generation IDs,
// cursors and idempotency keys must not change this resource: otherwise distinct
// start commands could each evade the same directory's privileged budget.
func DirectorySyncStartCounterResource(organizationID, sourceID, providerID string) (string, error) {
	if !scopeID(organizationID) || !scopeID(sourceID) || !scopeID(providerID) {
		return "", ErrInvalidCounterCommand
	}
	h := sha256.New()
	for _, field := range []string{"golib/risk/sso-directory-sync-start/resource/v1", organizationID, sourceID, providerID} {
		writeCounterField(h, field)
	}
	return "sso-directory-v1:" + hex.EncodeToString(h.Sum(nil)), nil
}
