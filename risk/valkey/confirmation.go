package valkey

import (
	"context"
	_ "embed"
	"encoding/hex"

	"github.com/faustbrian/go-identity/risk"
)

//go:embed confirmation.lua
var confirmationScriptBody string

var confirmationScript = publicationProfileScript + confirmationScriptBody

// confirm changes only the exact existing published marker after checking the
// configured primary's recorded confirmation. An identical confirmed marker
// permits an explicit read-only retry, never missing-marker repair. Final primary
// checks precede success; lost/late IO is not success or automatic resend. This
// private checkpoint does not establish whole-counter continuity or public
// healthy admission. The concrete public store remains unactivated.
func (r ownedRecovery) confirm(ctx context.Context, lease risk.VelocityLease, closure risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation) error {
	if ctx == nil || r.transport == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	verifier, err := r.issuer.Verifier()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, r.transport.config.timeout)
	defer cancel()
	b, err := verifier.Confirmation(bounded, lease, closure, publication, confirmation)
	if err != nil {
		return err
	}
	lb, err := r.reader.Lease(lease)
	if err != nil || lb.Namespace != r.layout.replay.Namespace() || !boundedScope(lb.Tenant) {
		return risk.ErrInvalidVelocityRecovery
	}
	original, err := ownedRecoveryMarker(lb)
	if err != nil {
		return err
	}
	published := coveredPublicationMarker(original, b, "published")
	confirmed := coveredPublicationMarker(original, b, "confirmed")
	key := "irv2:{" + r.layout.digest("identity-risk-valkey-slot-v1", lb.Tenant) + "}:health"
	reply, err := r.transport.executeScript(bounded, confirmationScript, []string{key}, []string{published, confirmed})
	if err := recoveryAcknowledgement(reply, err, "confirmed", hex.EncodeToString(b.ID[:])); err != nil {
		return err
	}
	_, err = verifier.Confirmation(bounded, lease, closure, publication, confirmation)
	return err
}
