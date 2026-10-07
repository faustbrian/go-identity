package valkey

import (
	"context"
	_ "embed"
	"encoding/hex"
	"strconv"

	"github.com/faustbrian/go-identity/risk"
)

//go:embed publication_profile.lua
var publicationProfileScript string

//go:embed publication.lua
var publicationScriptBody string

var publicationScript = publicationProfileScript + publicationScriptBody

// publish requires an existing exact native replay fence, even for a covered
// empty cut. It never reinstalls a lost fence, restores counters or confirms
// primary health. Only exact attributable IO followed by current primary checks
// returns custody. Ambiguous IO exposes none and never triggers a resend.
func (r ownedRecovery) publish(ctx context.Context, lease risk.VelocityLease, closure risk.VelocityClosure) (risk.VelocityPublication, error) {
	if ctx == nil || r.transport == nil {
		return risk.VelocityPublication{}, risk.ErrInvalidVelocityRecovery
	}
	bounded, cancel := context.WithTimeout(ctx, r.transport.config.timeout)
	defer cancel()
	b, err := r.reader.Closure(bounded, lease, closure)
	if err != nil {
		return risk.VelocityPublication{}, err
	}
	lb, err := r.reader.Lease(lease)
	if err != nil || lb.Namespace != r.layout.replay.Namespace() || !boundedScope(lb.Tenant) {
		return risk.VelocityPublication{}, risk.ErrInvalidVelocityRecovery
	}
	original, err := ownedRecoveryMarker(lb)
	if err != nil {
		return risk.VelocityPublication{}, err
	}
	candidate := coveredPublicationMarker(original, b, "published")
	key := "irv2:{" + r.layout.digest("identity-risk-valkey-slot-v1", lb.Tenant) + "}:health"
	reply, err := r.transport.executeScript(bounded, publicationScript, []string{key}, []string{original, candidate})
	if err := recoveryAcknowledgement(reply, err, "published", hex.EncodeToString(b.ID[:])); err != nil {
		return risk.VelocityPublication{}, err
	}
	return r.issuer.AcknowledgePublication(bounded, lease, closure)
}

// Callers supply only a validated ownedRecoveryMarker and checked core facts.
// Publication and confirmation must encode every original cut field identically.
func coveredPublicationMarker(original string, b risk.VelocityClosureBinding, state string) string {
	return state + original[len("replaying"):] + "|" + hex.EncodeToString(b.ID[:]) + "|" + strconv.FormatInt(b.Position, 10) + "|" + strconv.FormatInt(b.ReplayFrom.UnixMicro(), 10) + "|" + strconv.FormatInt(b.ReplayThrough.UnixMicro(), 10) + "|" + strconv.FormatInt(b.JournalStartedAt.UnixMicro(), 10) + "|" + strconv.FormatInt(b.MaximumWindow.Microseconds(), 10)
}
