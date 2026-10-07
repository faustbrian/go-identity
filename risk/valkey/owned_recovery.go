package valkey

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// ownedRecovery retains native issuance separately from primary verification.
// It reconstructs and applies original facts, never live debit or health. The
// concrete composition owner remains private until joint activation is ready.
type ownedRecovery struct {
	layout    commandLayout
	transport *nativeTransport
	issuer    risk.VelocityNativeIssuer
	reader    risk.VelocityJournalVerifier
}

func (ownedRecovery) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.ownedRecovery(redacted)")
}
func (ownedRecovery) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (ownedRecovery) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

func newOwnedRecovery(layout commandLayout, transport *nativeTransport, issuer risk.VelocityNativeIssuer) (ownedRecovery, error) {
	reader, err := issuer.JournalVerifier()
	if err != nil || transport == nil || !boundedScope(layout.namespace) || len(layout.secret) < 32 {
		return ownedRecovery{}, risk.ErrInvalidPolicy
	}
	return ownedRecovery{layout: layout, transport: transport, issuer: issuer, reader: reader}, nil
}

// restore closes primary checks before IO and rechecks primary custody before
// returning the native acknowledgement. Exact Lua fencing enforces generation
// and original expiry at the effect boundary. Lost/late acknowledgements expose
// no applied custody and never trigger an implicit resend.
func (r ownedRecovery) restore(ctx context.Context, lease risk.VelocityLease, history risk.VelocityHistory, previous risk.VelocityLease) (risk.VelocityAcknowledgement, error) {
	if ctx == nil || r.transport == nil {
		return risk.VelocityAcknowledgement{}, risk.ErrInvalidVelocityRecovery
	}
	bounded, cancel := context.WithTimeout(ctx, r.transport.config.timeout)
	defer cancel()
	plan, snapshot, err := r.layout.history(bounded, r.reader, lease, history)
	if err != nil {
		return risk.VelocityAcknowledgement{}, err
	}
	current, err := r.reader.Lease(lease)
	if err != nil {
		return risk.VelocityAcknowledgement{}, err
	}
	marker, err := ownedRecoveryMarker(current)
	if err != nil {
		return risk.VelocityAcknowledgement{}, err
	}
	oldMarker := ""
	if previous != (risk.VelocityLease{}) {
		old, err := r.reader.Lease(previous)
		if err != nil || old.Tenant != current.Tenant || old.Namespace != current.Namespace {
			return risk.VelocityAcknowledgement{}, risk.ErrInvalidVelocityRecovery
		}
		oldMarker, err = ownedRecoveryMarker(old)
		if err != nil {
			return risk.VelocityAcknowledgement{}, err
		}
	}
	if err := r.transport.recoverFence(bounded, plan, oldMarker, marker); err != nil {
		return risk.VelocityAcknowledgement{}, err
	}
	// Primary noncommit cannot override conflicting native attempt state. Its
	// read-only proof is fenced at server time; pending/unknown never reach IO.
	if len(snapshot) > 0 {
		if err := r.transport.restore(bounded, plan, marker, snapshot); err != nil {
			return risk.VelocityAcknowledgement{}, err
		}
	} else if err := r.transport.confirmNoncommit(bounded, plan, marker); err != nil {
		return risk.VelocityAcknowledgement{}, err
	}
	return r.issuer.Acknowledge(bounded, lease, history)
}

func ownedRecoveryMarker(b risk.VelocityLeaseBinding) (string, error) {
	at := b.ExpiresAt.UnixMicro()
	if at <= 0 || uint64(at) > maximumExactInteger || !b.ExpiresAt.Equal(time.UnixMicro(at)) {
		return "", risk.ErrInvalidVelocityRecovery
	}
	marker := "replaying|" + hex.EncodeToString(b.Epoch[:]) + "|" + strconv.FormatUint(b.Generation, 10) + "|" + hex.EncodeToString(b.Owner[:]) + "|" + strconv.FormatInt(at, 10)
	if _, ok := recoveryFenceFields(marker, hex.EncodeToString(b.Epoch[:])); !ok {
		return "", risk.ErrInvalidVelocityRecovery
	}
	return marker, nil
}
