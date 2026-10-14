package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// MagicLinkRegistrationLifecycleContributor persists the normal authentication
// lifecycle and separate account-creation lifecycle in the existing outbox,
// atomically with the same consuming command. It must use both staged profiles
// and may not close Work, retain it, or perform network IO.
type MagicLinkRegistrationLifecycleContributor interface {
	LifecycleContributor
	PersistMagicLinkRegistration(context.Context, Work) error
}

// StagedMagicLinkRegistrationLifecycle returns account creation only after
// actual kernel creation and the command's successful audit/lifecycle staging.
// It contains no address/attributes/proof and is not a durable commit receipt.
func (w Work) StagedMagicLinkRegistrationLifecycle() (StagedLifecycle, error) {
	if err := w.usable(); err != nil {
		return StagedLifecycle{}, err
	}
	if w.state.execution == nil || w.state.execution.reservation == nil {
		return StagedLifecycle{}, invalidWork()
	}
	p := w.state.execution.reservation.plan.magicLinkRegistration
	u := w.state.registrationUser
	if p == nil || u == nil || u.ID != p.UserID || u.Version != 1 || w.state.registrationAccepted {
		return StagedLifecycle{}, invalidWork()
	}
	primary, err := w.StagedLifecycle()
	if err != nil || len(primary) != 1 || primary[0].EventType != "session.created.v1" || primary[0].SubjectType != "authentication_attempt" || primary[0].EventIndex == p.CreationEventIndex {
		return StagedLifecycle{}, invalidLifecycle()
	}
	b := w.state.binding
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(uint64(p.CreationEventIndex))}))
	return StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: u.ID, OperationID: b.OperationID, EventType: "user.created.v1", EventIndex: p.CreationEventIndex, SubjectType: "user", SubjectID: string(u.ID), BeforeVersion: 0, AfterVersion: 1, OccurredAt: primary[0].OccurredAt}, nil
}
