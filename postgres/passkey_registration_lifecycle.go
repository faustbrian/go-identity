package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// PasskeyRegistrationLifecycleContributor persists the canonical credential
// creation and separate account creation lifecycles in the existing outbox,
// inside the sole signup command. It must use both staged profiles and must not
// retain Work, close the transaction or perform network IO.
type PasskeyRegistrationLifecycleContributor interface {
	LifecycleContributor
	PersistPasskeyRegistration(context.Context, Work) error
}

// StagedPasskeyRegistrationLifecycle returns account creation only after actual
// kernel creation and successful primary audit/lifecycle staging. It reveals no
// attributes or authenticator, and is not a durable commit or session receipt.
func (w Work) StagedPasskeyRegistrationLifecycle() (StagedLifecycle, error) {
	if err := w.usable(); err != nil {
		return StagedLifecycle{}, err
	}
	if w.state.execution == nil || w.state.execution.reservation == nil {
		return StagedLifecycle{}, invalidWork()
	}
	p := w.state.execution.reservation.plan.passkeyRegistration
	u := w.state.registrationUser
	if p == nil || u == nil || u.ID != p.UserID || u.Version != 1 || w.state.registrationAccepted {
		return StagedLifecycle{}, invalidWork()
	}
	primary, err := w.StagedLifecycle()
	if err != nil || len(primary) != 1 || primary[0].EventType != "identity.passkey.create_credential" || primary[0].SubjectType != "credential" || primary[0].SubjectID != string(p.CredentialID) || primary[0].EventIndex == p.CreationEventIndex {
		return StagedLifecycle{}, invalidLifecycle()
	}
	b := w.state.binding
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(uint64(p.CreationEventIndex))}))
	return StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: u.ID, OperationID: b.OperationID, EventType: "user.created.v1", EventIndex: p.CreationEventIndex, SubjectType: "user", SubjectID: string(u.ID), BeforeVersion: 0, AfterVersion: 1, OccurredAt: primary[0].OccurredAt}, nil
}
