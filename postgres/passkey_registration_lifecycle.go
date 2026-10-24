package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	identity "github.com/faustbrian/go-identity"
)

// PasskeyRegistrationLifecycleContributor persists the canonical credential
// creation and separate account creation lifecycles in the existing outbox,
// inside the sole signup command. It must use both staged profiles, never retain
// Work, close the transaction or perform network IO.
type PasskeyRegistrationLifecycleContributor interface {
	LifecycleContributor
	PersistPasskeyRegistration(context.Context, Work) error
}

// PasskeySignupSessionLifecycleContributor additionally persists the exact
// explicitly staged session creation alongside account and credential events.
// The coordinator requires this trait once session staging is selected; an old
// account-only contributor aborts instead of silently omitting a required event.
// Persist all three through the same Work without IO outside that transaction.
type PasskeySignupSessionLifecycleContributor interface {
	PasskeyRegistrationLifecycleContributor
	PersistPasskeySignupSession(context.Context, Work) error
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

// StagePasskeyRegistrationSession binds the actual session owner's provisional
// creation to the original native signup command during Apply. sessionID must
// equal its closed session.result.session.id field; the actual created user and
// original passkey reference are independently fenced. The native session owner
// must first persist and verify its complete session/family/issuance in this same
// Work. This method itself neither verifies those rows nor issues a credential.
// It creates no journal or event until normal successful audit/lifecycle staging.
// Duplicate/mismatched/foreign staging poisons Work even if the caller ignores
// the error. Existing account-only plans and encoded plan bytes stay unchanged.
func (w Work) StagePasskeyRegistrationSession(ctx context.Context, owner PasskeyRegistrationContributor, command identity.Command, sessionID string) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	fail := func() error { return w.fail(w.state.ctx, invalidLifecycle()) }
	if _, err := identity.ParseIdentifierID(sessionID); err != nil || w.state.passkeySignupSessionID != "" {
		return fail()
	}
	if _, err := w.PasskeyRegistrationUser(ctx, owner, command); err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return fail()
	}
	found := false
	for _, field := range spec.Fields {
		if field.Name == "session.result.session.id" {
			if found || field.Value.Kind != identity.FeatureText || field.Value.Text != sessionID {
				return fail()
			}
			found = true
		}
	}
	p := w.state.execution.reservation.plan.passkeyRegistration
	if !found || p == nil || p.CreationEventIndex == ^uint16(0) || w.state.lifecycle == nil || w.state.lifecycle.plan.EventIndex == ^uint16(0) {
		return fail()
	}
	w.state.passkeySignupSessionID = sessionID
	return nil
}

// StagedPasskeyRegistrationSessionLifecycle returns only an explicitly staged
// original signup session after successful account/credential audit staging.
// Legacy account-only profiles return present=false without inventing an event.
// Its next unused index and effect ID use the existing immutable lifecycle
// derivation; it contains no bearer, CSRF or session payload. The outbox owner
// must persist it in this same Work, not independently acknowledge a commit.
func (w Work) StagedPasskeyRegistrationSessionLifecycle() (event StagedLifecycle, present bool, err error) {
	if err := w.usable(); err != nil {
		return StagedLifecycle{}, false, err
	}
	if w.state.passkeySignupSessionID == "" {
		return StagedLifecycle{}, false, nil
	}
	created, err := w.StagedPasskeyRegistrationLifecycle()
	if err != nil {
		return StagedLifecycle{}, false, err
	}
	primary, err := w.StagedLifecycle()
	if err != nil || len(primary) != 1 {
		return StagedLifecycle{}, false, invalidLifecycle()
	}
	index := max(created.EventIndex, primary[0].EventIndex)
	if index == ^uint16(0) {
		return StagedLifecycle{}, false, invalidLifecycle()
	}
	index++
	b := w.state.binding
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(uint64(index))}))
	return StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: created.UserID, OperationID: b.OperationID, EventType: "session.created.v1", EventIndex: index, SubjectType: "session", SubjectID: w.state.passkeySignupSessionID, BeforeVersion: 0, AfterVersion: 1, OccurredAt: primary[0].OccurredAt}, true, nil
}
