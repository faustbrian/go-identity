package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// DeliveryContributor is the optional original-command encrypted-effect owner.
// ValidateDeliveryPlan is pure bounded validation, never authorization or IO.
// PersistDelivery is invoked only by the sole coordinator after mutation and
// before commit, using its exact enlisted instance and original Work. It must
// validate authenticated ciphertext/AAD and its confidential logical intent,
// persist custody and outbox admission together, and never call a sender, open
// a transaction, retain Work or stage kernel audit/lifecycle itself. Success is
// provisional. Recovery must inspect retained original bindings, not payload
// presence alone. Implementations support independent concurrent invocations.
// The registered owner must be comparable (normally a pointer): execution and
// recovery require exact instance identity, not descriptor equality.
type DeliveryContributor interface {
	RecoveryContributor
	ValidateDeliveryPlan(identity.CommandBinding, DeliveryPlan) error
	PersistDelivery(context.Context, Work) error
}

// DeliveryEnvelope contains authenticated ciphertext only, never plaintext.
// KeyID refers to the owner's retained secret-envelope key. The owning feature
// prepares encryption before the transaction and must not renew the credential
// or effect expiry. The coordinator does not invent a cryptographic verifier:
// the enlisted delivery owner verifies AAD and logical-input provenance.
type DeliveryEnvelope struct {
	EffectIndex uint16
	KeyID       string
	Ciphertext  []byte
}

func (DeliveryEnvelope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DeliveryEnvelope(redacted)"))
}

// MarshalJSON prevents ciphertext custody from entering diagnostics.
func (DeliveryEnvelope) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText prevents implicit transport of runtime custody.
func (DeliveryEnvelope) MarshalText() ([]byte, error) { return nil, invalidWork() }

type workDelivery struct {
	plan       *DeliveryPlan
	envelopes  map[uint16]DeliveryEnvelope
	bytes      int
	invocation DeliveryContributor
}

// StageDeliveryFor stages ciphertext only for the exact delivery participant
// enlisted in this original Work's frozen plan. Equal descriptors or shared
// configuration do not confer staging ownership. A foreign owner is rejected
// before copying custody. Otherwise StageDelivery's bounds, lifetime and poison
// semantics apply. This is a trusted workflow seam, not recipient authorization;
// the owning workflow must abort on any failure. Work remains serial-use.
func (w Work) StageDeliveryFor(p DeliveryContributor, v DeliveryEnvelope) error {
	if err := w.usable(); err != nil {
		return err
	}
	if w.state.delivery == nil || w.state.execution == nil || w.state.execution.reservation == nil || w.state.execution.reservation.plan == nil {
		return invalidWork()
	}
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor == w.state.delivery.plan.Contributor {
			if !sameParticipant(entry.contributor, p) {
				return invalidWork()
			}
			return w.StageDelivery(v)
		}
	}
	return invalidWork()
}

// StageDelivery copies one predeclared ciphertext during the original mutation.
// Zero/failed/closed Work, undeclared/duplicate indices and unsupported bounds
// fail closed. Each envelope is 1..524288 bytes; aggregate custody is at most
// 1MiB. No SQL runs; this is provisional memory, not queued/provider success.
// Only trusted original-command composition has Work; this method does not
// authenticate a caller or prove that ciphertext contains an admissible intent.
func (w Work) StageDelivery(v DeliveryEnvelope) error {
	if err := w.usable(); err != nil {
		return err
	}
	d := w.state.delivery
	if w.state.registrationAccepted || d == nil || d.invocation != nil || !deliveryIdentifier(v.KeyID) || len(v.Ciphertext) < 1 || len(v.Ciphertext) > 524288 || len(v.Ciphertext) > (1<<20)-d.bytes {
		return w.fail(w.state.ctx, invalidWork())
	}
	declared := false
	for _, intent := range d.plan.Intents {
		if intent.EffectIndex == v.EffectIndex {
			declared = true
			break
		}
	}
	if _, exists := d.envelopes[v.EffectIndex]; !declared || exists {
		return w.fail(w.state.ctx, invalidWork())
	}
	v.Ciphertext = bytes.Clone(v.Ciphertext)
	v.KeyID = strings.Clone(v.KeyID)
	d.envelopes[v.EffectIndex] = v
	d.bytes += len(v.Ciphertext)
	return nil
}

// DeliveryScope returns an owned declaration only during this exact enlisted
// delivery instance's invocation. Descriptor equality does not confer custody.
// The returned binding is the original mutation, never a separate enqueue ID.
func (w Work) DeliveryScope(p DeliveryContributor) (identity.CommandBinding, DeliveryPlan, error) {
	if w.usable() != nil || w.state.delivery == nil || !sameParticipant(w.state.delivery.invocation, p) {
		return identity.CommandBinding{}, DeliveryPlan{}, invalidWork()
	}
	return w.state.binding, *cloneDeliveryPlan(w.state.delivery.plan), nil
}

// StagedDelivery returns copied ciphertext only to the currently invoked exact
// participant. It grants no post-invocation Work or sender authority. Every
// declared intent must be staged, in its declared deterministic order.
func (w Work) StagedDelivery(p DeliveryContributor) ([]DeliveryEnvelope, error) {
	_, plan, err := w.DeliveryScope(p)
	if err != nil {
		return nil, err
	}
	d := w.state.delivery
	if len(d.envelopes) != len(plan.Intents) {
		return nil, invalidWork()
	}
	values := make([]DeliveryEnvelope, len(plan.Intents))
	for i, intent := range plan.Intents {
		v, ok := d.envelopes[intent.EffectIndex]
		if !ok {
			return nil, invalidWork()
		}
		v.Ciphertext = bytes.Clone(v.Ciphertext)
		values[i] = v
	}
	return values, nil
}

// DeliveryScope exposes original frozen inputs only to this exact contributor
// during its recovery invocation. It grants reads, not enqueue or replay work.
func (w RecoveryWork) DeliveryScope(p DeliveryContributor) (identity.CommandBinding, DeliveryPlan, error) {
	if w.usable() != nil || w.state.plan.delivery == nil || w.state.entry.descriptor != w.state.plan.delivery.Contributor || !sameParticipant(w.state.entry.contributor, p) {
		return identity.CommandBinding{}, DeliveryPlan{}, invalidWork()
	}
	return w.state.plan.binding, *cloneDeliveryPlan(w.state.plan.delivery), nil
}

func validateDeliveryContributor(b identity.CommandBinding, p *DeliveryPlan, entries []registeredContributor) (err error) {
	if p == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	for _, entry := range entries {
		if entry.descriptor == p.Contributor {
			owner, ok := entry.contributor.(DeliveryContributor)
			if !ok || !sameParticipant(owner, owner) || owner.ValidateDeliveryPlan(b, *cloneDeliveryPlan(p)) != nil {
				return invalidPlan()
			}
			return nil
		}
	}
	return invalidPlan()
}

func (c *Coordinator) persistDelivery(w Work) (err error) {
	d := w.state.delivery
	if d == nil {
		return nil
	}
	if w.state.registrationAccepted {
		if !w.state.execution.reservation.plan.signupAcceptance || len(d.envelopes) != 0 || d.bytes != 0 {
			return invalidWork()
		}
		return nil
	}
	if len(d.envelopes) != len(d.plan.Intents) {
		return invalidWork()
	}
	if err := deliveryFresh(w); err != nil {
		return err
	}
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor != d.plan.Contributor {
			continue
		}
		owner, ok := entry.contributor.(DeliveryContributor)
		if !ok {
			return invalidWork()
		}
		d.invocation = owner
		defer func() {
			d.invocation = nil
			if recover() != nil {
				err = identity.UnavailableError{}
			}
		}()
		if owner.PersistDelivery(w.state.ctx, w) != nil || w.state.rows != nil || w.usable() != nil {
			return identity.UnavailableError{}
		}
		return nil
	}
	return invalidWork()
}

// A later audit/lifecycle/current-check phase may cross an effect expiry.
// Check again before terminalization; an earlier persistence observation must
// not become permission to commit expired recoverable custody.
func deliveryFresh(w Work) error {
	if w.state.delivery == nil {
		return nil
	}
	now, err := w.DatabaseTime(w.state.ctx)
	if err != nil {
		return err
	}
	for _, intent := range w.state.delivery.plan.Intents {
		if !now.Before(intent.ExpiresAt) {
			return invalidWork()
		}
	}
	return nil
}
