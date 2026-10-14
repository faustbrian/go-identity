package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

const preparationHeader = "IDDP1"
const maximumPreparation = 1 << 20

// CheckpointPreparation exports explicitly authenticated encrypted custody for
// the owning workflow's existing command journal. It preserves original effect
// IDs, ciphertext, expiry, policy and recipient fences; it never decrypts,
// generates entropy, performs IO or grants execution authority. generation is
// the original acknowledged preparation generation, not a takeover generation.
// The first successful checkpoint fixes that generation for all copies of p.
// The record is at most 1 MiB; oversized preparation cannot be checkpointed.
// Automatic serialization remains forbidden. Retain the record only under the
// owning workflow's secret-retention policy and original journal provenance.
func (c *Contributor) CheckpointPreparation(ctx context.Context, p PreparedDelivery, generation uint64) ([]byte, error) {
	if ctx == nil || c == nil || c.store == nil || p.state == nil || p.state.owner != c || generation == 0 {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := p.state
	if err := c.store.ValidateDeliveryPlan(s.binding, s.plan); err != nil {
		return nil, err
	}
	if len(s.plan.Intents) < 1 || len(s.plan.Intents) > 16 || len(s.envelopes) != len(s.plan.Intents) || len(s.recipients) != 0 && len(s.recipients) != len(s.envelopes) {
		return nil, delivery.ErrInvalidInput
	}
	version := c.current
	// Restore preserves the original signing key even after active-key rotation.
	if s.checkpointKey != 0 {
		version = s.checkpointKey
	}
	key, ok := c.store.codec.keys[version]
	if !ok {
		return nil, delivery.ErrUnavailable
	}
	wire := append([]byte(preparationHeader), make([]byte, 14)...)
	binary.BigEndian.PutUint32(wire[5:9], version)
	binary.BigEndian.PutUint64(wire[9:17], generation)
	binary.BigEndian.PutUint16(wire[17:19], uint16(len(s.envelopes)))
	for n, envelope := range s.envelopes {
		bound, err := c.preparationBinding(s.binding, s.plan.Intents[n], envelope)
		if err != nil {
			return nil, err
		}
		aad, _ := custodyContext(bound, true)
		for _, field := range [][]byte{aad.AdditionalData(), []byte(envelope.KeyID), envelope.Ciphertext} {
			if len(wire)+4+len(field)+32 > maximumPreparation {
				return nil, delivery.ErrInvalidInput
			}
			wire = binary.BigEndian.AppendUint32(wire, uint32(len(field)))
			wire = append(wire, field...)
		}
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(s.recipients)))
	for _, fence := range s.recipients {
		if _, err := identity.ParseIdentifierID(string(fence.id)); err != nil || fence.version == 0 || fence.authority == 0 {
			return nil, delivery.ErrInvalidInput
		}
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(fence.id)))
		wire = append(wire, string(fence.id)...)
		wire = binary.BigEndian.AppendUint64(wire, fence.version)
		wire = binary.BigEndian.AppendUint64(wire, fence.authority)
	}
	if len(wire)+32 > maximumPreparation {
		return nil, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.checkpointGeneration.CompareAndSwap(0, generation) && s.checkpointGeneration.Load() != generation {
		return nil, delivery.ErrForbidden
	}
	mac := custodyMAC(key, "identity-delivery-preparation-v1", []byte(c.store.deployment), wire)
	return append(wire, mac[:]...), nil
}

// RestorePreparation authenticates a bounded original checkpoint using retained
// local keys and the coordinator-observed original generation and full command
// binding. It creates custody owned by this contributor without decrypting or
// resealing a message. Expired historical custody is preserved, not renewed;
// Stage and native execution still enforce expiry and current authority. Missing
// retained keys/profiles fail closed. No SQL, callbacks or execution takes place.
func (c *Contributor) RestorePreparation(ctx context.Context, binding identity.CommandBinding, generation uint64, wire []byte) (PreparedDelivery, error) {
	bad := func(err error) (PreparedDelivery, error) { return PreparedDelivery{}, err }
	if ctx == nil || c == nil || c.store == nil || generation == 0 || len(wire) < 19+2+32 || len(wire) > maximumPreparation {
		return bad(delivery.ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	if string(wire[:5]) != preparationHeader || binary.BigEndian.Uint64(wire[9:17]) != generation {
		return bad(delivery.ErrForbidden)
	}
	version := binary.BigEndian.Uint32(wire[5:9])
	key, ok := c.store.codec.keys[version]
	if !ok {
		return bad(delivery.ErrUnavailable)
	}
	end := len(wire) - 32
	mac := custodyMAC(key, "identity-delivery-preparation-v1", []byte(c.store.deployment), wire[:end])
	if !hmac.Equal(mac[:], wire[end:]) {
		return bad(delivery.ErrForbidden)
	}
	count := int(binary.BigEndian.Uint16(wire[17:19]))
	if count < 1 || count > 16 {
		return bad(delivery.ErrInvalidInput)
	}
	s := &preparedDelivery{owner: c, binding: binding, checkpointKey: version, plan: identitypostgres.DeliveryPlan{Contributor: c.Descriptor()}}
	s.checkpointGeneration.Store(generation)
	rest := wire[19:end]
	for n := 0; n < count; n++ {
		aad, next, ok := preparationField(rest, 16384)
		if !ok {
			return bad(delivery.ErrInvalidInput)
		}
		rest = next
		keyID, next, ok := preparationField(rest, 128)
		if !ok {
			return bad(delivery.ErrInvalidInput)
		}
		rest = next
		ciphertext, next, ok := preparationField(rest, maximumCustody)
		if !ok {
			return bad(delivery.ErrInvalidInput)
		}
		rest = next
		bound, err := decodeBinding(aad)
		if err != nil || bound.Command != binding || bound.Deployment != c.store.deployment || n > 0 && s.plan.Intents[n-1].EffectIndex >= bound.Intent.EffectIndex {
			return bad(delivery.ErrForbidden)
		}
		envelope := identitypostgres.DeliveryEnvelope{EffectIndex: bound.Intent.EffectIndex, KeyID: string(keyID), Ciphertext: bytes.Clone(ciphertext)}
		matched, err := c.preparationBinding(binding, bound.Intent, envelope)
		if err != nil {
			return bad(err)
		}
		// Preserve the installed AAD exactly, including retained provider policy.
		expected, _ := custodyContext(matched, true)
		if !bytes.Equal(expected.AdditionalData(), aad) {
			return bad(delivery.ErrForbidden)
		}
		s.plan.Intents = append(s.plan.Intents, bound.Intent)
		s.envelopes = append(s.envelopes, envelope)
	}
	if len(rest) < 2 {
		return bad(delivery.ErrInvalidInput)
	}
	fences := int(binary.BigEndian.Uint16(rest[:2]))
	rest = rest[2:]
	if fences != 0 && fences != count {
		return bad(delivery.ErrInvalidInput)
	}
	for n := 0; n < fences; n++ {
		id, next, ok := preparationField(rest, 128)
		if !ok || len(next) < 16 {
			return bad(delivery.ErrInvalidInput)
		}
		parsed, err := identity.ParseIdentifierID(string(id))
		if err != nil {
			return bad(delivery.ErrInvalidInput)
		}
		fence := recipientFence{id: parsed, version: binary.BigEndian.Uint64(next[:8]), authority: binary.BigEndian.Uint64(next[8:16])}
		if fence.version == 0 || fence.authority == 0 {
			return bad(delivery.ErrInvalidInput)
		}
		s.recipients = append(s.recipients, fence)
		rest = next[16:]
	}
	if len(rest) != 0 {
		return bad(delivery.ErrInvalidInput)
	}
	if err := c.store.ValidateDeliveryPlan(binding, s.plan); err != nil {
		return bad(err)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	return PreparedDelivery{state: s}, nil
}

func (c *Contributor) preparationBinding(b identity.CommandBinding, i identitypostgres.DeliveryIntentPlan, v identitypostgres.DeliveryEnvelope) (payloadBinding, error) {
	profile, ok := c.store.profiles[i.ProviderConfigVersion]
	if !ok || len(v.Ciphertext) < 9 {
		return payloadBinding{}, delivery.ErrUnavailable
	}
	bound := payloadBinding{Deployment: c.store.deployment, Command: b, Intent: i, Provider: profile.name, PolicyVersion: profile.policyVersion, DigestKeyVersion: binary.BigEndian.Uint32(v.Ciphertext[5:9])}
	// No-op is authenticated metadata, not a policy inferred from today's input.
	if c.store.codec.verify(bound, v) == nil {
		return bound, nil
	}
	bound.NoOpEquivalent = true
	if err := c.store.codec.verify(bound, v); err != nil {
		return payloadBinding{}, err
	}
	return bound, nil
}

func preparationField(wire []byte, maximum int) ([]byte, []byte, bool) {
	if len(wire) < 4 {
		return nil, nil, false
	}
	n := uint64(binary.BigEndian.Uint32(wire[:4]))
	if n == 0 || n > uint64(maximum) || n > uint64(len(wire)-4) {
		return nil, nil, false
	}
	return wire[4 : 4+int(n)], wire[4+int(n):], true
}
