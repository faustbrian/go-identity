package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	outbox "github.com/faustbrian/go-transactional-outbox/v2"
	outboxpostgres "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// Retained profiles are immutable deployment configuration, never caller-selected
// provider names. Workflow authorization and the public Queue are separate work.
type providerProfile struct {
	name          string
	policyVersion uint64
}

type intentStore struct {
	deployment string
	codec      *payloadCodec
	profiles   map[uint64]providerProfile
	writer     *outboxpostgres.Writer
}

var _ identitypostgres.DeliveryContributor = (*intentStore)(nil)

func newIntentStore(deployment string, codec *payloadCodec, profiles map[uint64]providerProfile) (*intentStore, error) {
	if !safeID(deployment, false) || codec == nil || len(codec.keys) == 0 || len(profiles) < 1 || len(profiles) > 32 {
		return nil, delivery.ErrInvalidInput
	}
	s := &intentStore{deployment: deployment, codec: codec, profiles: make(map[uint64]providerProfile, len(profiles))}
	for version, profile := range profiles {
		if version == 0 || !safeID(profile.name, false) || profile.policyVersion == 0 {
			return nil, delivery.ErrInvalidInput
		}
		s.profiles[version] = profile
	}
	var err error
	s.writer, err = outboxpostgres.NewWriter(outboxpostgres.WriterConfig{MaxBatchSize: 16})
	if err != nil {
		return nil, delivery.ErrUnavailable
	}
	return s, nil
}

func (*intentStore) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}
}

// Deterministic class/index identity is distinct from confidential input identity.
// Fixed framing prevents deployment/tenant concatenation collisions.
func deliveryEffectID(deployment string, b identity.CommandBinding, index uint16) string {
	h := sha256.New()
	_, _ = h.Write([]byte("identity-delivery-effect-v1"))
	var size [4]byte
	for _, v := range []string{deployment, string(b.TenantID), string(b.CommandID), "identity.message"} {
		binary.BigEndian.PutUint32(size[:], uint32(len(v)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(v))
	}
	var position [2]byte
	binary.BigEndian.PutUint16(position[:], index)
	_, _ = h.Write(position[:])
	return hex.EncodeToString(h.Sum(nil))
}

func (s *intentStore) binding(b identity.CommandBinding, i identitypostgres.DeliveryIntentPlan, key uint32, noOp bool) (payloadBinding, error) {
	if s == nil {
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	profile, ok := s.profiles[i.ProviderConfigVersion]
	if !ok {
		return payloadBinding{}, delivery.ErrUnavailable
	}
	result := payloadBinding{Deployment: s.deployment, Command: b, Intent: i, Provider: profile.name, PolicyVersion: profile.policyVersion, DigestKeyVersion: key, NoOpEquivalent: noOp}
	if _, err := custodyContext(result, true); err != nil {
		return payloadBinding{}, err
	}
	return result, nil
}

func (s *intentStore) ValidateDeliveryPlan(b identity.CommandBinding, plan identitypostgres.DeliveryPlan) error {
	if s == nil || plan.Contributor != s.Descriptor() || len(plan.Intents) < 1 || len(plan.Intents) > 16 {
		return delivery.ErrInvalidInput
	}
	for n, i := range plan.Intents {
		if i.EffectID != deliveryEffectID(s.deployment, b, i.EffectIndex) || n > 0 && plan.Intents[n-1].EffectIndex >= i.EffectIndex {
			return delivery.ErrInvalidInput
		}
		// The retained key is authenticated by the envelope at execution; this
		// placeholder validates shape only, and grants no custody or authority.
		if _, err := s.binding(b, i, 1, false); err != nil {
			return err
		}
	}
	return nil
}

type preparedIntent struct {
	binding  payloadBinding
	envelope identitypostgres.DeliveryEnvelope
	aad      []byte
}

func (s *intentStore) prepare(b identity.CommandBinding, plan identitypostgres.DeliveryPlan, envelopes []identitypostgres.DeliveryEnvelope) ([]preparedIntent, error) {
	if err := s.ValidateDeliveryPlan(b, plan); err != nil {
		return nil, err
	}
	if len(envelopes) != len(plan.Intents) {
		return nil, delivery.ErrInvalidInput
	}
	result := make([]preparedIntent, len(envelopes))
	for n, v := range envelopes {
		if len(v.Ciphertext) < 41 || len(v.Ciphertext) > maximumCustody {
			return nil, delivery.ErrInvalidInput
		}
		key := binary.BigEndian.Uint32(v.Ciphertext[5:9])
		if _, exists := s.codec.keys[key]; !exists {
			return nil, delivery.ErrUnavailable
		}
		bound, err := s.binding(b, plan.Intents[n], key, false)
		if err != nil {
			return nil, err
		}
		// The existing envelope profile authenticates the boolean in its AAD.
		// Try the closed two-value domain locally, never decrypt under locks.
		if s.codec.verify(bound, v) != nil {
			bound.NoOpEquivalent = true
			if err := s.codec.verify(bound, v); err != nil {
				return nil, err
			}
		}
		aad, _ := custodyContext(bound, true)
		v.Ciphertext = bytes.Clone(v.Ciphertext)
		result[n] = preparedIntent{binding: bound, envelope: v, aad: aad.AdditionalData()}
	}
	return result, nil
}

// Private SQL adapters keep the sole Work owner, with no transaction constructor,
// closure, provider call or raw driver API exposed to consumers.
type intentExec func(context.Context, string, ...any) (int64, error)
type intentRead func(context.Context, string, ...any) (retainedIntent, bool, error)
type retainedIntent struct {
	aad  []byte
	key  uint32
	noOp bool
}

const intentEvidenceSQL = `SELECT binding_aad,digest_key_version,no_op
 FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`

const insertIntentSQL = `INSERT INTO identity.delivery_intents
 (deployment,tenant_id,effect_id,command_purpose,command_id,effect_index,
 purpose,subject_id,template_id,template_version,provider,provider_version,
 policy_version,intent_digest,digest_key_version,no_op,binding_aad,
 envelope_key_id,ciphertext,state,expires_at,payload_erased_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::numeric,$13::numeric,
 $14,$15,$16,$17,$18,$19,$20,$21,CASE WHEN $16 THEN clock_timestamp() ELSE NULL END WHERE clock_timestamp() < $21
 ON CONFLICT DO NOTHING`

func (s *intentStore) persist(ctx context.Context, intents []preparedIntent, now time.Time, exec intentExec, read intentRead) error {
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return ctx.Err()
		}
		return delivery.ErrInvalidInput
	}
	for _, p := range intents {
		b, i := p.binding, p.binding.Intent
		commandID, err := base64.RawURLEncoding.DecodeString(string(b.Command.CommandID))
		if err != nil || len(commandID) != 16 {
			return delivery.ErrInvalidInput
		}
		state := "planned"
		var ciphertext any = p.envelope.Ciphertext
		var keyID any = p.envelope.KeyID
		if b.NoOpEquivalent {
			state, ciphertext, keyID = "cancelled", nil, nil
		}
		count, err := exec(ctx, insertIntentSQL, b.Deployment, string(b.Command.TenantID), i.EffectID, b.Command.OperationID, commandID, int32(i.EffectIndex), i.Purpose, i.SubjectID, i.TemplateID, int64(i.TemplateVersion), b.Provider, strconv.FormatUint(i.ProviderConfigVersion, 10), strconv.FormatUint(b.PolicyVersion, 10), i.IntentDigest[:], int64(b.DigestKeyVersion), b.NoOpEquivalent, p.aad, keyID, ciphertext, state, i.ExpiresAt)
		if err != nil {
			return delivery.ErrUnavailable
		}
		if count == 0 {
			evidence, exists, err := read(ctx, intentEvidenceSQL, b.Deployment, string(b.Command.TenantID), i.EffectID)
			if err != nil {
				return delivery.ErrUnavailable
			}
			if !exists {
				return delivery.ErrExpired
			}
			if !bytes.Equal(evidence.aad, p.aad) || evidence.key != b.DigestKeyVersion || evidence.noOp != b.NoOpEquivalent {
				return delivery.ErrConflict
			}
			continue
		}
		if count != 1 {
			return delivery.ErrUnavailable
		}
		// Outbox carries only a safe retained-intent handle. Duplicating custody
		// there would make terminal cryptographic erasure depend on another owner.
		prepared, err := s.writer.PrepareInsert([]outbox.Envelope{{ID: i.EffectID, Topic: "identity.delivery.intent.v1", Payload: []byte(i.EffectID), PayloadVersion: 1, Metadata: map[string]string{"deployment": b.Deployment, "tenant": string(b.Command.TenantID)}, IdempotencyKey: "identity.delivery:" + i.EffectID, AvailableAt: now, CreatedAt: now}})
		if err != nil {
			return delivery.ErrUnavailable
		}
		query, args := prepared.Statement()
		if count, err := exec(ctx, query, args...); err != nil || count != 1 {
			return delivery.ErrUnavailable
		}
	}
	return nil
}

func readRetained(ctx context.Context, w identitypostgres.Work, query string, args ...any) (retainedIntent, bool, error) {
	rows, err := w.Query(ctx, query, args...)
	if err != nil {
		return retainedIntent{}, false, err
	}
	defer rows.Close()
	var v retainedIntent
	var key int64
	if !rows.Next() {
		return v, false, rows.Err()
	}
	if err := rows.Scan(&v.aad, &key, &v.noOp); err != nil {
		return retainedIntent{}, false, err
	}
	if rows.Next() || key < 1 || key > 4294967295 {
		return retainedIntent{}, false, delivery.ErrUnavailable
	}
	v.key = uint32(key)
	return v, true, rows.Err()
}

func (s *intentStore) PersistDelivery(ctx context.Context, w identitypostgres.Work) error {
	return s.persistWork(ctx, w, s)
}

func (s *intentStore) persistWork(ctx context.Context, w identitypostgres.Work, owner identitypostgres.DeliveryContributor) error {
	b, plan, err := w.DeliveryScope(owner)
	if err != nil {
		return err
	}
	envelopes, err := w.StagedDelivery(owner)
	if err != nil {
		return err
	}
	intents, err := s.prepare(b, plan, envelopes)
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return s.persist(ctx, intents, now, w.Exec, func(ctx context.Context, query string, args ...any) (retainedIntent, bool, error) {
		return readRetained(ctx, w, query, args...)
	})
}

func (s *intentStore) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	return s.recoverWork(ctx, w, s)
}

func (s *intentStore) recoverWork(ctx context.Context, w identitypostgres.RecoveryWork, owner identitypostgres.DeliveryContributor) (identitypostgres.RecoveryStatus, error) {
	b, plan, err := w.DeliveryScope(owner)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if err := s.ValidateDeliveryPlan(b, plan); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	found := 0
	for _, intent := range plan.Intents {
		rows, err := w.Query(ctx, intentEvidenceSQL, s.deployment, string(b.TenantID), intent.EffectID)
		if err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		var v retainedIntent
		var key int64
		present := rows.Next()
		if present {
			err = rows.Scan(&v.aad, &key, &v.noOp)
		}
		extra := rows.Next()
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil || extra {
			return identitypostgres.RecoveryUnknown, delivery.ErrUnavailable
		}
		if !present {
			continue
		}
		if key < 1 || key > 4294967295 {
			return identitypostgres.RecoveryUnknown, nil
		}
		bound, err := s.binding(b, intent, uint32(key), v.noOp)
		if err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		aad, _ := custodyContext(bound, true)
		if !bytes.Equal(v.aad, aad.AdditionalData()) {
			return identitypostgres.RecoveryUnknown, nil
		}
		found++
	}
	if found == 0 {
		return identitypostgres.RecoveryNotCommitted, nil
	}
	if found == len(plan.Intents) {
		return identitypostgres.RecoveryCommitted, nil
	}
	return identitypostgres.RecoveryUnknown, nil
}
