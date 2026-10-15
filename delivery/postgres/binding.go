package postgres

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// restore authenticates installed metadata using retained local digest keys,
// without key-provider I/O. Workers must do this before trusting recovered
// scope, then decrypt only outside their lease transaction. It does not grant
// authorization, acquire a lease or renew the original credential's lifetime.
func (c *payloadCodec) restore(wire []byte, envelope identitypostgres.DeliveryEnvelope) (payloadBinding, error) {
	b, err := decodeBinding(wire)
	if err != nil {
		return payloadBinding{}, err
	}
	if err := c.verify(b, envelope); err != nil {
		return payloadBinding{}, err
	}
	return b, nil
}

// decodeBinding reads the installed user and explicit anonymous persistence
// profiles. Framing comes from the pinned secret-envelope Context.AdditionalData
// contract (22fc4a2d925d, context.go): sorted UTF-8 key/value pairs, uint32 BE
// lengths, no count prefix. This is not an envelope or cryptographic parser.
// Rebuilding through custodyContext verifies both the exact owned field set and
// upstream canonical encoding. Reconstruction grants no authority: verify/open
// must authenticate the resulting scope against the original custody.
func decodeBinding(wire []byte) (payloadBinding, error) {
	var b payloadBinding
	if len(wire) == 0 || len(wire) > 16384 {
		return b, delivery.ErrInvalidInput
	}
	values := make(map[string]string, 29)
	remaining := wire
	previous := ""
	for len(remaining) != 0 {
		if len(values) == 29 {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
		key, rest, ok := bindingField(remaining, 256)
		if !ok || key == "" || key <= previous {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
		value, rest, ok := bindingField(rest, 1024)
		if !ok {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
		values[key] = value
		remaining, previous = rest, key
	}
	switch values["profile"] {
	case "identity-delivery-payload-v1":
		if len(values) != 28 {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
	case "identity-delivery-payload-anonymous-v1":
		if len(values) != 29 || values["anonymous_flow"] == "" || values["user"] != "" {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
		b.Command.AnonymousFlowID = values["anonymous_flow"]
	default:
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	b.Deployment = values["deployment"]
	b.Command.CommandID = identity.CommandID(values["command"])
	b.Command.TenantID = identity.TenantID(values["tenant"])
	b.Command.UserID = identity.UserID(values["user"])
	b.Command.ActorID = identity.ActorID(values["actor"])
	b.Command.ActorKind = authorization.SubjectKind(values["actor_kind"])
	b.Command.OperationID = values["operation"]
	b.Command.PolicyID = values["command_policy"]
	b.Command.SchemaID = values["command_schema"]
	b.Command.CorrelationID = values["correlation"]
	b.Command.RecordID = values["record"]
	b.Intent.EffectID = values["effect"]
	b.Intent.Purpose = values["purpose"]
	b.Intent.SubjectID = values["subject"]
	b.Intent.TemplateID = values["template"]
	b.Provider = values["provider"]
	// Parsing all numbers before narrowing prevents wraparound. Canonical decimal
	// spelling is checked by the complete context round trip below.
	for _, field := range []struct {
		name string
		bits int
		set  func(uint64)
	}{
		{"command_policy_version", 64, func(v uint64) { b.Command.PolicyVersion = v }},
		{"command_schema_version", 32, func(v uint64) { b.Command.SchemaVersion = uint32(v) }},
		{"link_mode", 8, func(v uint64) { b.Command.LinkMode = identity.AccountLinkMode(v) }},
		{"effect_index", 16, func(v uint64) { b.Intent.EffectIndex = uint16(v) }},
		{"template_version", 32, func(v uint64) { b.Intent.TemplateVersion = uint32(v) }},
		{"provider_version", 64, func(v uint64) { b.Intent.ProviderConfigVersion = v }},
		{"delivery_policy", 64, func(v uint64) { b.PolicyVersion = v }},
		{"digest_key_version", 32, func(v uint64) { b.DigestKeyVersion = uint32(v) }},
	} {
		v, err := strconv.ParseUint(values[field.name], 10, field.bits)
		if err != nil {
			return payloadBinding{}, delivery.ErrInvalidInput
		}
		field.set(v)
	}
	expiry, err := strconv.ParseInt(values["expiry"], 10, 64)
	if err != nil || expiry <= 0 || expiry > 253402300799999999 {
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	b.Intent.ExpiresAt = time.UnixMicro(expiry).UTC()
	b.NoOpEquivalent, err = strconv.ParseBool(values["no_op"])
	if err != nil {
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	digest, err := hex.DecodeString(values["intent_digest"])
	if err != nil || len(digest) != len(b.Intent.IntentDigest) {
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	copy(b.Intent.IntentDigest[:], digest)
	canonical, err := custodyContext(b, true)
	if err != nil || !bytes.Equal(canonical.AdditionalData(), wire) {
		return payloadBinding{}, delivery.ErrInvalidInput
	}
	return b, nil
}

// Bound lengths before conversion or slicing; strings copy bounded non-secret
// metadata so reconstructed scope does not alias the caller's database buffer.
func bindingField(wire []byte, limit uint32) (string, []byte, bool) {
	if len(wire) < 4 {
		return "", nil, false
	}
	size := binary.BigEndian.Uint32(wire[:4])
	if size > limit || uint64(size) > uint64(len(wire)-4) {
		return "", nil, false
	}
	end := 4 + int(size)
	return string(wire[4:end]), wire[end:], true
}

// Management is intentionally user-only. SQL subject text is not a namespace:
// an anonymous flow can have the same spelling as an unrelated user. Check the
// immutable installed binding before disclosing state or applying an effect.
func decodeUserBinding(wire []byte, deployment, tenant, effect, user string) (payloadBinding, error) {
	b, err := decodeBinding(wire)
	if err != nil {
		return payloadBinding{}, delivery.ErrUnavailable
	}
	if b.Command.AnonymousFlowID != "" || string(b.Command.UserID) != user || b.Deployment != deployment || string(b.Command.TenantID) != tenant || b.Intent.EffectID != effect || b.Intent.SubjectID != user {
		return payloadBinding{}, delivery.ErrNotFound
	}
	return b, nil
}
