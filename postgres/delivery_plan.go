package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// DeliveryIntentPlan freezes one original-command effect. IntentDigest is the
// owner's confidential logical-input fingerprint, not a hash of randomized
// ciphertext. It must bind recipient, rendering, provider, no-op policy and all
// other behavior-affecting inputs. Metadata must contain only safe identifiers.
// Expiry is exclusive and never renewed by execution or recovery.
type DeliveryIntentPlan struct {
	EffectID              string
	EffectIndex           uint16
	IntentDigest          [32]byte
	Purpose               string
	SubjectID             string
	TemplateID            string
	TemplateVersion       uint32
	ProviderConfigVersion uint64
	ExpiresAt             time.Time
}

// DeliveryPlan declares 1..16 encrypted effects and their exact versioned
// persistence owner. The contributor must be the last selected participant;
// every effect is required. Nil preserves historical no-delivery bytes.
// This declaration carries no plaintext, ciphertext or authorization proof.
type DeliveryPlan struct {
	Contributor ContributorDescriptor
	Intents     []DeliveryIntentPlan
}

func cloneDeliveryPlan(p *DeliveryPlan) *DeliveryPlan {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Intents = append([]DeliveryIntentPlan(nil), p.Intents...)
	for i := range copy.Intents {
		v := &copy.Intents[i]
		v.EffectID, v.Purpose, v.SubjectID, v.TemplateID = strings.Clone(v.EffectID), strings.Clone(v.Purpose), strings.Clone(v.SubjectID), strings.Clone(v.TemplateID)
		v.ExpiresAt = v.ExpiresAt.UTC()
	}
	return &copy
}

func validDeliveryPlan(p *DeliveryPlan) bool {
	if p == nil || p.Contributor != (ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}) || len(p.Intents) < 1 || len(p.Intents) > 16 {
		return false
	}
	for i, v := range p.Intents {
		if !deliveryIdentifier(v.EffectID) || !deliveryIdentifier(v.SubjectID) || !deliveryIdentifier(v.TemplateID) || !featureEventName(v.Purpose) || v.IntentDigest == ([32]byte{}) || v.TemplateVersion == 0 || v.ProviderConfigVersion == 0 || !postgresExactTime(v.ExpiresAt) || v.ExpiresAt.UnixMicro() <= 0 || i > 0 && p.Intents[i-1].EffectIndex >= v.EffectIndex {
			return false
		}
		for _, prior := range p.Intents[:i] {
			if prior.EffectID == v.EffectID {
				return false
			}
		}
	}
	return true
}

func deliveryIdentifier(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, v := range []byte(s) {
		if v < 33 || v > 126 {
			return false
		}
	}
	return true
}

func encodeDeliveryPlan(p *DeliveryPlan) []byte {
	intents := make([][]byte, len(p.Intents))
	for i, v := range p.Intents {
		intents[i] = cborMap(map[string][]byte{
			"effect_id": cborText(v.EffectID), "effect_index": cborUint(uint64(v.EffectIndex)),
			"intent_digest": cborBytes(v.IntentDigest[:]), "purpose": cborText(v.Purpose),
			"subject_id": cborText(v.SubjectID), "template_id": cborText(v.TemplateID),
			"template_version": cborUint(uint64(v.TemplateVersion)), "provider_version": cborUint(v.ProviderConfigVersion),
			"expires_at": cborUint(uint64(v.ExpiresAt.UnixMicro())),
		})
	}
	return cborMap(map[string][]byte{"intents": cborArray(intents), "contributor": cborMap(map[string][]byte{"owner": cborText(p.Contributor.Owner), "contract_id": cborText(p.Contributor.ContractID), "version": cborUint(uint64(p.Contributor.Version))})})
}

// An optional versioned envelope conserves every historical base-plan byte.
// The declaration is part of the existing journal's digest, not another journal.
func encodeDeliveryWrappedPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan, encode func(identity.CommandBinding, [32]byte, CommandPlan) ([]byte, error)) ([]byte, error) {
	if !validDeliveryPlan(p.Delivery) || p.Lifecycle == nil || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != p.Delivery.Contributor {
		return nil, invalidPlan()
	}
	base := p
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	base.Delivery = nil
	wire, err := encode(b, fp, base)
	if err != nil {
		return nil, err
	}
	result := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("identity-delivery-plan-v1"), "delivery": encodeDeliveryPlan(p.Delivery)})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeDeliveryWrappedPlan(b identity.CommandBinding, fp [32]byte, data []byte, decode func(identity.CommandBinding, [32]byte, []byte) (CommandPlan, error), encode func(identity.CommandBinding, [32]byte, CommandPlan) ([]byte, error)) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 3)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65536 || n > uint64(len(r.data)) || r.data[0] == 0xa3 {
		return fail()
	}
	base, err := decode(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-delivery-plan-v1"))
	r.key("delivery")
	r.expect(5, 2)
	r.key("intents")
	count, ok := r.head(4)
	if !r.ok || !ok || count < 1 || count > 16 {
		return fail()
	}
	d := &DeliveryPlan{Intents: make([]DeliveryIntentPlan, int(count))}
	for i := range d.Intents {
		v := &d.Intents[i]
		r.expect(5, 9)
		r.key("purpose")
		v.Purpose = r.string(128)
		r.key("effect_id")
		v.EffectID = r.string(128)
		r.key("expires_at")
		us := r.number(253402300799999999)
		v.ExpiresAt = time.UnixMicro(int64(us)).UTC()
		r.key("subject_id")
		v.SubjectID = r.string(128)
		r.key("template_id")
		v.TemplateID = r.string(128)
		r.key("effect_index")
		v.EffectIndex = uint16(r.number(math.MaxUint16))
		r.key("intent_digest")
		r.digest(&v.IntentDigest)
		r.key("provider_version")
		v.ProviderConfigVersion = r.number(math.MaxUint64)
		r.key("template_version")
		v.TemplateVersion = uint32(r.number(math.MaxUint32))
	}
	r.key("contributor")
	d.Contributor = readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.Delivery = d
	base.Contributors = append(base.Contributors, d.Contributor)
	canonical, err := encode(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
