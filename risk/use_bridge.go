package risk

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"time"
)

// PreparedEvidenceUse is a signed native-command projection, not transport
// input or an operation result. Binding is the original issuance identity;
// ConsumerCommandID/Actor are separate proposed use identities. Digests retain
// authenticated recovery/configuration/bearer linkage without raw phone,
// network, pre-authentication, attempt or bearer bytes. Times are original,
// never renewed. A declaration alone grants no reservation or mutation rights.
// Copies own every scalar; callers must not mutate inputs during verification.
type PreparedEvidenceUse struct {
	Binding                                EvidenceIntentBinding
	ConsumerCommandID, ConsumerActor       string
	EvidenceDigest, ProofDigest, Signature [32]byte
	IssuedAt, CheckedAt, ExpiresAt         time.Time
}

func (PreparedEvidenceUse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedEvidenceUse(redacted)")
}
func (PreparedEvidenceUse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (PreparedEvidenceUse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Prepared bridges an authentic local precheck to the bounded native command.
// It performs no callbacks or I/O. Zero returns zero; copies cannot change the
// original proof. Only the private authenticated precheck state can sign.
func (p EvidenceUse) Prepared() PreparedEvidenceUse {
	if p.state == nil {
		return PreparedEvidenceUse{}
	}
	s := p.state
	var key EvidenceKey
	for _, k := range s.intent.state.keys {
		if k.version == s.record.KeyVersion {
			key = k
			break
		}
	}
	var binding EvidenceIntentBinding
	for _, b := range s.intent.Bindings() {
		if b.KeyVersion == key.version {
			binding = b
			break
		}
	}
	r := PreparedEvidenceUse{Binding: binding, ConsumerCommandID: s.request.CommandID, ConsumerActor: s.request.Actor, EvidenceDigest: s.record.EvidenceDigest, ProofDigest: s.record.ProofDigest, IssuedAt: s.record.IssuedAt, CheckedAt: s.checkedAt.UTC(), ExpiresAt: s.record.ExpiresAt}
	r.Signature = useEvidenceSignature(key, r)
	return r
}

// EvidenceUseClaim is immutable authenticated native metadata. It cannot
// reconstruct or compare the omitted raw recovery scope and cannot substitute
// for EvidenceUse.Validate. The official adapter must match declared current
// policy, complete consuming command scope, authoritative journal and counters
// in the sole coordinator. Copies support concurrent reads; zero is invalid.
type EvidenceUseClaim struct{ state *PreparedEvidenceUse }

func (EvidenceUseClaim) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceUseClaim(redacted)")
}
func (EvidenceUseClaim) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceUseClaim) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Prepared returns an independent authenticated native scalar copy, or zero.
func (c EvidenceUseClaim) Prepared() PreparedEvidenceUse {
	if c.state == nil {
		return PreparedEvidenceUse{}
	}
	return *c.state
}

// Validate checks only the signed original interval at trusted time. It grants
// no row existence, current policy, caller authority, reservation or use.
func (c EvidenceUseClaim) Validate(now time.Time) error {
	if c.state == nil || !validTime(now) || now.Before(c.state.CheckedAt) || !now.Before(c.state.ExpiresAt) {
		return ErrInvalidEvidenceExecution
	}
	return nil
}

// RestoreUse authenticates bounded native-command scalars under a copied
// startup key pair, without callbacks, I/O or lifetime renewal. Restoration is
// integrity-only: historical expired claims may restore, but cannot Validate
// at expiry. It does not reproduce raw-scope equality or current configuration
// admission; the owned adapter must establish those distinct invariants.
func (k EvidenceKey) RestoreUse(p PreparedEvidenceUse) (EvidenceUseClaim, error) {
	if k.version == 0 || k.signing == ([32]byte{}) || k.digest == ([32]byte{}) || k.version != p.Binding.KeyVersion || !validPreparedUse(p) {
		return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	want := useEvidenceSignature(k, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	return EvidenceUseClaim{state: &p}, nil
}

func validPreparedUse(p PreparedEvidenceUse) bool {
	return validPreparedEvidence(PreparedEvidence{Binding: p.Binding, ProofDigest: p.ProofDigest, PreparedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt}) && validEvidenceCommandID(p.ConsumerCommandID) && p.ConsumerCommandID != p.Binding.CommandID && scopeID(p.ConsumerActor) && p.EvidenceDigest != ([32]byte{}) && validTime(p.CheckedAt) && p.CheckedAt.Location() == time.UTC && !p.CheckedAt.Before(p.IssuedAt) && p.CheckedAt.Before(p.ExpiresAt)
}

func useEvidenceSignature(k EvidenceKey, p PreparedEvidenceUse) [32]byte {
	b := p.Binding
	fields := []string{b.CommandID, b.Tenant, b.Subject, b.Actor, b.Purpose, string(b.Phase), string(b.RecoveryOperation), strconv.FormatUint(b.PolicyVersion, 10), strconv.FormatUint(uint64(b.KeyVersion), 10), base64.RawURLEncoding.EncodeToString(b.IntentDigest[:]), p.ConsumerCommandID, p.ConsumerActor, base64.RawURLEncoding.EncodeToString(p.EvidenceDigest[:]), base64.RawURLEncoding.EncodeToString(p.ProofDigest[:]), evidenceTime(p.IssuedAt), evidenceTime(p.CheckedAt), evidenceTime(p.ExpiresAt)}
	// Bind both independently configured key lanes, so swapping the retained
	// linkage key cannot authenticate a declaration with the old integrity key.
	link := evidenceMAC(k.digest, "identity-risk-evidence-use-linkage-v1", fields)
	return evidenceMAC(k.signing, "identity-risk-evidence-use-v1", append(fields, base64.RawURLEncoding.EncodeToString(link[:])))
}
