package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	secretenvelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// The concrete copied local keyring prevents a network key-provider callback
// from running inside Work. Stable references must remain available for every
// retained encrypted response. No caller can inject a Service or entropy reader.
type recordCipher struct {
	service *secretenvelope.Service
	current string
}

func newRecordCipher(keys map[string][]byte, current string) (recordCipher, error) {
	if len(keys) == 0 || len(keys) > 16 || len(current) == 0 || len(current) > 128 {
		return recordCipher{}, risk.ErrInvalidPolicy
	}
	if _, ok := keys[current]; !ok {
		return recordCipher{}, risk.ErrInvalidPolicy
	}
	for reference, key := range keys {
		if len(reference) == 0 || len(reference) > 128 || len(key) != 32 {
			return recordCipher{}, risk.ErrInvalidPolicy
		}
		var nonzero byte
		for _, b := range key {
			nonzero |= b
		}
		if nonzero == 0 {
			return recordCipher{}, risk.ErrInvalidPolicy
		}
		for i := range len(reference) {
			b := reference[i]
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
				return recordCipher{}, risk.ErrInvalidPolicy
			}
		}
	}
	p, err := keyring.New(keys)
	if err != nil {
		return recordCipher{}, risk.ErrInvalidPolicy
	}
	s, err := secretenvelope.NewService(p)
	if err != nil {
		return recordCipher{}, risk.ErrInvalidPolicy
	}
	return recordCipher{service: s, current: current}, nil
}

func (c recordCipher) seal(ctx context.Context, b identity.CommandBinding, r risk.EvidenceRecord) ([]byte, error) {
	if ctx == nil || c.service == nil || r.Reference.Reveal() == "" {
		return nil, risk.ErrInvalidEvidenceExecution
	}
	aad, err := recordAAD(b, r)
	if err != nil {
		return nil, risk.ErrInvalidEvidenceExecution
	}
	plaintext := []byte(r.Reference.Reveal())
	defer clear(plaintext)
	e, err := c.service.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: plaintext, KeyReference: c.current, Context: aad})
	if err != nil {
		return nil, risk.ErrEvidenceUnavailable
	}
	encoded, err := e.MarshalBinary()
	if err != nil || len(encoded) > 1024 {
		return nil, risk.ErrEvidenceUnavailable
	}
	return encoded, nil
}

func (c recordCipher) open(ctx context.Context, b identity.CommandBinding, r risk.EvidenceRecord, encoded []byte) (risk.EvidenceRecord, error) {
	if ctx == nil || c.service == nil || r.Reference != (risk.RiskEvidenceRef{}) || len(encoded) > 1024 {
		return risk.EvidenceRecord{}, risk.ErrInvalidEvidenceExecution
	}
	aad, err := recordAAD(b, r)
	if err != nil {
		return risk.EvidenceRecord{}, risk.ErrInvalidEvidenceExecution
	}
	e, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		return risk.EvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	plaintext, err := c.service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: e, Context: aad})
	if err != nil {
		return risk.EvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	defer clear(plaintext)
	if len(plaintext) < 93 || len(plaintext) > 103 {
		return risk.EvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	r.Reference, err = risk.ParseRiskEvidenceRef(string(plaintext))
	if err != nil {
		return risk.EvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	return r, nil
}

func recordAAD(b identity.CommandBinding, r risk.EvidenceRecord) (secretenvelope.Context, error) {
	if b.ValidateFor(IssueOperation()) != nil || r.KeyVersion == 0 || r.IntentDigest == ([32]byte{}) || r.ProofDigest == ([32]byte{}) || r.EvidenceDigest == ([32]byte{}) || !recordTime(r.IssuedAt) || !recordTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 2*time.Minute {
		return secretenvelope.Context{}, risk.ErrInvalidEvidenceExecution
	}
	digest := bindingDigest(b)
	return secretenvelope.NewContext(map[string]string{"profile": "identity-risk-issued-response-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:]), "intent": base64.RawURLEncoding.EncodeToString(r.IntentDigest[:]), "proof": base64.RawURLEncoding.EncodeToString(r.ProofDigest[:]), "lookup": base64.RawURLEncoding.EncodeToString(r.EvidenceDigest[:]), "key-version": strconv.FormatUint(uint64(r.KeyVersion), 10), "issued-at": r.IssuedAt.Format(time.RFC3339Nano), "expires-at": r.ExpiresAt.Format(time.RFC3339Nano)})
}
func recordTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
func bindingDigest(b identity.CommandBinding) [32]byte {
	// Closed bounded non-secret scope only, never bearer or raw request facts.
	encoded, _ := json.Marshal(b)
	return sha256.Sum256(append([]byte("identity-risk-issued-binding-v1\x00"), encoded...))
}
