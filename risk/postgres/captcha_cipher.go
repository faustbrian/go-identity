package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// CAPTCHA custody has a separate envelope profile: an original response must
// never be transplanted into the existing phone-risk issuance namespace.
func (c recordCipher) sealCaptcha(ctx context.Context, b identity.CommandBinding, r risk.CaptchaEvidenceRecord) ([]byte, error) {
	if ctx == nil || c.service == nil {
		return nil, risk.ErrInvalidEvidenceExecution
	}
	if _, err := risk.ParseCaptchaEvidenceRef(r.Reference.Reveal()); err != nil {
		return nil, risk.ErrInvalidEvidenceExecution
	}
	aad, err := captchaRecordAAD(b, r)
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

func (c recordCipher) openCaptcha(ctx context.Context, b identity.CommandBinding, r risk.CaptchaEvidenceRecord, encoded []byte) (risk.CaptchaEvidenceRecord, error) {
	if ctx == nil || c.service == nil || r.Reference != (risk.CaptchaEvidenceRef{}) || len(encoded) == 0 || len(encoded) > 1024 {
		return risk.CaptchaEvidenceRecord{}, risk.ErrInvalidEvidenceExecution
	}
	aad, err := captchaRecordAAD(b, r)
	if err != nil {
		return risk.CaptchaEvidenceRecord{}, risk.ErrInvalidEvidenceExecution
	}
	e, err := secretenvelope.ParseEnvelope(encoded)
	if err != nil {
		return risk.CaptchaEvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	plaintext, err := c.service.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: e, Context: aad})
	if err != nil {
		return risk.CaptchaEvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	defer clear(plaintext)
	if len(plaintext) < 93 || len(plaintext) > 103 {
		return risk.CaptchaEvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	r.Reference, err = risk.ParseCaptchaEvidenceRef(string(plaintext))
	if err != nil {
		return risk.CaptchaEvidenceRecord{}, risk.ErrEvidenceUnavailable
	}
	return r, nil
}

func captchaRecordAAD(b identity.CommandBinding, r risk.CaptchaEvidenceRecord) (secretenvelope.Context, error) {
	subject := identity.FeatureSubjectUser
	if b.AnonymousFlowID != "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	if b.ValidateFor(CaptchaIssueOperation(subject)) != nil || b.RecordID != string(b.CommandID) || r.KeyVersion == 0 || r.IntentDigest == ([32]byte{}) || r.ProofDigest == ([32]byte{}) || r.EvidenceDigest == ([32]byte{}) || !recordTime(r.IssuedAt) || !recordTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 2*time.Minute || len(r.Hostname) > 253 || !utf8.ValidString(r.Hostname) {
		return secretenvelope.Context{}, risk.ErrInvalidEvidenceExecution
	}
	// Canonical hostname/selected-provider policy is authenticated by the native
	// issue owner. The envelope only binds that exact bounded historical value.
	digest := bindingDigest(b)
	return secretenvelope.NewContext(map[string]string{
		"profile":     "identity-captcha-issued-response-v1",
		"binding":     base64.RawURLEncoding.EncodeToString(digest[:]),
		"intent":      base64.RawURLEncoding.EncodeToString(r.IntentDigest[:]),
		"proof":       base64.RawURLEncoding.EncodeToString(r.ProofDigest[:]),
		"lookup":      base64.RawURLEncoding.EncodeToString(r.EvidenceDigest[:]),
		"hostname":    r.Hostname,
		"key-version": strconv.FormatUint(uint64(r.KeyVersion), 10),
		"issued-at":   r.IssuedAt.Format(time.RFC3339Nano),
		"expires-at":  r.ExpiresAt.Format(time.RFC3339Nano),
	})
}
