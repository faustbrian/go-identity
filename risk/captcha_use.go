package risk

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// CaptchaEvidenceUseRequest selects a distinct protected consuming command and
// separately verified actor with the exact original trusted flow. Reference is
// presented bearer custody, not authorization. Command/version fingerprinting,
// current authority and atomic reservation/finalization belong to the durable
// coordinator; this request cannot substitute for them. Never log this value.
type CaptchaEvidenceUseRequest struct {
	CommandID, Actor string
	Flow             FlowContext
	Reference        CaptchaEvidenceRef
}

// CaptchaEvidenceUse is an immutable local integrity precheck, not evidence of
// durable issuance, current policy, reservation or permission. Copies preserve
// the original interval and are safe for concurrent reads. Zero is invalid.
type CaptchaEvidenceUse struct{ state *captchaEvidenceUseState }
type captchaEvidenceUseState struct {
	request  CaptchaEvidenceUseRequest
	prepared PreparedCaptchaEvidenceUse
}

// PreparedCaptchaEvidenceUse is bounded signed native custody. Original retains
// the issuance flow/configuration and aliases; Consumer identity is distinct.
// No bearer/token survives this projection. Its keyed lookup linkage must enter
// the consuming command fingerprint alongside all target/version fields. A
// signature alone never establishes journal state or authorizes mutation.
type PreparedCaptchaEvidenceUse struct {
	Original                         PreparedCaptchaEvidence
	ConsumerCommandID, ConsumerActor string
	EvidenceDigest, Signature        [32]byte
	IssuedAt, CheckedAt, ExpiresAt   time.Time
}

// CaptchaEvidenceUseClaim is immutable authenticated native custody only. The
// enlisted participant must independently match current trusted configuration,
// locked journal state, consumer fingerprint/generation and primary expiry.
type CaptchaEvidenceUseClaim struct{ state *PreparedCaptchaEvidenceUse }

// PrecheckUse authenticates original signed issuance and a native record against
// the presented bearer and exact trusted flow. It calls only the configured
// clock, never providers/executors/stores, and cannot prove the record committed.
// Inputs must not be concurrently mutated. Cancellation is preserved; other
// failures are redacted. Sampling the clock never renews original expiry.
func (s CaptchaEvidenceIssuer) PrecheckUse(ctx context.Context, original CaptchaEvidenceIssue, request CaptchaEvidenceUseRequest, record CaptchaEvidenceRecord) (CaptchaEvidenceUse, error) {
	if ctx == nil || s.state == nil || original.state == nil {
		return CaptchaEvidenceUse{}, ErrInvalidEvidenceExecution
	}
	if err := ctx.Err(); err != nil {
		return CaptchaEvidenceUse{}, err
	}
	start := s.state.config.Clock()
	p := original.Prepared()
	current, err := s.RestoreCaptchaIssue(p)
	if err != nil || !captchaUseRequestMatches(request, p) || !hmac.Equal([]byte(request.Reference.value), []byte(record.Reference.value)) || !validCaptchaRecord(current.Intent(), record) {
		return CaptchaEvidenceUse{}, ErrInvalidEvidenceExecution
	}
	now := s.state.config.Clock()
	if err := ctx.Err(); err != nil {
		return CaptchaEvidenceUse{}, err
	}
	if evaluationTime(now, start, start, s.state.config.Timeout) != nil || start.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) {
		return CaptchaEvidenceUse{}, ErrInvalidEvidenceExecution
	}
	prepared := PreparedCaptchaEvidenceUse{Original: p, ConsumerCommandID: request.CommandID, ConsumerActor: request.Actor, EvidenceDigest: record.EvidenceDigest, IssuedAt: record.IssuedAt, CheckedAt: now.UTC(), ExpiresAt: record.ExpiresAt}
	prepared.Signature = captchaUseSignature(current.state.key, prepared)
	return CaptchaEvidenceUse{state: &captchaEvidenceUseState{request: request, prepared: prepared}}, nil
}

func captchaUseRequestMatches(r CaptchaEvidenceUseRequest, original PreparedCaptchaEvidence) bool {
	if r.Flow.state == nil || r.Flow.state.input != original.Binding.Replay.Flow || !validEvidenceCommandID(r.CommandID) || r.CommandID == original.Binding.CommandID || !scopeID(r.Actor) {
		return false
	}
	return r.Flow.state.input.Kind != FlowAdministrator || r.Actor == r.Flow.state.input.Actor
}

// Validate compares the exact proposed consumer, bearer and value-equal flow at
// trusted time. It performs no IO and grants no durable use or permission.
func (u CaptchaEvidenceUse) Validate(request CaptchaEvidenceUseRequest, now time.Time) error {
	if u.state == nil || !captchaUseRequestMatches(request, u.state.prepared.Original) || request.CommandID != u.state.request.CommandID || request.Actor != u.state.request.Actor || !hmac.Equal([]byte(request.Reference.value), []byte(u.state.request.Reference.value)) {
		return ErrInvalidEvidenceExecution
	}
	return (CaptchaEvidenceUseClaim{state: &u.state.prepared}).Validate(now)
}

// Prepared returns an independently owned signed projection, or zero. Mutating
// its alias slice cannot change this proof or another returned projection.
func (u CaptchaEvidenceUse) Prepared() PreparedCaptchaEvidenceUse {
	if u.state == nil {
		return PreparedCaptchaEvidenceUse{}
	}
	return cloneCaptchaUse(u.state.prepared)
}
func cloneCaptchaUse(p PreparedCaptchaEvidenceUse) PreparedCaptchaEvidenceUse {
	p.Original = clonePreparedCaptcha(p.Original)
	return p
}

// RestoreCaptchaUse authenticates both original issuance custody and consuming
// linkage with the retained key pair. No clock/callback/IO runs; expired history
// can restore for reconciliation but cannot Validate at expiry. Inputs are copied.
// Key possession does not establish durable state, configuration or permission.
func (k EvidenceKey) RestoreCaptchaUse(p PreparedCaptchaEvidenceUse) (CaptchaEvidenceUseClaim, error) {
	if _, err := k.RestoreCaptchaIssue(p.Original); err != nil {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	if !validEvidenceCommandID(p.ConsumerCommandID) || p.ConsumerCommandID == p.Original.Binding.CommandID || !scopeID(p.ConsumerActor) || p.Original.Binding.Replay.Flow.Kind == FlowAdministrator && p.ConsumerActor != p.Original.Binding.Replay.Flow.Actor || p.EvidenceDigest == ([32]byte{}) || !databaseEvidenceTime(p.IssuedAt) || !databaseEvidenceTime(p.ExpiresAt) || p.ExpiresAt != p.Original.ExpiresAt || p.IssuedAt.Before(p.Original.PreparedAt) || !p.ExpiresAt.After(p.IssuedAt) || !validTime(p.CheckedAt) || p.CheckedAt.Location() != time.UTC || p.CheckedAt.Before(p.IssuedAt) || !p.CheckedAt.Before(p.ExpiresAt) {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	want := captchaUseSignature(k, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	p = cloneCaptchaUse(p)
	return CaptchaEvidenceUseClaim{state: &p}, nil
}

// RecheckUse additionally admits the exact current immutable verifier profile
// and policy through original signed custody. now must be primary database UTC
// microsecond time from the coordinator, sampled after required locks. It
// preserves original times and runs no callbacks. Journal/authority checks and
// finalization remain mandatory and separate in the same protected transaction.
func (s CaptchaEvidenceIssuer) RecheckUse(original PreparedCaptchaEvidence, p PreparedCaptchaEvidenceUse, now time.Time) (CaptchaEvidenceUseClaim, error) {
	if !databaseEvidenceTime(now) {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	i, err := s.RestoreCaptchaIssue(original)
	if err != nil || !hmac.Equal(original.Signature[:], p.Original.Signature[:]) {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	claim, err := i.state.key.RestoreCaptchaUse(p)
	if err != nil || claim.Validate(now) != nil {
		return CaptchaEvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	return claim, nil
}

// RecheckUse performs the same current-configuration integrity and primary-time
// check without retaining an executable issuer, clock, provider or executor.
// It avoids a native-adapter construction cycle. The returned claim grants no
// journal, reservation or mutation authority; zero custody fails closed.
func (c CaptchaEvidenceCustody) RecheckUse(original PreparedCaptchaEvidence, p PreparedCaptchaEvidenceUse, now time.Time) (CaptchaEvidenceUseClaim, error) {
	return (CaptchaEvidenceIssuer{state: c.state}).RecheckUse(original, p, now)
}

// Prepared returns independent native custody, or zero.
func (c CaptchaEvidenceUseClaim) Prepared() PreparedCaptchaEvidenceUse {
	if c.state == nil {
		return PreparedCaptchaEvidenceUse{}
	}
	return cloneCaptchaUse(*c.state)
}

// Validate enforces the unchanged exclusive interval only, not current authority
// or row state. Historical restoration cannot renew CheckedAt or ExpiresAt.
func (c CaptchaEvidenceUseClaim) Validate(now time.Time) error {
	if c.state == nil || !validTime(now) || now.Before(c.state.CheckedAt) || !now.Before(c.state.ExpiresAt) {
		return ErrInvalidEvidenceExecution
	}
	return nil
}

func captchaUseSignature(k EvidenceKey, p PreparedCaptchaEvidenceUse) [32]byte {
	fields := []string{base64.RawURLEncoding.EncodeToString(p.Original.Signature[:]), p.ConsumerCommandID, p.ConsumerActor, base64.RawURLEncoding.EncodeToString(p.EvidenceDigest[:]), evidenceTime(p.IssuedAt), evidenceTime(p.CheckedAt), evidenceTime(p.ExpiresAt)}
	link := evidenceMAC(k.digest, "identity-captcha-use-linkage-v1", fields)
	return evidenceMAC(k.signing, "identity-captcha-use-v1", append(fields, base64.RawURLEncoding.EncodeToString(link[:])))
}

// Format redacts bearer and private flow/consumer linkage.
func (CaptchaEvidenceUseRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceUseRequest(redacted)")
}

// MarshalJSON rejects sensitive request serialization.
func (CaptchaEvidenceUseRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects sensitive request serialization.
func (CaptchaEvidenceUseRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts authenticated local use custody.
func (CaptchaEvidenceUse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceUse(redacted)")
}

// MarshalJSON rejects authenticated local use serialization.
func (CaptchaEvidenceUse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects authenticated local use serialization.
func (CaptchaEvidenceUse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts signed native consuming custody.
func (PreparedCaptchaEvidenceUse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedCaptchaEvidenceUse(redacted)")
}

// MarshalJSON rejects signed native custody serialization.
func (PreparedCaptchaEvidenceUse) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects signed native custody serialization.
func (PreparedCaptchaEvidenceUse) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts authenticated native consuming custody.
func (CaptchaEvidenceUseClaim) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceUseClaim(redacted)")
}

// MarshalJSON rejects authenticated native custody serialization.
func (CaptchaEvidenceUseClaim) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects authenticated native custody serialization.
func (CaptchaEvidenceUseClaim) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
