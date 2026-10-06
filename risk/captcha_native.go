package risk

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// PreparedCaptchaEvidence is a signed, bounded native command projection for
// the official durable adapter, never a transport request or public result.
// It retains the exact original replay aliases, independent intent commitment,
// verifier configuration commitment, proof, nonce and exclusive validity.
// No raw token, provider payload, score, reason text or remote address survives.
// Restoring it grants neither durable issuance nor protected-use authority.
// Encode typed scalars only in the existing coordinator's private command;
// automatic formatting and serialization are redacted or rejected.
type PreparedCaptchaEvidence struct {
	Binding                                            CaptchaIntentBinding
	ConfigurationDigest, ProofDigest, Nonce, Signature [32]byte
	Hostname                                           string
	PreparedAt, ExpiresAt                              time.Time
}

type captchaNativeIntent struct {
	prepared PreparedCaptchaEvidence
	key      EvidenceKey
}

// Prepared returns an independently owned signed projection. Zero returns zero.
// Repeated calls preserve the original nonce, interval and alias set, including
// after restoration; newest configured keys never rewrite existing custody.
func (i CaptchaEvidenceIssue) Prepared() PreparedCaptchaEvidence {
	if i.state == nil {
		return PreparedCaptchaEvidence{}
	}
	s := i.state
	if n := s.intent.state.native; n != nil {
		return clonePreparedCaptcha(n.prepared)
	}
	var binding CaptchaIntentBinding
	for _, b := range s.intent.Bindings() {
		if b.KeyVersion == s.key.version {
			binding = b
			break
		}
	}
	p := PreparedCaptchaEvidence{Binding: binding, ProofDigest: s.proof, Nonce: s.nonce, Hostname: s.hostname, PreparedAt: s.preparedAt, ExpiresAt: s.expiresAt}
	p.ConfigurationDigest = evidenceMAC(s.key.digest, "identity-captcha-configuration-v1", captchaIntentFields(s.intent.state))
	p.Signature = preparedCaptchaSignature(s.key, p)
	return p
}

// RestoreCaptchaIssue authenticates copied native custody without a token,
// provider callback, clock, randomness or IO. Only the configured official
// adapter uses this bridge in shared Work; it must separately enforce current
// policy, authorization, key-rotation history and command/generation ownership.
// Key possession and signature success restore provisional input only, not
// commitment or consumption. Historical expiry remains authentic but cannot
// materialize a new record. Wrong key or malformed input returns a redacted error.
// This key-level form avoids an issuer/executor construction cycle.
func (k EvidenceKey) RestoreCaptchaIssue(p PreparedCaptchaEvidence) (CaptchaEvidenceIssue, error) {
	if k.version == 0 || k.signing == ([32]byte{}) || k.digest == ([32]byte{}) || k.version != p.Binding.KeyVersion {
		return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	flow, ok := validatedPreparedCaptcha(p)
	if !ok {
		return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	want := preparedCaptchaSignature(k, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	p = clonePreparedCaptcha(p)
	i := CaptchaEvidenceIntent{state: &captchaEvidenceIntentState{
		request: CaptchaEvidenceRequest{CommandID: p.Binding.CommandID, Flow: flow},
		replay:  CaptchaReplayIdentity{state: &captchaReplayIdentityState{binding: p.Binding.Replay}},
		native:  &captchaNativeIntent{prepared: p, key: k},
	}}
	return captchaNativeIssue(i), nil
}

// RestoreCaptchaIssue additionally checks the exact current immutable verifier
// configuration and policy, and every originally referenced replay-key version.
// Retained newer keys may coexist; original aliases are never regenerated or
// replaced. The restored intent may only Recover, never Issue or reverify.
// This performs no callbacks or IO and does not renew historical validity.
func (s CaptchaEvidenceIssuer) RestoreCaptchaIssue(p PreparedCaptchaEvidence) (CaptchaEvidenceIssue, error) {
	if s.state == nil || p.Binding.PolicyVersion != s.state.config.Replay.state.config.Policy.state.version {
		return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	for _, k := range s.state.config.Keys {
		if k.version != p.Binding.KeyVersion {
			continue
		}
		issue, err := k.RestoreCaptchaIssue(p)
		if err != nil {
			return CaptchaEvidenceIssue{}, err
		}
		i := issue.state.intent
		i.state.owner = s.state
		c, b := s.state.config.Replay.state.config, p.Binding.Replay
		if b.Provider != c.Provider || b.Site != c.Site || b.APIProfile != c.APIProfile || b.ConfigurationVersion != c.ConfigurationVersion {
			return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
		}
		admitted, err := c.Policy.Admit(b.Flow.Operation)
		if err != nil || admitted.Preflight != "" || !slices.Contains(admitted.Profile.RequiredSignals, "captcha") {
			return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
		}
		for _, alias := range b.Keys {
			found := false
			for _, retained := range c.Keys {
				if retained.version == alias.Version {
					found = true
					break
				}
			}
			if !found {
				return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
			}
		}
		want := evidenceMAC(k.digest, "identity-captcha-configuration-v1", captchaIntentFields(i.state))
		if !hmac.Equal(want[:], p.ConfigurationDigest[:]) {
			return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
		}
		return issue, nil
	}
	return CaptchaEvidenceIssue{}, ErrInvalidEvidenceExecution
}

func captchaNativeIssue(i CaptchaEvidenceIntent) CaptchaEvidenceIssue {
	n := i.state.native
	p := n.prepared
	return CaptchaEvidenceIssue{state: &captchaEvidenceIssueState{intent: i, key: n.key, proof: p.ProofDigest, nonce: p.Nonce, hostname: p.Hostname, preparedAt: p.PreparedAt, expiresAt: p.ExpiresAt}}
}

func cloneCaptchaIntentBinding(b CaptchaIntentBinding) CaptchaIntentBinding {
	b.Replay.Keys = slices.Clone(b.Replay.Keys)
	return b
}
func clonePreparedCaptcha(p PreparedCaptchaEvidence) PreparedCaptchaEvidence {
	p.Binding = cloneCaptchaIntentBinding(p.Binding)
	return p
}

// Bound variable-width metadata before constructing MAC inputs. Replay aliases
// remain signed original facts; this parser cannot derive or authorize aliases.
func validPreparedCaptcha(p PreparedCaptchaEvidence) bool {
	_, ok := validatedPreparedCaptcha(p)
	return ok
}

func validatedPreparedCaptcha(p PreparedCaptchaEvidence) (FlowContext, bool) {
	b, r := p.Binding, p.Binding.Replay
	if !validEvidenceCommandID(b.CommandID) || b.PolicyVersion == 0 || b.KeyVersion == 0 || b.IntentDigest == ([32]byte{}) || p.ConfigurationDigest == ([32]byte{}) || p.ProofDigest == ([32]byte{}) || !databaseEvidenceTime(p.PreparedAt) || !databaseEvidenceTime(p.ExpiresAt) || !p.ExpiresAt.After(p.PreparedAt) || p.ExpiresAt.Sub(p.PreparedAt) > 2*time.Minute || p.Hostname != "" && !captchaHostname(p.Hostname) || len(r.Site) == 0 || len(r.Site) > 512 || !utf8.ValidString(r.Site) || strings.TrimSpace(r.Site) != r.Site || strings.ContainsRune(r.Site, 0) || !scopeID(r.APIProfile) || len(r.ConfigurationVersion) > 64 || !scopeID(r.ConfigurationVersion) || len(r.Keys) == 0 || len(r.Keys) > 16 {
		return FlowContext{}, false
	}
	switch r.Provider {
	case "recaptcha", "turnstile", "hcaptcha", "captchafox":
	default:
		return FlowContext{}, false
	}
	flow, err := NewFlowContext(r.Flow)
	if err != nil {
		return FlowContext{}, false
	}
	for n, alias := range r.Keys {
		if alias.Version == 0 || n > 0 && r.Keys[n-1].Version <= alias.Version || len(alias.Fingerprint) != 43 {
			return FlowContext{}, false
		}
		digest, err := base64.RawURLEncoding.Strict().DecodeString(alias.Fingerprint)
		if err != nil || len(digest) != 32 {
			return FlowContext{}, false
		}
	}
	return flow, true
}

func preparedCaptchaSignature(k EvidenceKey, p PreparedCaptchaEvidence) [32]byte {
	b, r := p.Binding, p.Binding.Replay
	f := r.Flow
	fields := []string{b.CommandID, strconv.FormatUint(b.PolicyVersion, 10), strconv.FormatUint(uint64(b.KeyVersion), 10), string(f.Kind), f.Tenant, string(f.Operation), f.Subject, f.AnonymousFlow, f.PreAuthTransaction, f.Session, f.Actor, f.ChallengeID, f.RequestFingerprint, r.Provider, r.Site, r.APIProfile, r.ConfigurationVersion, base64.RawURLEncoding.EncodeToString(b.IntentDigest[:]), base64.RawURLEncoding.EncodeToString(p.ConfigurationDigest[:]), base64.RawURLEncoding.EncodeToString(p.ProofDigest[:]), base64.RawURLEncoding.EncodeToString(p.Nonce[:]), p.Hostname, evidenceTime(p.PreparedAt), evidenceTime(p.ExpiresAt), strconv.Itoa(len(r.Keys))}
	for _, alias := range r.Keys {
		fields = append(fields, strconv.FormatUint(uint64(alias.Version), 10), alias.Fingerprint)
	}
	// Native restoration must authenticate the digest lane as well as signing:
	// a substituted digest key would change the original lookup candidate.
	digestBinding := evidenceMAC(k.digest, "identity-captcha-prepared-digest-v1", fields)
	fields = append(fields, base64.RawURLEncoding.EncodeToString(digestBinding[:]))
	return evidenceMAC(k.signing, "identity-captcha-prepared-v1", fields)
}

// Format redacts signed native command custody.
func (PreparedCaptchaEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedCaptchaEvidence(redacted)")
}

// MarshalJSON rejects automatic export of native command custody.
func (PreparedCaptchaEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects automatic export of native command custody.
func (PreparedCaptchaEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
