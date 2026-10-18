// Package captcha provides bounded provider-neutral CAPTCHA facts and a callback
// for the risk-owned issuer. It never issues authority or decides risk policy.
package captcha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// VerifyRequest preserves the issuer's opaque original flow and synchronously
// borrowed token. Callers retain token ownership; no replay identity is accepted.
type VerifyRequest = risk.CaptchaVerificationRequest

// Outcome aliases the upstream provider-fact vocabulary, not risk decisions.
type Outcome = risk.CaptchaOutcome

const (
	OutcomeSolved          = risk.CaptchaSolved
	OutcomeRejected        = risk.CaptchaRejected
	OutcomeUnavailable     = risk.CaptchaUnavailable
	OutcomeMalformed       = risk.CaptchaMalformed
	OutcomeThrottled       = risk.CaptchaThrottled
	OutcomeCancelled       = risk.CaptchaCancelled
	OutcomeAmbiguous       = risk.CaptchaAmbiguous
	OutcomeUnsupported     = risk.CaptchaUnsupported
	OutcomeBindingMismatch = risk.CaptchaBindingMismatch
)

var (
	ErrInvalidConfiguration = errors.New("captcha: invalid configuration")
	ErrInvalidRequest       = errors.New("captcha: invalid request")
	ErrInvalidToken         = errors.New("captcha: invalid token")
	ErrBindingMismatch      = errors.New("captcha: binding mismatch")
	ErrProviderUnavailable  = errors.New("captcha: provider unavailable")
	ErrMalformedResponse    = errors.New("captcha: malformed response")
	ErrThrottled            = errors.New("captcha: provider throttled")
	ErrAmbiguousTransport   = errors.New("captcha: ambiguous provider exchange")
	ErrUnsupported          = errors.New("captcha: unsupported capability")
	ErrOverloaded           = errors.New("captcha: caller capacity exhausted")
	errSensitive            = errors.New("captcha: sensitive serialization forbidden")
)

// OptionalString retains absent versus present-empty bounded provider facts.
type OptionalString = risk.CaptchaString

// OptionalTime distinguishes a missing timestamp from a supplied timestamp.
type OptionalTime struct {
	Available bool
	Value     time.Time
}

// ProviderEvidenceKind is a closed native-envelope discriminator. Implemented
// profiles are Turnstile, reCAPTCHA v3, hCaptcha Publisher/Pro and CaptchaFox Free.
type ProviderEvidenceKind uint8

const (
	EvidenceRecaptcha ProviderEvidenceKind = iota + 1
	EvidenceTurnstile
	EvidenceHCaptcha
	EvidenceCaptchaFox
)

// ProviderCapabilities declares exact supported fields for an immutable profile.
// Unsupported fields remain unavailable, never fabricated empty trusted values.
type ProviderCapabilities struct {
	Hostname, Origin, Action, Score, ChallengeTime bool
	ProviderIdempotency, RemoteAddressDisclosure   bool
}

// TurnstileEvidence holds bounded native fields, never an arbitrary metadata map.
// EphemeralID is documented Enterprise metadata; its presence is unsupported in
// the selected free profile and cannot produce solved evidence.
type TurnstileEvidence struct {
	CData, EphemeralID                     OptionalString
	ErrorCodes                             []string
	ErrorCodesAvailable, MetadataAvailable bool
}

// RecaptchaEvidence retains bounded native classic Siteverify codes, including
// safe unknown codes on unusable results. Absent and present-empty stay distinct.
type RecaptchaEvidence struct {
	ErrorCodes          []string
	ErrorCodesAvailable bool
}

// HCaptchaEvidence retains optional deprecated credit and bounded native codes.
// Publisher/Pro has no documented returned sitekey or score reasons: those
// fields stay unavailable, independently of the configured SiteKey attribution.
// Unsupported closed native fields may remain attributable on unusable results.
type HCaptchaEvidence struct {
	ReturnedSiteKey         OptionalString
	CreditAvailable, Credit bool
	ErrorCodesAvailable     bool
	ErrorCodes              []string
	ScoreReasonsAvailable   bool
	ScoreReasons            []string
}

// CaptchaFoxEvidence retains bounded native failure codes, preserving absent
// versus present-empty. The Free profile has no Enterprise insights, returned
// sitekey, action, score or origin evidence; those are never inferred.
type CaptchaFoxEvidence struct {
	ErrorCodes          []string
	ErrorCodesAvailable bool
}

// ProviderEvidence retains bounded authentic native fields and match facts. All
// values are evidence only; provider success alone is not a trusted binding.
type ProviderEvidence struct {
	Provider, API, Version, Tier, APIProfile, SiteKey, ConfigurationVersion string
	Kind                                                                    ProviderEvidenceKind
	Success                                                                 bool
	Hostname, Origin, Action                                                OptionalString
	HostnameMatched, OriginMatched, ActionMatched                           bool
	ChallengeTime                                                           OptionalTime
	ScoreAvailable                                                          bool
	Score                                                                   float64
	ReasonCodes                                                             []string
	Turnstile                                                               *TurnstileEvidence
	Recaptcha                                                               *RecaptchaEvidence
	HCaptcha                                                                *HCaptchaEvidence
	CaptchaFox                                                              *CaptchaFoxEvidence
}

// TransportOutcome describes whether provider consumption is known. Ambiguous
// transport cannot be retried as a new logical operation by this package.
type TransportOutcome uint8

const (
	TransportNotSent TransportOutcome = iota + 1
	TransportResponded
	TransportUnknown
)

// RetryClass is diagnostic advice, not permission to retry or mint new custody.
type RetryClass uint8

const (
	RetryNever RetryClass = iota + 1
	RetrySameLogicalRequest
	RetryNewChallenge
)

// Failure contains only closed safe classifications, never provider diagnostics.
type Failure struct {
	Outcome   Outcome
	Transport TransportOutcome
	Retry     RetryClass
}

// VerifyError preserves stable identities without wrapping untrusted diagnostics.
type VerifyError struct {
	Failure Failure
	Cause   error
}

func (*VerifyError) Error() string   { return "captcha: verification failed" }
func (e *VerifyError) Unwrap() error { return e.Cause }

// ProviderResult is an owned per-caller bounded snapshot. The original Flow and
// CommandID are conserved. Errors invalidate ExpiresAt, never native attribution.
type ProviderResult struct {
	CommandID             string
	Flow                  risk.FlowContext
	Outcome               Outcome
	Evidence              ProviderEvidence
	Failure               Failure
	ObservedAt, ExpiresAt time.Time
}

// Verifier returns facts only. Implementations honor context, borrow Token only
// synchronously and retain no token, replay identity, cache or authority.
type Verifier interface {
	Verify(context.Context, VerifyRequest) (ProviderResult, error)
}

func (ProviderResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.ProviderResult(redacted)")
}
func (ProviderResult) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (ProviderResult) MarshalText() ([]byte, error) { return nil, errSensitive }
func (ProviderEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.ProviderEvidence(redacted)")
}
func (ProviderEvidence) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (ProviderEvidence) MarshalText() ([]byte, error) { return nil, errSensitive }
func (TurnstileEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.TurnstileEvidence(redacted)")
}
func (TurnstileEvidence) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (TurnstileEvidence) MarshalText() ([]byte, error) { return nil, errSensitive }

func (RecaptchaEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.RecaptchaEvidence(redacted)")
}
func (RecaptchaEvidence) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (RecaptchaEvidence) MarshalText() ([]byte, error) { return nil, errSensitive }

func (HCaptchaEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.HCaptchaEvidence(redacted)")
}
func (HCaptchaEvidence) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (HCaptchaEvidence) MarshalText() ([]byte, error) { return nil, errSensitive }

func (CaptchaFoxEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "captcha.CaptchaFoxEvidence(redacted)")
}
func (CaptchaFoxEvidence) MarshalJSON() ([]byte, error) { return nil, errSensitive }
func (CaptchaFoxEvidence) MarshalText() ([]byte, error) { return nil, errSensitive }
