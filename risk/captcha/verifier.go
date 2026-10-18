package captcha

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// Client owns only bounded synchronous verification and copied configuration.
// It holds no locks across callbacks, starts no goroutines and owns no replay,
// audit queue, provider lifecycle or durable state. Zero is invalid. The host
// must stop calls before shutting down its borrowed verifier and clock.
type Client struct {
	config    Config
	provider  Verifier
	admission chan struct{}
}

// New copies validated configuration and borrows a concurrent-safe verifier.
// Only explicitly supported profiles are implemented; other selections fail
// closed. Returned provider facts are revalidated before risk projection.
func New(config Config, provider Verifier) (*Client, error) {
	if !config.valid() || nilDependency(provider) {
		return nil, ErrInvalidConfiguration
	}
	config.Hostnames, config.Origins = slices.Clone(config.Hostnames), slices.Clone(config.Origins)
	return &Client{config: config, provider: provider, admission: make(chan struct{}, config.MaxConcurrent)}, nil
}

func failed(result ProviderResult, outcome Outcome, cause error) (ProviderResult, error) {
	result.Outcome = outcome
	result.ExpiresAt = time.Time{}
	result.Failure.Outcome = outcome
	if result.Failure.Transport < TransportNotSent || result.Failure.Transport > TransportUnknown {
		result.Failure.Transport = TransportNotSent
	}
	if result.Failure.Retry < RetryNever || result.Failure.Retry > RetryNewChallenge {
		result.Failure.Retry = RetryNever
	}
	return result, &VerifyError{Failure: result.Failure, Cause: cause}
}

// Verify performs one bounded provider call. Native evidence remains separately
// attributable on rejection/mismatch; no failed result has usable validity.
// There is no automatic retry, coalescing, token cache or fallback success.
func (c *Client) Verify(ctx context.Context, request VerifyRequest) (ProviderResult, error) {
	result := ProviderResult{CommandID: request.CommandID, Flow: request.Flow}
	if c == nil || c.provider == nil || c.admission == nil {
		return failed(result, OutcomeUnavailable, ErrInvalidConfiguration)
	}
	if ctx == nil || request.Flow == (risk.FlowContext{}) {
		return failed(result, OutcomeRejected, ErrInvalidRequest)
	}
	if _, err := identity.ParseCommandID(request.CommandID); err != nil {
		return failed(result, OutcomeRejected, ErrInvalidRequest)
	}
	if len(request.Token) == 0 || len(request.Token) > c.config.MaxTokenBytes || !utf8.Valid(request.Token) {
		return failed(result, OutcomeRejected, ErrInvalidToken)
	}
	if err := ctx.Err(); err != nil {
		return failed(result, OutcomeCancelled, err)
	}
	select {
	case c.admission <- struct{}{}:
		defer func() { <-c.admission }()
	default:
		return failed(result, OutcomeUnavailable, ErrOverloaded)
	}
	start := c.config.Clock.Now().UTC()
	if start.IsZero() {
		return failed(result, OutcomeUnavailable, ErrProviderUnavailable)
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if err := expired(bounded); err != nil {
		return failed(result, OutcomeCancelled, err)
	}
	result, err := c.provider.Verify(bounded, request)
	if result.Failure.Transport < TransportNotSent || result.Failure.Transport > TransportUnknown {
		result.Failure.Transport = TransportUnknown
	}
	// Match flags are trusted local comparisons, never provider assertions.
	result.Evidence.HostnameMatched, result.Evidence.OriginMatched, result.Evidence.ActionMatched = false, false, false
	// Validate bounded snapshots before copying provider-owned slices or retaining
	// a provider field on any error/cancellation path.
	if !boundedResult(result) || !validNativeUnion(result.Evidence) {
		result = ProviderResult{CommandID: request.CommandID, Flow: request.Flow, Failure: Failure{Transport: TransportUnknown}}
		if cancelErr := bounded.Err(); cancelErr != nil {
			return failed(result, OutcomeCancelled, cancelErr)
		}
		return failed(result, OutcomeMalformed, ErrMalformedResponse)
	}
	result = cloneResult(result)
	if cancelErr := bounded.Err(); cancelErr != nil {
		return failed(result, OutcomeCancelled, cancelErr)
	}
	deadline, _ := bounded.Deadline()
	if !time.Now().Before(deadline) {
		return failed(result, OutcomeCancelled, context.DeadlineExceeded)
	}
	now := c.config.Clock.Now().UTC()
	if now.IsZero() || now.Before(start) {
		return failed(result, OutcomeUnavailable, ErrProviderUnavailable)
	}
	if result.CommandID != request.CommandID || result.Flow != request.Flow || !c.sameProfile(result.Evidence) {
		return failed(result, OutcomeBindingMismatch, ErrBindingMismatch)
	}
	result.Evidence.HostnameMatched = result.Evidence.Hostname.Available && slices.Contains(c.config.Hostnames, result.Evidence.Hostname.Value)
	result.Evidence.ActionMatched = result.Evidence.Action.Available && result.Evidence.Action.Value == c.config.ExpectedAction
	if err != nil {
		var safe *VerifyError
		if errors.As(err, &safe) && safe != nil && safe.Failure.Outcome >= OutcomeRejected && safe.Failure.Outcome <= OutcomeBindingMismatch {
			return failed(result, safe.Failure.Outcome, safeCause(safe.Failure.Outcome))
		}
		return failed(result, OutcomeAmbiguous, ErrAmbiguousTransport)
	}
	if !c.validEnvelope(result.Evidence) {
		return failed(result, OutcomeMalformed, ErrMalformedResponse)
	}
	if result.Outcome < OutcomeSolved || result.Outcome > OutcomeBindingMismatch || (result.Outcome == OutcomeSolved) != result.Evidence.Success {
		return failed(result, OutcomeMalformed, ErrMalformedResponse)
	}
	if result.Outcome != OutcomeSolved || !result.Evidence.Success {
		return failed(result, result.Outcome, safeCause(result.Outcome))
	}
	evidence := &result.Evidence
	// Unsupported action profiles keep the field and match flag unavailable;
	// they must not fabricate an empty successful comparison.
	if !evidence.HostnameMatched || c.config.ExpectedAction != "" && !evidence.ActionMatched || c.config.ExpectedCData.Available && evidence.Turnstile.CData != c.config.ExpectedCData {
		return failed(result, OutcomeBindingMismatch, ErrBindingMismatch)
	}
	if !evidence.ChallengeTime.Available || evidence.ChallengeTime.Value.IsZero() || evidence.ChallengeTime.Value.After(result.ObservedAt) || !now.Before(evidence.ChallengeTime.Value.Add(c.config.ChallengeMaxAge)) || result.ObservedAt.IsZero() || result.ObservedAt.Before(start) || result.ObservedAt.After(now) || result.ExpiresAt.IsZero() || !now.Before(result.ExpiresAt) || result.ExpiresAt.After(result.ObservedAt.Add(c.config.Lifetime)) {
		return failed(result, OutcomeRejected, ErrInvalidToken)
	}
	if expiry := evidence.ChallengeTime.Value.Add(c.config.ChallengeMaxAge); expiry.Before(result.ExpiresAt) {
		result.ExpiresAt = expiry
	}
	result.Failure = Failure{Transport: TransportResponded, Retry: RetryNever}
	if err := expired(bounded); err != nil {
		return failed(result, OutcomeCancelled, err)
	}
	return result, nil
}

func expired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, bounded := ctx.Deadline(); bounded && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *Client) sameProfile(e ProviderEvidence) bool {
	p := c.config
	kind := EvidenceTurnstile
	if p.Provider == "recaptcha" {
		kind = EvidenceRecaptcha
	} else if p.Provider == "hcaptcha" {
		kind = EvidenceHCaptcha
	} else if p.Provider == "captchafox" {
		kind = EvidenceCaptchaFox
	}
	return e.Provider == p.Provider && e.API == p.API && e.Version == p.Version && e.Tier == p.Tier && e.APIProfile == p.APIProfile && e.SiteKey == p.SiteKey && e.ConfigurationVersion == p.ConfigurationVersion && e.Kind == kind
}

// Validate shape before any error, cancellation or binding-mismatch return can
// retain provider attribution. Unsupported but structurally closed facts stay
// attributable; profile-specific acceptance is a separate check below.
func validNativeUnion(e ProviderEvidence) bool {
	switch e.Kind {
	case EvidenceTurnstile:
		return e.Turnstile != nil && e.Recaptcha == nil && e.HCaptcha == nil && e.CaptchaFox == nil
	case EvidenceRecaptcha:
		return e.Recaptcha != nil && e.Turnstile == nil && e.HCaptcha == nil && e.CaptchaFox == nil
	case EvidenceHCaptcha:
		return e.HCaptcha != nil && e.Turnstile == nil && e.Recaptcha == nil && e.CaptchaFox == nil
	case EvidenceCaptchaFox:
		return e.CaptchaFox != nil && e.Turnstile == nil && e.Recaptcha == nil && e.HCaptcha == nil
	default:
		return false
	}
}

func (c *Client) validEnvelope(e ProviderEvidence) bool {
	if c.config.Provider == "captchafox" {
		return e.CaptchaFox != nil && validNativeUnion(e) &&
			!e.Origin.Available && e.Origin.Value == "" &&
			!e.Action.Available && e.Action.Value == "" &&
			!e.ScoreAvailable && e.Score == 0 && optionalString(e.Hostname, 253) &&
			(e.ChallengeTime.Available || e.ChallengeTime.Value.IsZero()) &&
			(e.CaptchaFox.ErrorCodesAvailable || len(e.CaptchaFox.ErrorCodes) == 0) &&
			(!e.Success || !e.CaptchaFox.ErrorCodesAvailable) &&
			(e.Success || !e.ChallengeTime.Available)
	}
	if c.config.Provider == "hcaptcha" {
		return e.HCaptcha != nil && validNativeUnion(e) &&
			!e.Origin.Available && e.Origin.Value == "" &&
			!e.Action.Available && e.Action.Value == "" &&
			!e.ScoreAvailable && e.Score == 0 && optionalString(e.Hostname, 253) &&
			(e.ChallengeTime.Available || e.ChallengeTime.Value.IsZero()) &&
			!e.HCaptcha.ReturnedSiteKey.Available && e.HCaptcha.ReturnedSiteKey.Value == "" &&
			(e.HCaptcha.CreditAvailable || !e.HCaptcha.Credit) &&
			(e.HCaptcha.ErrorCodesAvailable || len(e.HCaptcha.ErrorCodes) == 0) &&
			!e.HCaptcha.ScoreReasonsAvailable && len(e.HCaptcha.ScoreReasons) == 0
	}
	if c.config.Provider == "recaptcha" {
		return e.Recaptcha != nil && validNativeUnion(e) && !e.Origin.Available && e.Origin.Value == "" && optionalString(e.Hostname, 253) && optionalString(e.Action, 64) && (!e.Action.Available || e.Action.Value == "" || recaptchaAction(e.Action.Value)) && (e.ChallengeTime.Available || e.ChallengeTime.Value.IsZero()) && (!e.Success || e.ScoreAvailable) && !math.IsNaN(e.Score) && !math.IsInf(e.Score, 0) && e.Score >= 0 && e.Score <= 1 && (e.ScoreAvailable || e.Score == 0) && (e.Recaptcha.ErrorCodesAvailable || len(e.Recaptcha.ErrorCodes) == 0)
	}
	if e.Turnstile == nil || e.Recaptcha != nil || e.HCaptcha != nil || e.CaptchaFox != nil || e.Origin.Available || e.Origin.Value != "" || e.ScoreAvailable || e.Score != 0 || !optionalString(e.Hostname, 253) || !optionalString(e.Action, 32) || !optionalString(e.Turnstile.CData, 255) || !optionalString(e.Turnstile.EphemeralID, 256) || e.Turnstile.EphemeralID.Available || !e.ChallengeTime.Available && !e.ChallengeTime.Value.IsZero() || len(e.ReasonCodes) > 16 || len(e.Turnstile.ErrorCodes) > 16 {
		return false
	}
	for _, reasons := range [][]string{e.ReasonCodes, e.Turnstile.ErrorCodes} {
		for _, reason := range reasons {
			if !ascii(reason, 64, false) {
				return false
			}
		}
	}
	return true
}

func cloneResult(r ProviderResult) ProviderResult {
	r.Evidence.ReasonCodes = slices.Clone(r.Evidence.ReasonCodes)
	if r.Evidence.Turnstile != nil {
		copy := *r.Evidence.Turnstile
		copy.ErrorCodes = slices.Clone(copy.ErrorCodes)
		r.Evidence.Turnstile = &copy
	}
	if r.Evidence.Recaptcha != nil {
		copy := *r.Evidence.Recaptcha
		copy.ErrorCodes = slices.Clone(copy.ErrorCodes)
		r.Evidence.Recaptcha = &copy
	}
	if r.Evidence.HCaptcha != nil {
		copy := *r.Evidence.HCaptcha
		copy.ErrorCodes = slices.Clone(copy.ErrorCodes)
		copy.ScoreReasons = slices.Clone(copy.ScoreReasons)
		r.Evidence.HCaptcha = &copy
	}
	if r.Evidence.CaptchaFox != nil {
		copy := *r.Evidence.CaptchaFox
		copy.ErrorCodes = slices.Clone(copy.ErrorCodes)
		r.Evidence.CaptchaFox = &copy
	}
	return r
}

func boundedResult(r ProviderResult) bool {
	e := r.Evidence
	for _, field := range []struct {
		value   string
		maximum int
	}{{r.CommandID, 22}, {e.Provider, 32}, {e.API, 64}, {e.Version, 32}, {e.Tier, 32}, {e.APIProfile, 128}, {e.SiteKey, 512}, {e.ConfigurationVersion, 64}, {e.Hostname.Value, 253}, {e.Origin.Value, 512}, {e.Action.Value, 64}} {
		if !ascii(field.value, field.maximum, true) {
			return false
		}
	}
	codes := [][]string{e.ReasonCodes}
	if e.Turnstile != nil {
		if !optionalString(e.Turnstile.CData, 255) || !optionalString(e.Turnstile.EphemeralID, 256) {
			return false
		}
		codes = append(codes, e.Turnstile.ErrorCodes)
	}
	if e.Recaptcha != nil {
		codes = append(codes, e.Recaptcha.ErrorCodes)
	}
	if e.HCaptcha != nil {
		if !optionalString(e.HCaptcha.ReturnedSiteKey, 512) {
			return false
		}
		codes = append(codes, e.HCaptcha.ErrorCodes)
		codes = append(codes, e.HCaptcha.ScoreReasons)
	}
	if e.CaptchaFox != nil {
		codes = append(codes, e.CaptchaFox.ErrorCodes)
	}
	for _, set := range codes {
		if len(set) > 16 {
			return false
		}
		for _, code := range set {
			if !ascii(code, 64, false) {
				return false
			}
		}
	}
	return true
}

func safeCause(outcome Outcome) error {
	switch outcome {
	case OutcomeRejected:
		return ErrInvalidToken
	case OutcomeMalformed:
		return ErrMalformedResponse
	case OutcomeThrottled:
		return ErrThrottled
	case OutcomeCancelled:
		return context.Canceled
	case OutcomeAmbiguous:
		return ErrAmbiguousTransport
	case OutcomeUnsupported:
		return ErrUnsupported
	case OutcomeBindingMismatch:
		return ErrBindingMismatch
	default:
		return ErrProviderUnavailable
	}
}

// Observe is directly assignable to risk.CaptchaEvidenceIssuerConfig.Verify.
// It projects existing core fields only; native cdata/metadata stay private to
// the verifier result. It creates no replay identity or reusable evidence bearer.
func (c *Client) Observe(ctx context.Context, request risk.CaptchaVerificationRequest) (risk.CaptchaObservation, error) {
	r, err := c.Verify(ctx, request)
	e := r.Evidence
	fact := risk.CaptchaObservation{Flow: request.Flow, CommandID: request.CommandID, Provider: e.Provider, Site: e.SiteKey, APIProfile: e.APIProfile, ConfigurationVersion: e.ConfigurationVersion, API: e.API, Version: e.Version, Tier: e.Tier, Outcome: r.Outcome, Hostname: e.Hostname, Origin: e.Origin, Action: e.Action, ScoreAvailable: e.ScoreAvailable, Score: e.Score, ObservedAt: r.ObservedAt, ExpiresAt: r.ExpiresAt, ReasonCodes: slices.Clone(e.ReasonCodes)}
	if e.ChallengeTime.Available {
		fact.ChallengeTime = e.ChallengeTime.Value
	}
	return fact, err
}
