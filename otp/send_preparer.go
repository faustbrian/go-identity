package otp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

// SendPreparationConfig fixes trusted policy, retained digest keys and the
// owned versioned renderer for native issuance composition. LocaleChain is an
// explicit ordered fallback, copied at construction; no locale is inferred.
// Do not mutate inputs during construction. This is not caller-selected risk
// clearance, recipient ownership, or a public Send workflow configuration.
type SendPreparationConfig struct {
	Policy          AttemptPolicy
	Verifier        Verifier
	Renderer        *delivery.TemplateRenderer
	TemplateID      string
	TemplateVersion uint32
	LocaleChain     []string
}

// SendPreparer is immutable policy for the owned same-code digest/render/seal
// boundary. It retains no per-request challenge, plaintext, delivery or callback
// and supports concurrent calls. Zero is invalid. It does not own transactions,
// replay, recipient discovery, risk admission, code delivery or session issuance.
type SendPreparer struct {
	policy   AttemptPolicy
	verifier Verifier
	renderer *delivery.TemplateRenderer
	template sendTemplate
}

// NewSendPreparer validates bounds and copies trusted configuration without
// IO, entropy, hashing or callbacks. Template identifiers are 1..128 visible
// ASCII bytes; locale entries are distinct 1..35-byte bounded text, with 1..8
// entries. Delivery's complete locale/schema/catalog validation runs against
// the real request before any entropy in Prepare, not against a guessed address.
// Invalid configuration returns nil and redacted ErrInvalidGeneration.
func NewSendPreparer(c SendPreparationConfig) (*SendPreparer, error) {
	_, _, err := c.Policy.Bindings()
	if err != nil || c.Verifier.current == 0 || c.Verifier.keys[c.Verifier.current] == ([32]byte{}) || c.Renderer == nil ||
		len(c.TemplateID) == 0 || len(c.TemplateID) > 128 || c.TemplateVersion == 0 || len(c.LocaleChain) == 0 || len(c.LocaleChain) > 8 {
		return nil, ErrInvalidGeneration
	}
	for i := range len(c.TemplateID) {
		if c.TemplateID[i] < 0x21 || c.TemplateID[i] > 0x7e {
			return nil, ErrInvalidGeneration
		}
	}
	locales := make([]string, len(c.LocaleChain))
	for i, locale := range c.LocaleChain {
		if !boundedText(locale, 35, false) {
			return nil, ErrInvalidGeneration
		}
		for _, previous := range locales[:i] {
			if previous == locale {
				return nil, ErrInvalidGeneration
			}
		}
		locales[i] = strings.Clone(locale)
	}
	// The catalog is immutable, but the caller still owns its renderer pointer
	// slot. Snapshot the value so replacing that slot cannot rewrite our policy.
	renderer := *c.Renderer
	return &SendPreparer{policy: c.Policy, verifier: c.Verifier, renderer: &renderer,
		template: sendTemplate{id: strings.Clone(c.TemplateID), version: c.TemplateVersion, locales: locales}}, nil
}

// Prepare generates one code, computes its complete-scope keyed digest and
// renders that same code under frozen policy. The native adapter must first
// authenticate/currently admit the original request and acknowledge its durable
// generation marker; this method cannot perform or prove those steps. Recipient
// input must already be resolved and authorized by the owning workflow.
//
// seal borrows the draft, recipient and secret rendered message synchronously.
// It must encrypt into owned bounded custody, honor ctx, and not retain/log
// plaintext or start asynchronous work. No plaintext is returned. Caller or
// five-second deadline wins; cancellation, seal failure or panic returns zero
// Challenge. Diagnostics/panics are redacted to ErrCodeUse (cancellation wins).
// Go cannot erase strings/copies retained by a violating callback. A returned
// digest is not committed issuance: the native adapter must conserve sealed
// output in its original journal and recheck authority/expiry at atomic commit.
// Do not call this on retry before the coordinator selects retained output.
func (p *SendPreparer) Prepare(ctx context.Context, continuation Continuation, issuedAt, expiresAt time.Time, seal func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error) (challenge Challenge, err error) {
	if ctx == nil || p == nil || p.renderer == nil || seal == nil {
		return Challenge{}, ErrInvalidGeneration
	}
	ctx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	defer func() {
		if recover() != nil {
			challenge, err = Challenge{}, ErrCodeUse
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
	}()
	prepared, err := prepareSend(ctx, continuation, p.policy, p.verifier, p.renderer, p.template, issuedAt, expiresAt, seal)
	if err != nil {
		return Challenge{}, err
	}
	return prepared.challenge, nil
}

// Format hides retained configuration and keys on pointer and value copies.
func (SendPreparer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.SendPreparer(redacted)")
}

// MarshalJSON denies implicit retained configuration export.
func (SendPreparer) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit retained configuration export.
func (SendPreparer) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue hides retained configuration and keys.
func (SendPreparer) LogValue() slog.Value { return slog.StringValue("otp.SendPreparer(redacted)") }

// Format hides configuration and retained keys.
func (SendPreparationConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.SendPreparationConfig(redacted)")
}

// MarshalJSON denies implicit key export.
func (SendPreparationConfig) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit key export.
func (SendPreparationConfig) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// LogValue hides configuration and retained keys.
func (SendPreparationConfig) LogValue() slog.Value {
	return slog.StringValue("otp.SendPreparationConfig(redacted)")
}
