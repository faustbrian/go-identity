package otp

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/delivery"
)

// These are owned Send preparation internals, not caller-supplied generated
// challenges. The explicit SendPreparer adapter seam calls this same owner.
// Current primary flow/recipient
// admission and replay selection must precede this preparation; durable
// authority must still be checked again in the original transaction.
type sendTemplate struct {
	id      string
	version uint32
	locales []string
}

// No plaintext leaves preparation: only the synchronous owned sealing boundary
// receives the message. Its encrypted custody is retained by the adapter, not
// here. Neither this digest nor successful sealing is committed issuance.
type preparedSend struct {
	challenge Challenge
}

func prepareSend(ctx context.Context, continuation Continuation, policy AttemptPolicy, verifier Verifier, renderer *delivery.TemplateRenderer, template sendTemplate, issuedAt, expiresAt time.Time, seal func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error) (preparedSend, error) {
	if ctx == nil || seal == nil {
		return preparedSend{}, ErrInvalidGeneration
	}
	if err := ctx.Err(); err != nil {
		return preparedSend{}, err
	}
	profile, _, err := policy.Bindings()
	bindings, bindingErr := continuation.Bindings()
	if err != nil || bindingErr != nil || profile.Purpose != bindings.Scope.Purpose || renderer == nil || verifier.current == 0 ||
		!challengeTime(issuedAt) || !challengeTime(expiresAt) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > profile.TTL ||
		template.id == "" || template.version == 0 {
		return preparedSend{}, ErrInvalidGeneration
	}
	scope, err := continuation.DigestScope()
	if err != nil {
		return preparedSend{}, ErrInvalidGeneration
	}
	channel := delivery.ChannelEmail
	if bindings.Scope.Channel == ChannelSMS {
		channel = delivery.ChannelSMS
	}
	// The digest version is shared with the challenge, never selected from input.
	// It binds delivery to the complete original scope, including authorization.
	scopeDigest, err := verifier.ScopeDigest(scope, verifier.current)
	if err != nil {
		return preparedSend{}, ErrInvalidGeneration
	}
	recipient := delivery.Recipient{Channel: channel, Address: bindings.Scope.Destination.Value(), ScopeDigest: hex.EncodeToString(scopeDigest.Value[:])}
	message := delivery.Message{Purpose: "otp-" + string(profile.Purpose), Channel: channel, Recipient: recipient, TemplateID: template.id, TemplateVersion: uint64(template.version), LocaleChain: template.locales,
		Variables: []delivery.TemplateVariable{{Name: "code", Kind: "code", Sensitive: true}}}
	// Validate the declared template/locale/channel/schema with non-secret input
	// before generating a code. The owned renderer has no IO or callbacks.
	message.Variables[0].CodeValue = strings.Repeat(profile.Alphabet[:1], profile.Length)
	if _, err := renderer.Render(ctx, message); err != nil {
		if ctx.Err() != nil {
			return preparedSend{}, ctx.Err()
		}
		return preparedSend{}, ErrInvalidGeneration
	}
	message.Variables[0].CodeValue = ""
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var prepared preparedSend
	err = policy.profile.Generate(ctx, func(ctx context.Context, raw []byte) error {
		code, err := auth.NewOneTimeCode(string(raw))
		if err != nil {
			return ErrInvalidGeneration
		}
		digest, err := verifier.Digest(scope, code)
		if err != nil {
			return err
		}
		challenge, err := NewChallenge(ChallengeSpec{Continuation: continuation, Policy: policy, Digest: digest.Storage(), IssuedAt: issuedAt, ExpiresAt: expiresAt, State: ChallengeIssued, Version: 1})
		if err != nil {
			return err
		}
		message.Variables[0].CodeValue = string(raw)
		defer func() { message.Variables[0].CodeValue = "" }()
		rendered, err := renderer.Render(ctx, message)
		if err != nil {
			return err
		}
		// Seal before releasing the borrowed code. Only ciphertext and the scoped
		// digest may survive this callback; there is no plaintext-return API.
		if err := seal(ctx, challenge, recipient, rendered); err != nil {
			return err
		}
		prepared = preparedSend{challenge: challenge}
		return nil
	})
	if err != nil {
		return preparedSend{}, err
	}
	return prepared, nil
}

func (preparedSend) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.preparedSend(redacted)")
}
func (preparedSend) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (preparedSend) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (preparedSend) LogValue() slog.Value         { return slog.StringValue("otp.preparedSend(redacted)") }
