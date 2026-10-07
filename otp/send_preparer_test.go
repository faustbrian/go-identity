package otp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/delivery"
)

func sendPreparerFixture(t *testing.T) (Continuation, Verifier, SendPreparationConfig) {
	t.Helper()
	c, policy, verifier, renderer, template := sendPreparationFixture(t)
	return c, verifier, SendPreparationConfig{Policy: policy, Verifier: verifier, Renderer: renderer, TemplateID: template.id, TemplateVersion: template.version, LocaleChain: template.locales}
}

func TestSendPreparerOwnsConfigurationAndSameCode(t *testing.T) {
	c, verifier, config := sendPreparerFixture(t)
	preparer, err := NewSendPreparer(config)
	if err != nil {
		t.Fatal(err)
	}
	config.LocaleChain[0] = "unknown"
	config.TemplateID = "unknown"
	*config.Renderer = delivery.TemplateRenderer{}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for range 8 {
		t.Run("independent invocation", func(t *testing.T) {
			t.Parallel()
			var sealedDigest StoredCodeDigest
			challenge, err := preparer.Prepare(context.Background(), c, now, now.Add(time.Minute), func(_ context.Context, draft Challenge, recipient delivery.Recipient, message delivery.RenderedMessage) error {
				s, _ := draft.Bindings()
				sealedDigest = s.Digest
				code, err := auth.NewOneTimeCode(strings.TrimPrefix(message.Body, "Your code is "))
				if err != nil {
					return err
				}
				scope, _ := c.DigestScope()
				matches, err := verifier.Compare(scope, s.Digest, code)
				if err != nil || !matches || recipient.Address != "recipient@example.invalid" || message.Locale != "en" {
					t.Fatal("preparer mixed code, recipient or retained locale")
				}
				return nil
			})
			s, bindingErr := challenge.Bindings()
			if err != nil || bindingErr != nil || s.Digest != sealedDigest || !s.ExpiresAt.Equal(now.Add(time.Minute)) || s.Continuation != c {
				t.Fatal("usable challenge did not match protected custody", err, bindingErr)
			}
		})
	}
}

func TestSendPreparerRejectsInvalidConfiguration(t *testing.T) {
	_, _, valid := sendPreparerFixture(t)
	for name, change := range map[string]func(*SendPreparationConfig){
		"policy":           func(c *SendPreparationConfig) { c.Policy = AttemptPolicy{} },
		"verifier":         func(c *SendPreparationConfig) { c.Verifier = Verifier{} },
		"renderer":         func(c *SendPreparationConfig) { c.Renderer = nil },
		"template":         func(c *SendPreparationConfig) { c.TemplateID = "" },
		"template bound":   func(c *SendPreparationConfig) { c.TemplateID = strings.Repeat("x", 129) },
		"template control": func(c *SendPreparationConfig) { c.TemplateID = "otp\n" },
		"version":          func(c *SendPreparationConfig) { c.TemplateVersion = 0 },
		"locales":          func(c *SendPreparationConfig) { c.LocaleChain = nil },
		"locale bound":     func(c *SendPreparationConfig) { c.LocaleChain = []string{strings.Repeat("x", 36)} },
		"duplicate locale": func(c *SendPreparationConfig) { c.LocaleChain = []string{"en", "en"} },
		"locale count":     func(c *SendPreparationConfig) { c.LocaleChain = make([]string, 9) },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			change(&config)
			p, err := NewSendPreparer(config)
			if p != nil || !errors.Is(err, ErrInvalidGeneration) {
				t.Fatal("invalid configuration admitted", err)
			}
		})
	}
}

func TestSendPreparerSealingFailureCancellationAndPanicHaveNoResult(t *testing.T) {
	c, _, config := sendPreparerFixture(t)
	p, err := NewSendPreparer(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, mode := range []string{"error", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			result, err := p.Prepare(ctx, c, now, now.Add(time.Minute), func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
				if mode == "panic" {
					panic("recognizable-secret")
				}
				if mode == "cancel" {
					stop()
				}
				return errors.New("recognizable-secret")
			})
			want := ErrCodeUse
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || result != (Challenge{}) || strings.Contains(err.Error(), "recognizable-secret") {
				t.Fatal("failed sealing exposed result or diagnostics")
			}
		})
	}
	for _, zero := range []*SendPreparer{nil, {}} {
		result, err := zero.Prepare(context.Background(), c, now, now.Add(time.Minute), nil)
		if !errors.Is(err, ErrInvalidGeneration) || result != (Challenge{}) {
			t.Fatal("zero preparer admitted")
		}
	}
}

func TestSendPreparerRedactsPolicyAndRetainedKeys(t *testing.T) {
	_, _, config := sendPreparerFixture(t)
	p, err := NewSendPreparer(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, p, *p} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(verb, value); !strings.Contains(text, "redacted") || strings.Contains(text, "otp-code") {
				t.Fatal("configuration leaked")
			}
		}
		if wire, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) || len(wire) != 0 {
			t.Fatal("configuration serialized")
		}
	}
}

func TestSendPreparerCatalogAndRequestRejectionPrecedesSealing(t *testing.T) {
	c, _, valid := sendPreparerFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for name, change := range map[string]func(*SendPreparationConfig){
		"unknown-template":      func(c *SendPreparationConfig) { c.TemplateID = "missing" },
		"unknown-version":       func(c *SendPreparationConfig) { c.TemplateVersion++ },
		"unknown-locale":        func(c *SendPreparationConfig) { c.LocaleChain = []string{"fr"} },
		"invalid-locale-schema": func(c *SendPreparationConfig) { c.LocaleChain = []string{"en_US"} },
		"empty-renderer":        func(c *SendPreparationConfig) { c.Renderer = &delivery.TemplateRenderer{} },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			change(&config)
			p, err := NewSendPreparer(config)
			if err != nil {
				t.Fatal("bounded configuration should defer catalog checks", err)
			}
			challenge, err := p.Prepare(context.Background(), c, now, now.Add(time.Minute), func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
				t.Fatal("invalid rendering reached secret sealing")
				return nil
			})
			if !errors.Is(err, ErrInvalidGeneration) || challenge != (Challenge{}) {
				t.Fatal("invalid renderer returned a challenge")
			}
		})
	}
	p, _ := NewSendPreparer(valid)
	for _, request := range []struct {
		ctx          context.Context
		continuation Continuation
		expires      time.Time
	}{
		{nil, c, now.Add(time.Minute)},
		{context.Background(), Continuation{}, now.Add(time.Minute)},
		{context.Background(), c, now.Add(time.Minute + time.Microsecond)},
	} {
		challenge, err := p.Prepare(request.ctx, request.continuation, now, request.expires, func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
			t.Fatal("invalid request reached secret sealing")
			return nil
		})
		if !errors.Is(err, ErrInvalidGeneration) || challenge != (Challenge{}) {
			t.Fatal("invalid request admitted")
		}
	}
}
