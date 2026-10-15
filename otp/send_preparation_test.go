package otp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/session"
)

// Scenario 1: the owning Send preparation generates the secret, not its caller.
// A different digest code or an omitted exact scope makes comparison fail.
func TestSendPreparationOwnsOneCodeForDigestAndRenderedMessage(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	var message delivery.RenderedMessage
	var recipient delivery.Recipient
	p, err := prepareSend(context.Background(), c, policy, v, renderer, template, now, now.Add(time.Minute), func(_ context.Context, _ Challenge, r delivery.Recipient, m delivery.RenderedMessage) error {
		// Capture is confined to test memory at the encryption boundary.
		message, recipient = m, r
		return nil
	})
	if err != nil {
		t.Fatal("owned preparation did not produce a challenge", err)
	}
	s, err := p.challenge.Bindings()
	if err != nil || s.State != ChallengeIssued || s.Version != 1 || s.UsedAttempts != 0 || s.FailedAttempts != 0 || s.Checks != 0 || !s.IssuedAt.Equal(now) || !s.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("wrong initial challenge", err)
	}
	if message.Channel != delivery.ChannelEmail || message.Locale != "en" || message.Subject != "verification" || message.ContentType != "text/plain" || !strings.HasPrefix(message.Body, "Your code is ") {
		t.Fatal("wrong rendered message profile")
	}
	code, err := auth.NewOneTimeCode(strings.TrimPrefix(message.Body, "Your code is "))
	if err != nil {
		t.Fatal("message has no valid one-time code")
	}
	scope, _ := c.DigestScope()
	// Independent framing oracle: do not derive the expected value through
	// Verifier.Digest or the generator's own callback.
	raw := []byte(strings.TrimPrefix(message.Body, "Your code is "))
	defer clear(raw)
	frame := []byte("identity-otp-code-scope-v1\x00")
	b, _ := c.Bindings()
	for _, value := range []string{b.Scope.TenantID, string(b.Scope.Purpose), b.Scope.SubjectID, string(b.Scope.Channel), b.Scope.Destination.Value(), b.Scope.ChallengeID, b.Scope.TargetID} {
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(value)))
		frame = append(frame, value...)
	}
	frame = binary.BigEndian.AppendUint64(frame, b.Scope.PolicyVersion)
	frame = binary.BigEndian.AppendUint64(frame, b.Scope.Generation)
	frame = append(frame, b.Scope.AuthorizationBinding[:]...)
	frame = binary.BigEndian.AppendUint32(frame, s.Digest.KeyVersion)
	wire := []byte("authentication-one-time-code-digest-v1\x00")
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(frame)))
	wire = append(wire, frame...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(raw)))
	wire = append(wire, raw...)
	defer clear(wire)
	defer clear(frame)
	key := [32]byte{0x71}
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write(wire)
	if !hmac.Equal(h.Sum(nil), s.Digest.Value[:]) {
		t.Fatal("rendered code disagrees with independent complete-scope HMAC")
	}
	match, err := v.Compare(scope, s.Digest, code)
	if err != nil || !match {
		t.Fatal("delivered code differs from the stored scoped digest", err)
	}
	b.Scope.TargetID = "different-target"
	b.Scope.AuthorizationBinding = [32]byte{}
	other, err := NewContinuation(b.Scope, b.Authorization, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	otherScope, _ := other.DigestScope()
	if match, err := v.Compare(otherScope, s.Digest, code); err != nil || match {
		t.Fatal("delivered code escaped original target scope", err)
	}
	if recipient.Address != b.Scope.Destination.Value() || recipient.Channel != delivery.ChannelEmail || recipient.Validate() != nil {
		t.Fatal("message recipient escaped original destination")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, p); strings.Contains(got, strings.TrimPrefix(message.Body, "Your code is ")) || strings.Contains(got, recipient.Address) {
			t.Fatal("prepared Send leaked secret content")
		}
	}
	if wire, err := json.Marshal(p); !errors.Is(err, ErrSensitiveSerialization) || len(wire) != 0 {
		t.Fatal("implicit serialization accepted prepared plaintext")
	}
}

func sendPreparationFixture(t *testing.T) (Continuation, AttemptPolicy, Verifier, *delivery.TemplateRenderer, sendTemplate) {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := NewFlowAuthorization(FlowAuthorizationSpec{Kind: FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: "AQEBAQEBAQEBAQEBAQEBAQ"})
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := NewDestinationInput("recipient@example.invalid")
	c, err := NewContinuation(DigestScopeSpec{TenantID: "tenant", SubjectID: "user", Purpose: PurposeSignin, Channel: ChannelEmail, Destination: destination, ChallengeID: "challenge", TargetID: "target", PolicyVersion: 1, Generation: 1}, flow, remember)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := NewCodeProfile(CodeProfileSpec{Purpose: PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: ReplacePrevious})
	policy, _ := NewAttemptPolicy(profile, CheckPolicySpec{LockoutAfter: time.Minute})
	v, _ := NewVerifier(1, map[uint32][32]byte{1: {0x71}})
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "otp", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 1024, Subject: "verification", Body: "Your code is {{.code}}", ContentType: "text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, policy, v, renderer, sendTemplate{id: "otp", version: 1, locales: []string{"en"}}
}

// Scenario 10: cancellation does not produce a usable partial preparation.
func TestSendPreparationCancellationHasNoChallengeOrMessage(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p, err := prepareSend(ctx, c, policy, v, renderer, template, now, now.Add(time.Minute), func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
		t.Fatal("cancelled preparation reached encryption")
		return nil
	})
	if !errors.Is(err, context.Canceled) || p.challenge != (Challenge{}) {
		t.Fatal("cancelled Send produced partial issuance")
	}
}

// Scenario 10: secret-bearing encryption errors never cross the boundary.
func TestSendPreparationRequiresProtectedCustodyBeforeReturning(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	p, err := prepareSend(context.Background(), c, policy, v, renderer, template, now, now.Add(time.Minute), func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
		return errors.New("recognizable-private-sentinel")
	})
	if !errors.Is(err, ErrCodeUse) || p.challenge != (Challenge{}) || strings.Contains(err.Error(), "recognizable-private-sentinel") {
		t.Fatal("failed encryption returned issuance or secret-bearing error")
	}
}

// Scenarios 2/10: policy and purpose remain frozen, including expiry precision.
func TestSendPreparationRejectsInvalidInputsWithoutSealing(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	type input struct {
		ctx             context.Context
		c               Continuation
		policy          AttemptPolicy
		v               Verifier
		renderer        *delivery.TemplateRenderer
		template        sendTemplate
		issued, expires time.Time
	}
	valid := input{context.Background(), c, policy, v, renderer, template, now, now.Add(time.Minute)}
	for name, change := range map[string]func(*input){
		"nil-context":            func(i *input) { i.ctx = nil },
		"zero-continuation":      func(i *input) { i.c = Continuation{} },
		"zero-policy":            func(i *input) { i.policy = AttemptPolicy{} },
		"zero-verifier":          func(i *input) { i.v = Verifier{} },
		"nil-renderer":           func(i *input) { i.renderer = nil },
		"zero-template":          func(i *input) { i.template = sendTemplate{} },
		"unknown-template":       func(i *input) { i.template.id = "unknown" },
		"unknown-version":        func(i *input) { i.template.version = 2 },
		"unknown-locale":         func(i *input) { i.template.locales = []string{"fr"} },
		"zero-issued":            func(i *input) { i.issued = time.Time{} },
		"zero-expiry":            func(i *input) { i.expires = time.Time{} },
		"equal-expiry":           func(i *input) { i.expires = i.issued },
		"early-expiry":           func(i *input) { i.expires = i.issued.Add(-time.Microsecond) },
		"past-ttl":               func(i *input) { i.expires = i.expires.Add(time.Microsecond) },
		"sub-microsecond-issued": func(i *input) { i.issued = i.issued.Add(time.Nanosecond) },
		"sub-microsecond-expiry": func(i *input) { i.expires = i.expires.Add(-time.Nanosecond) },
		"cross-purpose": func(i *input) {
			p, _ := NewCodeProfile(CodeProfileSpec{Purpose: PurposePasswordReset, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: ReplacePrevious})
			i.policy, _ = NewAttemptPolicy(p, CheckPolicySpec{LockoutAfter: time.Minute})
		},
	} {
		t.Run(name, func(t *testing.T) {
			i := valid
			change(&i)
			p, err := prepareSend(i.ctx, i.c, i.policy, i.v, i.renderer, i.template, i.issued, i.expires, func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
				t.Fatal("invalid preparation reached encryption")
				return nil
			})
			if !errors.Is(err, ErrInvalidGeneration) || p.challenge != (Challenge{}) {
				t.Fatal("invalid preparation returned usable issuance")
			}
		})
	}
	if p, err := prepareSend(valid.ctx, c, policy, v, renderer, template, now, valid.expires, nil); !errors.Is(err, ErrInvalidGeneration) || p.challenge != (Challenge{}) {
		t.Fatal("missing sealing boundary admitted")
	}
}

func TestSendPreparationCancellationAfterSealingDiscardsResult(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := prepareSend(ctx, c, policy, v, renderer, template, now, now.Add(time.Minute), func(context.Context, Challenge, delivery.Recipient, delivery.RenderedMessage) error {
		cancel()
		return errors.New("private-sentinel")
	})
	if !errors.Is(err, context.Canceled) || p.challenge != (Challenge{}) {
		t.Fatal("late cancellation returned challenge or secret error")
	}
}

func TestSendPreparationPurposeChannelAndRememberBindings(t *testing.T) {
	c, _, v, _, _ := sendPreparationFixture(t)
	base, _ := c.Bindings()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, purpose := range []Purpose{PurposeSignin, PurposeEmailVerification, PurposePasswordReset, PurposeEmailChange, PurposeMFA, PurposeStepUp} {
		for _, channel := range []Channel{ChannelEmail, ChannelSMS} {
			t.Run(string(purpose)+"/"+string(channel), func(t *testing.T) {
				scope := base.Scope
				scope.Purpose, scope.Channel, scope.AuthorizationBinding = purpose, channel, [32]byte{}
				remember := session.RememberPolicy{}
				if purpose == PurposeSignin || purpose == PurposeMFA {
					remember = base.RememberPolicy
				}
				deliveryChannel := delivery.ChannelEmail
				if channel == ChannelSMS {
					deliveryChannel = delivery.ChannelSMS
					scope.Destination, _ = NewDestinationInput("+12025550123")
				}
				continuation, err := NewContinuation(scope, base.Authorization, remember)
				if err != nil {
					t.Fatal(err)
				}
				profile, _ := NewCodeProfile(CodeProfileSpec{Purpose: purpose, Alphabet: "0123456789abcdef", Length: 5, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: RetainPrevious})
				policy, _ := NewAttemptPolicy(profile, CheckPolicySpec{LockoutAfter: time.Minute})
				renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "otp", Version: 1, Channel: deliveryChannel, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Body: "{{.code}}", ContentType: "text/plain"}})
				if err != nil {
					t.Fatal(err)
				}
				p, err := prepareSend(context.Background(), continuation, policy, v, renderer, sendTemplate{id: "otp", version: 1, locales: []string{"en"}}, now, now.Add(30*time.Second), func(_ context.Context, challenge Challenge, recipient delivery.Recipient, message delivery.RenderedMessage) error {
					stored, _ := challenge.Bindings()
					code, err := auth.NewOneTimeCode(message.Body)
					if err != nil {
						return err
					}
					binding, _ := continuation.DigestScope()
					match, err := v.Compare(binding, stored.Digest, code)
					if err != nil || !match || len(message.Body) != 5 || recipient.Address != scope.Destination.Value() || recipient.Channel != deliveryChannel {
						t.Fatal("purpose/channel rendering or digest changed")
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				stored, _ := p.challenge.Bindings()
				original, _ := stored.Continuation.Bindings()
				if original.RememberPolicy != remember || original.Scope.Purpose != purpose || original.Scope.Channel != channel || stored.Policy != policy || !stored.ExpiresAt.Equal(now.Add(30*time.Second)) {
					t.Fatal("preparation renewed original policy or changed purpose/channel")
				}
			})
		}
	}
}

func TestSendPreparationConcurrentCallsUseIndependentSecrets(t *testing.T) {
	c, policy, v, renderer, template := sendPreparationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	for range 8 {
		t.Run("independent", func(t *testing.T) {
			t.Parallel()
			p, err := prepareSend(context.Background(), c, policy, v, renderer, template, now, now.Add(time.Minute), func(_ context.Context, challenge Challenge, _ delivery.Recipient, m delivery.RenderedMessage) error {
				s, _ := challenge.Bindings()
				code, err := auth.NewOneTimeCode(strings.TrimPrefix(m.Body, "Your code is "))
				if err != nil {
					return err
				}
				scope, _ := c.DigestScope()
				match, err := v.Compare(scope, s.Digest, code)
				if err != nil || !match {
					t.Fatal("concurrent code crossed another invocation")
				}
				return nil
			})
			if err != nil || p.challenge == (Challenge{}) {
				t.Fatal("concurrent preparation failed", err)
			}
		})
	}
}
