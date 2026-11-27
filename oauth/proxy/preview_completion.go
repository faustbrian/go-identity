package oauthproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// CompletionError is a stable, redacted preview admission failure. It retains
// no browser credential, envelope, provider observation or collaborator error.
type CompletionError string

func (e CompletionError) Error() string { return "oauth proxy: " + string(e) }

const (
	// CompletionInvalid identifies malformed configuration or bounded request.
	CompletionInvalid CompletionError = "invalid_completion"
	// CompletionDenied identifies a mismatched, unauthenticated or expired
	// original browser flow or encrypted provider observation.
	CompletionDenied CompletionError = "completion_denied"
	// CompletionUnavailable identifies cancellation, deadline expiry, unavailable
	// decryption or a panic at a borrowed clock/codec boundary.
	CompletionUnavailable CompletionError = "completion_unavailable"
)

const (
	// Match the codec's bounded authenticated wire, without parsing it before
	// the original browser cookie is verified. Key retention matches its active
	// plus at most 32 retained-key selection; this bounds local admission work.
	maximumCompletionEnvelope = 8192
	maximumCompletionKeys     = 33
	maximumCompletionDuration = 20 * time.Second
	completionAction          = "identity.oauth.callback"
)

// PreviewCompletionConfig selects one trusted preview registration and native
// browser policy. IDs and target endpoints are exact, never normalized. FlowKeys
// contains 1..33 distinct versions of dedicated pre-authentication digest keys;
// retain an old key while its original flows remain eligible. MaximumDuration
// is positive and at most 20 seconds, not a renewed envelope or flow lifetime.
// Codec and Clock are borrowed, must support concurrent calls and outlive the
// admission. The clock must be trusted and nonblocking. No I/O runs at creation.
type PreviewCompletionConfig struct {
	TenantID             identity.TenantID
	ProductionDeployment string
	Target               PreviewTarget
	PolicyID             string
	PolicyVersion        uint64
	FlowKeys             []session.DigestKey
	Codec                *oauth.ProxyOIDCEvidenceCodec
	Clock                oauth.Clock
	MaximumDuration      time.Duration
}

// PreviewCompletionRequest borrows one request's browser cookie and 1..8192-byte
// encrypted handoff only until Open returns. Origin must be established by the
// trusted transport, not copied from envelope contents or unchecked client
// metadata. Callers must not mutate input concurrently or log this value.
type PreviewCompletionRequest struct {
	Origin     string
	FlowCookie authentication.BearerCredential
	Envelope   []byte
}

// PreviewEvidence is an opaque, immutable provider observation plus the exact
// authenticated wire digest and earliest original deadline. It is not an active
// flow, reservation, one-use consumption grant, account or session authority.
// A native completion owner must independently reserve and consume its artifact,
// fence current policy and apply/finalize linking or issuance transactionally.
// Zero contains no evidence. Copies are safe for concurrent reads.
type PreviewEvidence struct {
	identity oauth.ProviderIdentity
	expires  time.Time
	digest   [32]byte
}

// Identity returns only the codec's verified provider observation. Its signed
// times are unchanged; ID-token issuance is not authentication freshness.
func (e PreviewEvidence) Identity() (oauth.ProviderIdentity, bool) {
	if e.identity.Subject() == "" || e.expires.IsZero() || e.digest == ([32]byte{}) {
		return oauth.ProviderIdentity{}, false
	}
	return e.identity, true
}

// ExpiresAt is the earliest signed-proof, original-envelope and browser-flow
// deadline. It never renews the source observation's lifetime.
func (e PreviewEvidence) ExpiresAt() time.Time { return e.expires }

// EnvelopeDigest is SHA-256 of the exact authenticated wire, not a credential,
// alternate envelope or proof that any durable artifact was consumed.
func (e PreviewEvidence) EnvelopeDigest() [32]byte { return e.digest }

// PreviewCompletionAdmission authenticates encrypted evidence against original
// native browser custody. It owns no provider I/O, HTTP transport, durable state,
// replay control, account lookup, session issuance, goroutine or authorization.
// Its zero value is invalid. Constructed values support concurrent requests if
// their borrowed codec and clock do. Successful Open can authenticate identical
// wire again; only the native durable owner may grant one-use completion.
type PreviewCompletionAdmission struct {
	configuration PreviewCompletionConfig
}

// NewPreviewCompletionAdmission validates trusted configuration and copies its
// key selection. It performs no clock read, key-provider I/O or state mutation.
func NewPreviewCompletionAdmission(c PreviewCompletionConfig) (*PreviewCompletionAdmission, error) {
	if _, err := identity.ParseIdentifierID(string(c.TenantID)); err != nil {
		return nil, CompletionInvalid
	}
	if !identifier(c.ProductionDeployment) || !c.Target.valid() || c.ProductionDeployment == c.Target.Deployment ||
		!completionPolicyID(c.PolicyID) || c.PolicyVersion == 0 || c.Codec == nil || nilCompletionClock(c.Clock) ||
		c.MaximumDuration <= 0 || c.MaximumDuration > maximumCompletionDuration ||
		len(c.FlowKeys) == 0 || len(c.FlowKeys) > maximumCompletionKeys {
		return nil, CompletionInvalid
	}
	// DigestKey intentionally exposes no key material or version accessor. A
	// fixed noncredential probe checks initialization and duplicate versions;
	// it is never accepted as browser proof and uses no pre-auth flow framing.
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	versions := make(map[uint32]struct{}, len(c.FlowKeys))
	for _, key := range c.FlowKeys {
		digest, err := probe.Digest(key, string(c.TenantID))
		if err != nil {
			return nil, CompletionInvalid
		}
		if _, duplicate := versions[digest.KeyVersion]; duplicate {
			return nil, CompletionInvalid
		}
		versions[digest.KeyVersion] = struct{}{}
	}
	c.FlowKeys = slices.Clone(c.FlowKeys)
	return &PreviewCompletionAdmission{configuration: c}, nil
}

// Open verifies independently loaded original envelope and browser-flow state
// before decrypting the bounded wire. No input is derived from the envelope to
// select trusted registration or cookie bindings. The configured/caller deadline
// bounds synchronous codec work; collaborators must honor cancellation. Errors
// return zero evidence, including late success, clock rollback and panic.
func (p *PreviewCompletionAdmission) Open(ctx context.Context, original oauth.ProxyOIDCEvidenceBinding, flow session.PreAuthTransaction, request PreviewCompletionRequest) (out PreviewEvidence, err error) {
	defer func() {
		if recover() != nil {
			out, err = PreviewEvidence{}, CompletionUnavailable
		}
	}()
	if p == nil || p.configuration.Codec == nil || p.configuration.Clock == nil || ctx == nil ||
		len(request.Envelope) == 0 || len(request.Envelope) > maximumCompletionEnvelope {
		return PreviewEvidence{}, CompletionInvalid
	}
	token, err := session.ParseToken(request.FlowCookie.Token())
	if err != nil {
		return PreviewEvidence{}, CompletionInvalid
	}
	if ctx.Err() != nil {
		return PreviewEvidence{}, CompletionUnavailable
	}
	c := p.configuration
	if !p.matchesOriginal(original, request.Origin) {
		return PreviewEvidence{}, CompletionDenied
	}
	stored, err := flow.Bindings()
	if err != nil || !p.matchesFlow(original, stored.Binding) {
		return PreviewEvidence{}, CompletionDenied
	}
	observed := c.Clock.Now()
	if observed.Before(original.IssuedAt) || !observed.Before(original.ExpiresAt) {
		return PreviewEvidence{}, CompletionDenied
	}
	cookie, verified := completionCookie(token, c.FlowKeys, stored)
	if !verified || flow.Check(observed, stored.Binding, cookie) != nil {
		return PreviewEvidence{}, CompletionDenied
	}

	budget := min(c.MaximumDuration, original.ExpiresAt.Sub(observed), stored.Binding.ExpiresAt.Sub(observed))
	work, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if initiationContextEnded(work) {
		return PreviewEvidence{}, CompletionUnavailable
	}
	// The returned digest must identify the same bytes that authenticated, not
	// a caller's subsequently reused buffer. This copy is bounded before allocation.
	wire := bytes.Clone(request.Envelope)
	defer clear(wire)
	principal, err := c.Codec.Open(work, original, wire)
	if initiationContextEnded(work) {
		return PreviewEvidence{}, CompletionUnavailable
	}
	if err != nil {
		var oauthError *oauth.Error
		if errors.As(err, &oauthError) && oauthError.Kind() == oauth.Unavailable {
			return PreviewEvidence{}, CompletionUnavailable
		}
		return PreviewEvidence{}, CompletionDenied
	}
	expires := original.ExpiresAt
	for _, deadline := range []time.Time{stored.Binding.ExpiresAt, principal.EvidenceExpiresAt(), principal.IDTokenExpiresAt()} {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	at := c.Clock.Now()
	if at.Before(observed) || !at.Before(expires) || flow.Check(at, stored.Binding, cookie) != nil {
		return PreviewEvidence{}, CompletionDenied
	}
	if initiationContextEnded(work) {
		return PreviewEvidence{}, CompletionUnavailable
	}
	return PreviewEvidence{identity: principal, expires: expires, digest: sha256.Sum256(wire)}, nil
}

func (p *PreviewCompletionAdmission) matchesOriginal(original oauth.ProxyOIDCEvidenceBinding, origin string) bool {
	c := p.configuration
	target := PreviewTarget{Deployment: original.PreviewDeployment, Origin: original.PreviewOrigin, Redirect: original.PreviewRedirect, Recipient: original.Recipient}
	return validRecord(original) && original.TenantID == c.TenantID && original.ProductionDeployment == c.ProductionDeployment &&
		target == c.Target && origin == c.Target.Origin
}

func (p *PreviewCompletionAdmission) matchesFlow(original oauth.ProxyOIDCEvidenceBinding, flow session.PreAuthBinding) bool {
	c := p.configuration
	i := flow.Intent
	remember, originalErr := original.Remember.Bindings()
	flowRemember, flowErr := i.Remember.Bindings()
	return flow.ID == original.TransactionID && i.TenantID == c.TenantID && i.Action == completionAction &&
		i.Origin == c.Target.Origin && i.CallbackURL == c.Target.Redirect && i.PolicyID == c.PolicyID && i.PolicyVersion == c.PolicyVersion &&
		i.Purpose == session.PreAuthSessionIssuance && i.IdentifierBinding == ([32]byte{}) &&
		originalErr == nil && flowErr == nil && remember == flowRemember
}

func completionCookie(token session.Token, keys []session.DigestKey, stored session.PreAuthTransactionSpec) (session.TokenDigest, bool) {
	for _, key := range keys {
		digest, err := token.PreAuthDigest(key, stored.Binding)
		if err == nil && digest.KeyVersion == stored.Cookie.KeyVersion {
			return digest, true
		}
	}
	return session.TokenDigest{}, false
}

func completionPolicyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func nilCompletionClock(clock oauth.Clock) bool {
	if clock == nil {
		return true
	}
	value := reflect.ValueOf(clock)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (PreviewCompletionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewCompletionConfig(redacted)"))
}

func (PreviewCompletionRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewCompletionRequest(redacted)"))
}

func (PreviewEvidence) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewEvidence(redacted)"))
}

func (PreviewCompletionAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.PreviewCompletionAdmission(redacted)"))
}

func (PreviewCompletionConfig) MarshalJSON() ([]byte, error)    { return nil, CompletionInvalid }
func (PreviewCompletionConfig) MarshalText() ([]byte, error)    { return nil, CompletionInvalid }
func (PreviewCompletionRequest) MarshalJSON() ([]byte, error)   { return nil, CompletionInvalid }
func (PreviewCompletionRequest) MarshalText() ([]byte, error)   { return nil, CompletionInvalid }
func (PreviewEvidence) MarshalJSON() ([]byte, error)            { return nil, CompletionInvalid }
func (PreviewEvidence) MarshalText() ([]byte, error)            { return nil, CompletionInvalid }
func (PreviewCompletionAdmission) MarshalJSON() ([]byte, error) { return nil, CompletionInvalid }
func (PreviewCompletionAdmission) MarshalText() ([]byte, error) { return nil, CompletionInvalid }
