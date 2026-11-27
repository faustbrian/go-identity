// Package oauthproxy coordinates the production side of an OAuth preview
// handoff without selecting or changing a production user, account or session.
package oauthproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// CallbackError is a stable redacted error classification. A denied callback
// never returns a destination. Reconciliation requires reading the original
// durable outcome; sending another exchange is not a recovery operation.
type CallbackError string

func (e CallbackError) Error() string { return "oauth proxy: " + string(e) }

const (
	CallbackInvalid   CallbackError = "invalid_callback"
	CallbackDenied    CallbackError = "callback_denied"
	CallbackReconcile CallbackError = "reconciliation_required"
)

// ErrOriginalUnavailable may be returned only after an authoritative refusal
// of reservation (for example, absent, expired or already reserved state).
// A failed or unknown read/write acknowledgement must not return this error.
const ErrOriginalUnavailable CallbackError = "original_unavailable"

// PreviewTarget is a trusted exact registration. One deployment selects one
// origin, completion endpoint and recipient; none are read from the callback.
type PreviewTarget struct {
	Deployment, Origin, Redirect, Recipient string
}

// CallbackLookup selects the original one-use production record. StateDigest
// is derived from the parsed callback; the other fields are trusted provider
// configuration. This lookup contains no raw callback input or verifier.
type CallbackLookup struct {
	StateDigest                                          [32]byte
	ProductionDeployment, ProductionCallback, ProviderID string
	Issuer, ClientID                                     string
	ProviderVersion                                      uint64
	ProviderDenied                                       bool
}

// OriginalCallback is returned only by an acknowledged durable reservation.
// Verifier custody is transferred to the caller; the store must not return a
// retained shared alias. Nonce is the provider nonce of that same record.
type OriginalCallback struct {
	ID       [32]byte
	Binding  oauth.ProxyOIDCEvidenceBinding
	Verifier oauth.PKCEVerifier
	Nonce    string
}

func (OriginalCallback) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.OriginalCallback(redacted)"))
}

func (OriginalCallback) MarshalJSON() ([]byte, error) { return nil, CallbackInvalid }
func (OriginalCallback) MarshalText() ([]byte, error) { return nil, CallbackInvalid }

// CallbackDisposition selects the durable disposition of the reserved record.
// Reconciliation must withhold the handoff and forbid automatic re-exchange.
type CallbackDisposition uint8

const (
	CallbackForwarded CallbackDisposition = iota + 1
	CallbackRejected
	CallbackNeedsReconciliation
)

// ProductionCallbackStore owns current native authority, replay, recovery and
// the audit event. Reserve atomically fences the exact record and lifetime and
// acknowledges durable exclusive ownership before releasing the verifier. An
// abandoned or ambiguous reservation must never allow a second exchange.
// A parsed provider denial does not require opening or releasing the verifier.
// Finalize acknowledges the exact reservation, persists the disposition and,
// for Forwarded/Rejected, stages identity.oauth.use_proxy once. Forwarded must
// recheck original current authority and expiry; any failed acknowledgement
// withholds the result. The envelope is borrowed only during the call. This
// interface does not authorize changes to users, accounts, sessions or cookies.
type ProductionCallbackStore interface {
	Reserve(context.Context, CallbackLookup) (OriginalCallback, error)
	Finalize(context.Context, [32]byte, CallbackDisposition, []byte) error
}

type callbackProviderExchange interface {
	Profile() oauth.ProviderProfile
	Exchange(context.Context, identity.OAuthCallbackInput, oauth.PKCEVerifier, string) (oauth.ProviderIdentity, error)
}

// ProductionCallbackConfig selects the trusted provider, keys and registered
// preview targets. Borrowed collaborators must support concurrent use. Targets
// and provider profile slices are copied at construction.
type ProductionCallbackConfig struct {
	ProductionDeployment string
	Provider             *oauth.OIDCProxyExchange
	Codec                *oauth.ProxyOIDCEvidenceCodec
	Store                ProductionCallbackStore
	Clock                oauth.Clock
	Targets              []PreviewTarget
}

type ProductionCallback struct {
	production string
	provider   callbackProviderExchange
	profile    oauth.ProviderProfile
	codec      *oauth.ProxyOIDCEvidenceCodec
	store      ProductionCallbackStore
	clock      oauth.Clock
	targets    map[string]PreviewTarget
}

// NewProductionCallback performs no external IO. The registered callback URI
// remains the provider's exact configured production URI. HTTP composition
// must supply the effective route from trusted deployment configuration.
func NewProductionCallback(c ProductionCallbackConfig) (*ProductionCallback, error) {
	if c.Provider == nil {
		return nil, CallbackInvalid
	}
	return newProductionCallback(c, c.Provider)
}

func newProductionCallback(c ProductionCallbackConfig, provider callbackProviderExchange) (*ProductionCallback, error) {
	if !identifier(c.ProductionDeployment) || c.Codec == nil || c.Store == nil || c.Clock == nil || len(c.Targets) == 0 || len(c.Targets) > 64 {
		return nil, CallbackInvalid
	}
	profile := provider.Profile()
	if profile.ValidateQueryCallback() != nil {
		return nil, CallbackInvalid
	}
	profile.Scopes = slices.Clone(profile.Scopes)
	profile.Algorithms = slices.Clone(profile.Algorithms)
	targets := make(map[string]PreviewTarget, len(c.Targets))
	for _, target := range c.Targets {
		if !target.valid() || target.Deployment == c.ProductionDeployment {
			return nil, CallbackInvalid
		}
		if _, exists := targets[target.Deployment]; exists {
			return nil, CallbackInvalid
		}
		targets[target.Deployment] = target
	}
	return &ProductionCallback{production: c.ProductionDeployment, provider: provider, profile: profile,
		codec: c.Codec, store: c.Store, clock: c.Clock, targets: targets}, nil
}

// CallbackResult holds only acknowledged encrypted handoff custody and its
// exact recipient endpoint. It conveys no preview consumption authority.
type CallbackResult struct {
	destination string
	envelope    []byte
}

func (r CallbackResult) Destination() string { return r.destination }
func (r CallbackResult) Envelope() []byte    { return bytes.Clone(r.envelope) }

func (CallbackResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.CallbackResult(redacted)"))
}

func (CallbackResult) MarshalJSON() ([]byte, error) { return nil, CallbackInvalid }
func (CallbackResult) MarshalText() ([]byte, error) { return nil, CallbackInvalid }

const storageBudget = 5 * time.Second

// Handle parses the provider's query callback without taking redirects from
// input. It does not retry collaborators. When the parent is cancelled after
// reservation, a bounded detached context records the disposition, but a
// handoff is never disclosed after cancellation or original expiry.
func (p *ProductionCallback) Handle(ctx context.Context, receivedCallback, rawQuery string) (result CallbackResult, err error) {
	if p == nil || ctx == nil || p.store == nil || receivedCallback != p.profile.RedirectURI || ctx.Err() != nil {
		return CallbackResult{}, CallbackInvalid
	}
	defer func() {
		if recover() != nil {
			result, err = CallbackResult{}, CallbackReconcile
		}
	}()
	query, err := oauth.ParseQueryCallback(ctx, rawQuery, p.profile)
	if err != nil {
		return CallbackResult{}, CallbackInvalid
	}
	defer query.Destroy()

	state, input, err := callbackState(ctx, query)
	if err != nil {
		return CallbackResult{}, CallbackInvalid
	}
	lookup := CallbackLookup{
		StateDigest: state, ProductionDeployment: p.production, ProductionCallback: receivedCallback,
		ProviderID: p.profile.ID, ProviderVersion: p.profile.Version, Issuer: p.profile.Issuer, ClientID: p.profile.ClientID,
		ProviderDenied: query.Denied(),
	}
	reserveCtx, stop := context.WithTimeout(ctx, storageBudget)
	defer stop()
	original, err := p.store.Reserve(reserveCtx, lookup)
	acknowledged := reserveCtx.Err() == nil
	stop()
	defer original.Verifier.Destroy()
	if !acknowledged {
		return CallbackResult{}, CallbackReconcile
	}
	if errors.Is(err, ErrOriginalUnavailable) {
		return CallbackResult{}, CallbackDenied
	}
	if err != nil || original.ID == ([32]byte{}) {
		return CallbackResult{}, CallbackReconcile
	}
	if !p.matchesOriginal(lookup, original) {
		return p.finalize(ctx, original, CallbackNeedsReconciliation, nil)
	}
	if lookup.ProviderDenied || ctx.Err() != nil || !p.current(original.Binding) {
		return p.finalize(ctx, original, CallbackRejected, nil)
	}
	work, cancel := context.WithTimeout(ctx, original.Binding.ExpiresAt.Sub(p.clock.Now()))
	defer cancel()
	proof, err := p.provider.Exchange(work, input, original.Verifier, original.Nonce)
	if err != nil {
		return p.finalize(ctx, original, exchangeDisposition(err), nil)
	}
	if work.Err() != nil || !p.current(original.Binding) || !proof.EvidenceExpiresAt().After(p.clock.Now()) {
		return p.finalize(ctx, original, CallbackRejected, nil)
	}
	artifact, err := p.codec.Seal(work, original.Binding, proof)
	if err != nil {
		return p.finalize(ctx, original, CallbackNeedsReconciliation, nil)
	}
	defer clear(artifact)
	if work.Err() != nil || !p.current(original.Binding) || !proof.EvidenceExpiresAt().After(p.clock.Now()) {
		return p.finalize(ctx, original, CallbackRejected, nil)
	}
	result, err = p.finalize(ctx, original, CallbackForwarded, artifact)
	if err == nil && !proof.EvidenceExpiresAt().After(p.clock.Now()) {
		clear(result.envelope)
		return CallbackResult{}, CallbackReconcile
	}
	return result, err
}

func callbackState(ctx context.Context, query oauth.QueryCallback) ([32]byte, identity.OAuthCallbackInput, error) {
	var digest [32]byte
	hash := func(_ context.Context, state []byte) error {
		digest = sha256.Sum256(state)
		return nil
	}
	if query.Denied() {
		err := query.UseDeniedState(ctx, hash)
		return digest, identity.OAuthCallbackInput{}, err
	}
	input, ok := query.Input()
	if !ok {
		return digest, input, CallbackInvalid
	}
	err := input.Use(ctx, func(ctx context.Context, _, state []byte) error { return hash(ctx, state) })
	return digest, input, err
}

func (p *ProductionCallback) current(b oauth.ProxyOIDCEvidenceBinding) bool {
	now := p.clock.Now()
	return !now.Before(b.IssuedAt) && now.Before(b.ExpiresAt)
}

func (p *ProductionCallback) matchesOriginal(lookup CallbackLookup, original OriginalCallback) bool {
	b := original.Binding
	target, registered := p.targets[b.PreviewDeployment]
	if !registered || target.Origin != b.PreviewOrigin || target.Redirect != b.PreviewRedirect || target.Recipient != b.Recipient ||
		b.ProductionDeployment != lookup.ProductionDeployment || b.ProviderID != lookup.ProviderID || b.ProviderVersion != lookup.ProviderVersion ||
		b.Issuer != lookup.Issuer || b.ClientID != lookup.ClientID || b.StateDigest != lookup.StateDigest || !validRecord(b) {
		return false
	}
	if lookup.ProviderDenied {
		return true
	}
	challenge := original.Verifier.Challenge()
	return challenge != "" && sha256.Sum256([]byte(challenge)) == b.PKCEChallengeDigest && canonicalNonce(original.Nonce)
}

func canonicalNonce(nonce string) bool {
	if len(nonce) != 43 {
		return false
	}
	var decoded [32]byte
	defer clear(decoded[:])
	n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], []byte(nonce))
	return err == nil && n == len(decoded)
}

func exchangeDisposition(err error) CallbackDisposition {
	var provider *oauth.Error
	if errors.As(err, &provider) {
		switch provider.Kind() {
		case oauth.InvalidInput, oauth.Refused, oauth.InvalidProof, oauth.Unavailable:
			return CallbackRejected
		}
	}
	return CallbackNeedsReconciliation
}

func (p *ProductionCallback) finalize(ctx context.Context, original OriginalCallback, disposition CallbackDisposition, envelope []byte) (CallbackResult, error) {
	settle, cancel := context.WithTimeout(context.WithoutCancel(ctx), storageBudget)
	defer cancel()
	if err := p.store.Finalize(settle, original.ID, disposition, envelope); err != nil || settle.Err() != nil {
		return CallbackResult{}, CallbackReconcile
	}
	switch disposition {
	case CallbackRejected:
		return CallbackResult{}, CallbackDenied
	case CallbackForwarded:
		if ctx.Err() == nil && p.current(original.Binding) {
			return CallbackResult{destination: original.Binding.PreviewRedirect, envelope: bytes.Clone(envelope)}, nil
		}
	}
	return CallbackResult{}, CallbackReconcile
}
