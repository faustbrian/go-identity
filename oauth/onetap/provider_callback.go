package onetap

import (
	"context"
	"fmt"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// ProviderBoundConfig freezes the exact Google browser policy and optional
// trusted hosted-domain restriction. HostedDomain is empty or an exact canonical
// domain accepted by oauth.NewGoogleHostedDomain; never choose it from callback
// fields. Bind changes to it to the original PolicyID/PolicyVersion. Provider,
// Clock, origin, ownership and concurrency requirements are Config's.
type ProviderBoundConfig struct {
	Provider         *oauth.OIDCProvider
	TenantID         identity.TenantID
	Origin, PolicyID string
	PolicyVersion    uint64
	Clock            oauth.Clock
	HostedDomain     string
}

// ProviderBoundAdapterBinding is trusted original server context, not browser
// input. Transaction must retain its persisted provider-selected authority and
// Expected must be its exact original binding. Cookie must be independently
// computed with Token.ProviderPreAuthDigest from this request's flow cookie,
// never copied from storage. The validator derives its provider/client/mode
// solely from startup configuration; the adapter cannot select them here.
type ProviderBoundAdapterBinding struct {
	Transaction session.PreAuthTransaction
	Expected    session.PreAuthBinding
	Cookie      session.TokenDigest
}

// ProviderBoundValidator verifies read-only evidence for its constructor-selected
// callback or redirect mode. A mode cannot be selected by the callback command.
// It is concurrency-safe for distinct borrowed commands, owns no stores or
// goroutines and consumes no flow. Provider and key-set lifetimes are Config's.
type ProviderBoundValidator struct {
	validator    *Validator
	selected     session.PreAuthProviderBinding
	hostedDomain *oauth.GoogleHostedDomain
}

// NewProviderBoundValidator validates trusted startup configuration without IO
// or clock reads. Provider/version/client/callback mode are selected privately
// from the configured Google provider, never supplied by a callback adapter.
func NewProviderBoundValidator(c ProviderBoundConfig) (*ProviderBoundValidator, error) {
	v, err := NewValidator(Config{
		Provider: c.Provider, TenantID: c.TenantID, Origin: c.Origin,
		PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, Clock: c.Clock,
	})
	if err != nil {
		return nil, err
	}
	bound := &ProviderBoundValidator{
		validator: v,
		selected: session.PreAuthProviderBinding{
			ProviderID: v.profile.ID, ProviderVersion: v.profile.Version,
			ClientID: v.profile.ClientID, Mode: session.PreAuthProviderCallback,
		},
	}
	if c.HostedDomain != "" {
		domain, err := oauth.NewGoogleHostedDomain(c.HostedDomain)
		if err != nil {
			return nil, failure(InvalidInput, nil)
		}
		bound.hostedDomain = &domain
	}
	return bound, nil
}

// NewProviderBoundRedirectValidator selects only the Google button redirect
// profile and one exact trusted same-origin HTTPS endpoint, at most 2048 visible
// ASCII bytes. The endpoint must have a clean literal path without query,
// fragment, escapes or semicolon; no aliases are normalized. Register this exact
// login_uri for the configured Google client before browser use. Construction
// performs no IO, clock reads, registration checks or transaction issuance.
//
// Validate requires that same endpoint in both the original CallbackURL and the
// trusted Callback.Redirect context, the original initiating origin, a redirect-
// bound transaction and an independently derived provider cookie digest. Google's
// separate double-submit CSRF proof remains mandatory before credential parsing.
// The result, borrowed dependency lifetime and read-only semantics are unchanged.
func NewProviderBoundRedirectValidator(c ProviderBoundConfig, redirectURL string) (*ProviderBoundValidator, error) {
	bound, err := NewProviderBoundValidator(c)
	if err != nil {
		return nil, err
	}
	if !canonicalRedirectEndpoint(c.Origin, redirectURL) {
		return nil, failure(InvalidInput, nil)
	}
	bound.selected.Mode = session.PreAuthProviderRedirect
	bound.validator.redirectURL = strings.Clone(redirectURL)
	return bound, nil
}

// ProviderBoundResult contains generic verified provider evidence and the full
// unchanged original provider-bound transaction projection. It is not active
// state, one-use admission or local signin/link/session authority. The durable
// owner must reread, fence, reserve/apply/finalize and recover unknown completion.
type ProviderBoundResult struct {
	identity oauth.ProviderIdentity
	original session.ProviderPreAuthTransactionSpec
}

// Identity returns only the existing generic verified OAuth identity projection.
func (r ProviderBoundResult) Identity() oauth.ProviderIdentity { return r.identity }

// Original returns the complete unchanged original private storage projection,
// including provider/client/mode, record version, nonce, cookie and RememberPolicy.
// A zero or rejected result returns InvalidInput and no projection.
func (r ProviderBoundResult) Original() (session.ProviderPreAuthTransactionSpec, error) {
	if r.identity.Subject() == "" {
		return session.ProviderPreAuthTransactionSpec{}, failure(InvalidInput, nil)
	}
	return r.original, nil
}

// Validate rejects CSRF/origin and original provider-bound context before signed
// credential work, then checks the original authority again after verification.
// Exact configured hd, when selected, is enforced only by Google's signed claim;
// email and browser hints are never a fallback. Validation is read-only and may
// succeed repeatedly until the durable owner consumes or invalidates the flow.
func (v *ProviderBoundValidator) Validate(ctx context.Context, b ProviderBoundAdapterBinding, c Callback) (ProviderBoundResult, error) {
	if ctx == nil || v == nil || v.validator == nil {
		return ProviderBoundResult{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return ProviderBoundResult{}, failure(Unavailable, ctx)
	}
	policy := v.validator
	if !policy.matchesBrowserContext(c) || !policy.matchesOriginalIntent(b.Expected.Intent) {
		return ProviderBoundResult{}, failure(Denied, ctx)
	}
	if err := b.Transaction.CheckProvider(policy.config.Clock.Now(), b.Expected, v.selected, b.Cookie); err != nil {
		return ProviderBoundResult{}, failure(Denied, ctx)
	}
	verified, err := policy.verifyCredential(ctx, c.Credential, b.Expected.Intent.Nonce, v.hostedDomain)
	if err != nil {
		return ProviderBoundResult{}, err
	}
	if err := b.Transaction.CheckProvider(policy.config.Clock.Now(), b.Expected, v.selected, b.Cookie); err != nil {
		return ProviderBoundResult{}, failure(Denied, ctx)
	}
	if ctx.Err() != nil {
		return ProviderBoundResult{}, failure(Unavailable, ctx)
	}
	original, err := b.Transaction.ProviderBindings()
	if err != nil {
		return ProviderBoundResult{}, failure(Denied, ctx)
	}
	return ProviderBoundResult{identity: verified, original: original}, nil
}

// Format redacts the trusted policy, provider and hosted-domain restriction.
func (ProviderBoundConfig) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental private configuration export.
func (ProviderBoundConfig) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental private configuration export.
func (ProviderBoundConfig) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts all correlated original transaction fields.
func (ProviderBoundAdapterBinding) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental private transaction export.
func (ProviderBoundAdapterBinding) MarshalJSON() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// MarshalText denies accidental private transaction export.
func (ProviderBoundAdapterBinding) MarshalText() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// Format redacts the original flow and verified identity evidence.
func (ProviderBoundResult) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental identity or flow export.
func (ProviderBoundResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental identity or flow export.
func (ProviderBoundResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// Format redacts the frozen policy and provider configuration.
func (*ProviderBoundValidator) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON denies accidental private validator export.
func (*ProviderBoundValidator) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText denies accidental private validator export.
func (*ProviderBoundValidator) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
