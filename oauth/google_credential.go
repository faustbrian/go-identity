package oauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"

	googleoidc "github.com/faustbrian/go-authentication/oidc/v2"
)

// GoogleCredential is a synchronous borrowed Google ID-token input, not verified
// identity or callback admission. The caller owns and clears IDToken and must
// not mutate it during verification. No bytes are retained after the call; Go
// cannot guarantee erasure of compiler/runtime copies. Zero is invalid.
type GoogleCredential struct{ IDToken []byte }

// Format redacts the borrowed credential in every diagnostic format.
func (GoogleCredential) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.GoogleCredential(redacted)"))
}

// MarshalJSON refuses accidental credential serialization.
func (GoogleCredential) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental credential serialization.
func (GoogleCredential) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// GoogleCredentialNonce supplies the mandatory original canonical 32-byte nonce
// from the caller's trusted initiating transaction, never from inbound callback
// data. This projection grants no state admission, one-use or origin authority;
// those remain with the browser and durable transaction owners. Zero is invalid.
type GoogleCredentialNonce struct{ OriginalNonce string }

// Format redacts the original nonce in every diagnostic format.
func (GoogleCredentialNonce) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.GoogleCredentialNonce(redacted)"))
}

// MarshalJSON refuses accidental original-nonce serialization.
func (GoogleCredentialNonce) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental original-nonce serialization.
func (GoogleCredentialNonce) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// VerifyGoogleCredential verifies a borrowed credential only on the explicitly
// selected Google Accounts provider. It reuses the pinned strict Google validator
// and the code-flow identity projection, without exchanging or returning tokens.
// Any present at_hash/c_hash is rejected: this input supplies no original token
// or code against which to validate the binding. The configured key set may
// fetch public verification keys; this method calls no authorization, token,
// UserInfo or discovery endpoint and stores no credential. The provider timeout
// bounds validation; the key set must honor context.
//
// Invalid/empty/oversized input, a missing/noncanonical original nonce and a
// nil/zero/non-Google/closed provider return InvalidInput. Invalid signed proof
// returns InvalidProof. Cancellation/deadline returns Unavailable and preserves
// errors.Is for the context cause. Calls are concurrency-safe with distinct
// borrowed inputs; Close does not cancel already admitted validation.
//
// The caller must first validate browser CSRF/origin and native transaction
// bindings. This method neither consumes nonce/state nor prevents replay, links
// accounts, validates hosted-domain/email policy or grants local signin/session
// authority. A successful ProviderIdentity is only verified provider evidence.
func (p *OIDCProvider) VerifyGoogleCredential(ctx context.Context, credential GoogleCredential, nonce GoogleCredentialNonce) (ProviderIdentity, error) {
	return p.verifyGoogleCredential(ctx, credential, nonce, nil)
}

func (p *OIDCProvider) verifyGoogleCredential(ctx context.Context, credential GoogleCredential, nonce GoogleCredentialNonce, domain *GoogleHostedDomain) (ProviderIdentity, error) {
	if ctx == nil || !p.ready() || !p.googleAccounts || len(credential.IDToken) == 0 || len(credential.IDToken) > p.config.MaxTokenBytes || !canonical32(nonce.OriginalNonce) {
		return ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return ProviderIdentity{}, failure(Unavailable, ctx)
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	token := bytes.Clone(credential.IDToken)
	defer clear(token)
	nonceCheck := googleoidc.NonceValidatorFunc(func(_ context.Context, actual string) error {
		if subtle.ConstantTimeCompare([]byte(actual), []byte(nonce.OriginalNonce)) != 1 {
			return failure(InvalidProof, nil)
		}
		return nil
	})
	validator, err := googleoidc.NewGoogleAccountsWithKeySet(googleValidatorConfig(p.config, nonceCheck), p.config.KeySet)
	if err != nil {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	principal, err := validator.ValidateBearer(ctx, string(token))
	if ctx.Err() != nil {
		return ProviderIdentity{}, failure(Unavailable, ctx)
	}
	if err != nil {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	metadata, ok := validatedMetadata(token)
	// OIDC Core 3.1.3.6 binds a present hash to its original companion bytes.
	// Direct credential mode has neither companion; null is present, not absent.
	if !ok || len(metadata.AccessHash) > 0 || len(metadata.CodeHash) > 0 {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	if domain != nil && !domain.matchesValidatedToken(token) {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	verified, ok := p.projectValidatedIdentity(token, principal, metadata)
	if !ok {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	return verified, nil
}
