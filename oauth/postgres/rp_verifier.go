package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-identity/oauth"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

var errRPVerifier = errors.New("oauth postgres: invalid RP verifier custody")

// rpVerifierBinding snapshots trusted native configuration, not callback claims.
// The sole AAD profile is REFERENCE_CONFIGURATION struct:ref.oauth.rp_transaction.
// It supplies no state validation, reservation, SQL or exchange authority.
type rpVerifierBinding struct {
	tenant, transactionID, operation string
	provider                         oauth.ProviderProfile
	stateDigest                      [32]byte
}

func newRPVerifierBinding(tenant string, profile oauth.ProviderProfile, transactionID string, stateDigest [32]byte, operation string) (rpVerifierBinding, error) {
	// The explicit Google policy has additional trusted profile constraints.
	// Reuse their protocol owner rather than admitting a foreign-issuer variant;
	// unselected profiles retain the released native validation and AAD bytes.
	if profile.GoogleAccounts && profile.ValidateQueryCallback() != nil {
		return rpVerifierBinding{}, errRPVerifier
	}
	b := rpVerifierBinding{tenant: tenant, provider: profile, transactionID: transactionID, stateDigest: stateDigest, operation: operation}
	if _, err := b.aad(); err != nil {
		return rpVerifierBinding{}, err
	}
	if len(profile.Scopes) > 32 || len(profile.Algorithms) > 2 {
		return rpVerifierBinding{}, errRPVerifier
	}
	for _, scope := range profile.Scopes {
		if !rpASCII(scope, 1, 128) {
			return rpVerifierBinding{}, errRPVerifier
		}
	}
	for _, algorithm := range profile.Algorithms {
		if algorithm != "ES256" && algorithm != "RS256" {
			return rpVerifierBinding{}, errRPVerifier
		}
	}
	b.provider = b.profile()
	return b, nil
}

func (b rpVerifierBinding) profile() oauth.ProviderProfile {
	p := b.provider
	p.Scopes = slices.Clone(p.Scopes)
	p.Algorithms = slices.Clone(p.Algorithms)
	return p
}

func (b rpVerifierBinding) aad() (secretenvelope.Context, error) {
	_, txErr := identity.ParsePreAuthTransactionID(b.transactionID)
	p := b.provider
	// secret-envelope/v2 NewContext limits each exact value to 1024
	// bytes. This selected native profile rejects longer values; the core OAuth
	// profile retains its own URL validation/limits. No hashing or truncation.
	if !rpDirectoryID(b.tenant) || !rpProviderID(p.ID) || !rpASCII(p.Issuer, 1, 1024) || !rpASCII(p.ClientID, 1, 1024) || !rpASCII(p.RedirectURI, 1, 1024) || !strings.HasPrefix(p.Issuer, "https://") || !strings.HasPrefix(p.RedirectURI, "https://") || txErr != nil || b.stateDigest == [32]byte{} || p.Version == 0 || p.ResponseMode != "query" || p.PKCEMethod != "S256" || !p.NonceRequired || p.StateBytes != 32 || p.NonceBytes != 32 || (b.operation != "identity.account.link-start" && b.operation != "identity.oauth.signin-start") {
		return secretenvelope.Context{}, errRPVerifier
	}
	c, err := secretenvelope.NewContext(map[string]string{
		"tenant": b.tenant, "provider": p.ID, "issuer": p.Issuer, "client_id": p.ClientID, "transaction_id": b.transactionID, "state_digest": hex.EncodeToString(b.stateDigest[:]), "redirect_uri": p.RedirectURI, "response_mode": p.ResponseMode, "operation": b.operation, "configuration_version": strconv.FormatUint(p.Version, 10),
	})
	if err != nil {
		return secretenvelope.Context{}, errRPVerifier
	}
	return c, nil
}

// Keys are secret-manager supplied, retained for the owner's process lifetime.
// The actual upstream immutable keyring copies its AES keys and has no erasure
// API. Commitment keys are separately copied; Go cannot promise runtime erasure.
type rpVerifierKeyConfig struct {
	CurrentEnvelopeKey       string
	EnvelopeKeys             map[string][]byte
	CurrentCommitmentVersion uint32
	CommitmentKeys           map[uint32][]byte
}

type rpVerifierCustody struct {
	envelopes      *secretenvelope.Service
	envelopeKey    string
	currentVersion uint32
	commitmentKeys map[uint32][]byte
}

// rpSealedVerifier is the original persistence payload, never admission proof.
// Only ciphertext and keyed commitment are retained, not raw PKCE or state.
type rpSealedVerifier struct {
	ciphertext []byte
	commitment [32]byte
	keyVersion uint32
}

func newRPVerifierCustody(c rpVerifierKeyConfig) (*rpVerifierCustody, error) {
	if len(c.EnvelopeKeys) == 0 || len(c.EnvelopeKeys) > 32 || len(c.CommitmentKeys) == 0 || len(c.CommitmentKeys) > 32 || !rpASCII(c.CurrentEnvelopeKey, 1, 128) || c.CurrentCommitmentVersion == 0 || len(c.EnvelopeKeys[c.CurrentEnvelopeKey]) != 32 || len(c.CommitmentKeys[c.CurrentCommitmentVersion]) < 32 {
		return nil, errRPVerifier
	}
	for ref, key := range c.EnvelopeKeys {
		if !rpASCII(ref, 1, 128) || strings.TrimSpace(ref) != ref || len(key) != 32 || rpZero(key) {
			return nil, errRPVerifier
		}
	}
	for version, key := range c.CommitmentKeys {
		if version == 0 || len(key) < 32 || len(key) > 64 || rpZero(key) {
			return nil, errRPVerifier
		}
		for _, envelopeKey := range c.EnvelopeKeys {
			if bytes.Equal(key, envelopeKey) {
				return nil, errRPVerifier
			}
		}
	}
	provider, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		return nil, errRPVerifier
	}
	service, err := secretenvelope.NewService(provider)
	if err != nil {
		return nil, errRPVerifier
	}
	keys := make(map[uint32][]byte, len(c.CommitmentKeys))
	for version, key := range c.CommitmentKeys {
		keys[version] = bytes.Clone(key)
	}
	return &rpVerifierCustody{envelopes: service, envelopeKey: c.CurrentEnvelopeKey, currentVersion: c.CurrentCommitmentVersion, commitmentKeys: keys}, nil
}

// seal borrows and privately copies the exact original verifier for one bounded
// encryption. The authoritative caller supplies original UTC issue/expiry, with
// every earlier native deadline already applied. Context expiry never refreshes
// those times; no new clock, flow TTL, state capability or replay owner exists.
func (c *rpVerifierCustody) seal(ctx context.Context, b rpVerifierBinding, verifier []byte, issued, expires time.Time) (rpSealedVerifier, error) {
	if !c.ready() || ctx == nil || ctx.Err() != nil || !rpVerifierBytes(verifier) || !rpVerifierLifetime(issued, expires) {
		return rpSealedVerifier{}, rpVerifierFailure(ctx)
	}
	aad, err := b.aad()
	if err != nil {
		return rpSealedVerifier{}, errRPVerifier
	}
	plain := bytes.Clone(verifier)
	defer clear(plain)
	envelope, err := c.envelopes.Encrypt(ctx, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: c.envelopeKey, Context: aad})
	if err != nil || ctx.Err() != nil {
		return rpSealedVerifier{}, rpVerifierFailure(ctx)
	}
	wire, err := envelope.MarshalBinary()
	if err != nil || len(wire) > 4096 {
		return rpSealedVerifier{}, errRPVerifier
	}
	commitment := rpVerifierCommitment(c.commitmentKeys[c.currentVersion], c.currentVersion, aad, plain, issued, expires)
	return rpSealedVerifier{ciphertext: wire, commitment: commitment, keyVersion: c.currentVersion}, nil
}

// open is private to the native callback exchange worker, AFTER canonical state
// reservation and original-flow admission. It must receive original persisted
// metadata and authoritative current UTC time, never callback-selected times.
// Expiry is exclusive and original validity cannot exceed ten minutes. Original
// timestamps are HMAC-bound to AAD/verifier/key version, so editing them cannot
// reset freshness. Every plaintext copy is cleared before returning real core
// PKCE custody. Errors retain no envelope/provider/input diagnostics.
func (c *rpVerifierCustody) open(ctx context.Context, b rpVerifierBinding, sealed rpSealedVerifier, issued, expires, now time.Time) (oauth.PKCEVerifier, error) {
	if !c.ready() || ctx == nil || ctx.Err() != nil || !rpVerifierLifetime(issued, expires) || !rpUTCTime(now) || now.Before(issued) || !now.Before(expires) || len(sealed.ciphertext) == 0 || len(sealed.ciphertext) > 4096 || len(c.commitmentKeys[sealed.keyVersion]) == 0 || sealed.commitment == [32]byte{} {
		return oauth.PKCEVerifier{}, rpVerifierFailure(ctx)
	}
	aad, err := b.aad()
	if err != nil {
		return oauth.PKCEVerifier{}, errRPVerifier
	}
	envelope, err := secretenvelope.ParseEnvelope(sealed.ciphertext)
	if err != nil {
		return oauth.PKCEVerifier{}, errRPVerifier
	}
	plain, err := c.envelopes.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	if err != nil || ctx.Err() != nil || !rpVerifierBytes(plain) {
		return oauth.PKCEVerifier{}, rpVerifierFailure(ctx)
	}
	want := rpVerifierCommitment(c.commitmentKeys[sealed.keyVersion], sealed.keyVersion, aad, plain, issued, expires)
	if !hmac.Equal(want[:], sealed.commitment[:]) {
		return oauth.PKCEVerifier{}, errRPVerifier
	}
	verifier, err := oauth.NewPKCEVerifier(plain)
	if err != nil {
		return oauth.PKCEVerifier{}, errRPVerifier
	}
	return verifier, nil
}

func (c *rpVerifierCustody) ready() bool {
	return c != nil && c.envelopes != nil && c.envelopeKey != "" && c.currentVersion > 0 && len(c.commitmentKeys[c.currentVersion]) >= 32
}

func rpVerifierCommitment(key []byte, version uint32, aad secretenvelope.Context, plain []byte, issued, expires time.Time) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("identity.oauth.rp.pkce-verifier.v1\x00"))
	_, _ = mac.Write([]byte(strconv.FormatUint(uint64(version), 10)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(aad.AdditionalData())
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(issued.Format(time.RFC3339Nano)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(expires.Format(time.RFC3339Nano)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(plain)
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

func rpVerifierBytes(value []byte) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, b := range value {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("-._~", b) >= 0 {
			continue
		}
		return false
	}
	return true
}
func rpUTCTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999
}
func rpVerifierLifetime(issued, expires time.Time) bool {
	return rpUTCTime(issued) && rpUTCTime(expires) && expires.After(issued) && expires.Sub(issued) <= 10*time.Minute
}
func rpZero(b []byte) bool {
	var all byte
	for _, v := range b {
		all |= v
	}
	return all == 0
}
func rpASCII(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := range s {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func rpDirectoryID(s string) bool {
	if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}
func rpProviderID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := range s {
		b := s[i]
		if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' {
			continue
		}
		return false
	}
	return true
}

type rpVerifierContextError struct{ kind error }

func (rpVerifierContextError) Error() string { return "oauth postgres: RP verifier unavailable" }
func (e rpVerifierContextError) Is(target error) bool {
	return target == errRPVerifier || target == e.kind
}
func rpVerifierFailure(ctx context.Context) error {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return rpVerifierContextError{context.Canceled}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return rpVerifierContextError{context.DeadlineExceeded}
		}
	}
	return errRPVerifier
}

func (rpVerifierBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("rpVerifierBinding(redacted)"))
}
func (rpVerifierBinding) MarshalJSON() ([]byte, error) { return nil, errRPVerifier }
func (rpVerifierBinding) MarshalText() ([]byte, error) { return nil, errRPVerifier }
func (rpVerifierKeyConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("rpVerifierKeyConfig(redacted)"))
}
func (rpVerifierKeyConfig) MarshalJSON() ([]byte, error) { return nil, errRPVerifier }
func (rpVerifierKeyConfig) MarshalText() ([]byte, error) { return nil, errRPVerifier }
func (rpVerifierCustody) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("rpVerifierCustody(redacted)"))
}
func (rpVerifierCustody) MarshalJSON() ([]byte, error) { return nil, errRPVerifier }
func (rpVerifierCustody) MarshalText() ([]byte, error) { return nil, errRPVerifier }
func (rpSealedVerifier) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("rpSealedVerifier(redacted)"))
}
func (rpSealedVerifier) MarshalJSON() ([]byte, error) { return nil, errRPVerifier }
func (rpSealedVerifier) MarshalText() ([]byte, error) { return nil, errRPVerifier }
