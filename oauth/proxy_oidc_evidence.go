package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const (
	proxyOIDCContext       = "identity.oauth.proxy-oidc-evidence.v1"
	proxyOIDCAuthorityV2   = "identity.oauth.proxy-oidc-evidence.v2"
	proxyOIDCMaximumWire   = 8192
	proxyOIDCMaximumRecord = 2048
	proxyOIDCLifetime      = 5 * time.Minute
	proxyOIDCKeyBudget     = 5 * time.Second
)

// ProxyOIDCEvidenceBinding is the original persisted provider and preview
// selection. A recipient must recover it independently of presented ciphertext.
// It carries no raw provider code, token, verifier or browser credential. Its
// original deadline must not be renewed at either endpoint.
type ProxyOIDCEvidenceBinding struct {
	TenantID                                                    identity.TenantID
	CommandID                                                   identity.CommandID
	TransactionID                                               identity.PreAuthTransactionID
	RequestFingerprint, StateDigest, PKCEChallengeDigest        [32]byte
	ProductionDeployment, PreviewDeployment, ProviderID, Issuer string
	ClientID, PreviewOrigin, PreviewRedirect, Recipient         string
	ClaimsProfile                                               string
	ProviderVersion, ClaimsVersion                              uint64
	// ProviderAuthorityEpoch is the live connection epoch, independent of the
	// configured ProviderVersion. Zero selects the original legacy wire context.
	// Only a caller that requires a nonzero current epoch may rely on this field
	// as part of live authority; successful decoding grants no authority itself.
	ProviderAuthorityEpoch uint64
	Remember               session.RememberPolicy
	IssuedAt, ExpiresAt    time.Time
}

// Format redacts original browser and transaction metadata.
func (ProxyOIDCEvidenceBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.ProxyOIDCEvidenceBinding(redacted)"))
}

// MarshalJSON refuses implicit persistence outside the owning storage profile.
func (ProxyOIDCEvidenceBinding) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit textual export of original binding metadata.
func (ProxyOIDCEvidenceBinding) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// ProxyOIDCEvidenceCodec transfers the minimal signed OIDC evidence needed to
// locate an existing linked account. It cannot initiate a flow, call a provider,
// reissue a browser credential, enforce one-use, or authorize account/session
// effects. Production and preview each retain their original durable custody.
// The borrowed service and clock must support concurrent use and outlive it.
type ProxyOIDCEvidenceCodec struct {
	crypto *secretenvelope.Service
	clock  Clock
	active string
	keys   map[string]struct{}
}

// NewProxyOIDCEvidenceCodec selects one active wrapping reference for writes
// and zero to 32 distinct retired references that may still be read. Active
// is implicitly readable. The trusted service and clock are required; no
// provider request, key I/O or pool ownership is performed at construction.
func NewProxyOIDCEvidenceCodec(crypto *secretenvelope.Service, clock Clock, activeKey string, retainedKeys []string) (*ProxyOIDCEvidenceCodec, error) {
	if crypto == nil || clock == nil || !proxyOIDCKey(activeKey) || len(retainedKeys) > 32 {
		return nil, failure(InvalidInput, nil)
	}
	keys := map[string]struct{}{strings.Clone(activeKey): {}}
	for _, key := range retainedKeys {
		if _, exists := keys[key]; exists || !proxyOIDCKey(key) {
			return nil, failure(InvalidInput, nil)
		}
		keys[strings.Clone(key)] = struct{}{}
	}
	return &ProxyOIDCEvidenceCodec{crypto: crypto, clock: clock, active: strings.Clone(activeKey), keys: keys}, nil
}

func proxyOIDCKey(key string) bool {
	return visible(key, 1, 256) && !strings.ContainsAny(key, " \t")
}

// Format redacts trusted service configuration.
func (*ProxyOIDCEvidenceCodec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.ProxyOIDCEvidenceCodec(redacted)"))
}

// MarshalJSON refuses serialization of the runtime key selection.
func (*ProxyOIDCEvidenceCodec) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

type proxyOIDCProfile struct {
	Subject               string
	IssuedAt, ExpiresAt   time.Time
	AuthenticationTime    time.Time
	EvidenceExpiresAt     time.Time
	HasAuthenticationTime bool
}

// Seal encrypts verified subject and signed times from the original successful
// OIDC code exchange. Client and provider version must match that exchange;
// selected claims, tokens and preview-restored identities cannot be forwarded.
// It returns fresh owned ciphertext, but neither consumes nor replaces state.
func (c *ProxyOIDCEvidenceCodec) Seal(ctx context.Context, b ProxyOIDCEvidenceBinding, i ProviderIdentity) ([]byte, error) {
	at, working, cancel, err := c.begin(ctx, b)
	if err != nil {
		return nil, err
	}
	defer cancel()
	profile := proxyOIDCProfile{i.subject, i.idTokenIssuedAt.UTC(), i.idTokenExpiresAt.UTC(), i.authenticatedAt.UTC(), i.EvidenceExpiresAt().UTC(), i.hasAuthenticationTime}
	if i.provider != b.ProviderID || i.issuer != b.Issuer || i.exchangeClientID != b.ClientID || i.exchangeProviderVersion != b.ProviderVersion || !profile.validAt(at) {
		return nil, failure(InvalidProof, ctx)
	}
	aad, err := b.context(c.active)
	if err != nil {
		return nil, failure(InvalidInput, ctx)
	}
	plain, err := json.Marshal(profile)
	defer clear(plain)
	if err != nil || len(plain) > proxyOIDCMaximumRecord {
		return nil, failure(InvalidProof, ctx)
	}
	envelope, err := c.crypto.Encrypt(working, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: c.active, Context: aad})
	if err != nil || envelope.KeyReference() != c.active || working.Err() != nil || !c.current(b, profile, at) {
		return nil, failure(Unavailable, ctx)
	}
	wire, err := envelope.MarshalBinary()
	if err != nil || len(wire) > proxyOIDCMaximumWire || working.Err() != nil || !c.current(b, profile, at) {
		clear(wire)
		return nil, failure(Unavailable, ctx)
	}
	return wire, nil
}

// Open authenticates one bounded artifact against the independently loaded
// original binding and a selected key. Only the minimal provider observation
// is returned, at its original signed times and not as production exchange or
// local session authority. The native recipient must still consume its own
// artifact exactly once under the original deadline before using the result.
func (c *ProxyOIDCEvidenceCodec) Open(ctx context.Context, b ProxyOIDCEvidenceBinding, wire []byte) (ProviderIdentity, error) {
	if len(wire) == 0 || len(wire) > proxyOIDCMaximumWire {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	at, working, cancel, err := c.begin(ctx, b)
	if err != nil {
		return ProviderIdentity{}, err
	}
	defer cancel()
	envelope, err := secretenvelope.ParseEnvelope(wire)
	if err != nil {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	key := envelope.KeyReference()
	if _, allowed := c.keys[key]; !allowed {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	aad, err := b.context(key)
	if err != nil {
		return ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	plain, err := c.crypto.Decrypt(working, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	var profile proxyOIDCProfile
	if err != nil || len(plain) > proxyOIDCMaximumRecord || json.Unmarshal(plain, &profile) != nil || !profile.validAt(at) {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	canonical, err := json.Marshal(profile)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || working.Err() != nil || !c.current(b, profile, at) {
		return ProviderIdentity{}, failure(InvalidProof, ctx)
	}
	return ProviderIdentity{provider: b.ProviderID, issuer: b.Issuer, subject: profile.Subject,
		authenticatedAt: profile.AuthenticationTime, hasAuthenticationTime: profile.HasAuthenticationTime,
		idTokenIssuedAt: profile.IssuedAt, idTokenExpiresAt: profile.ExpiresAt, evidenceExpiresAt: profile.EvidenceExpiresAt}, nil
}

func (p proxyOIDCProfile) validAt(at time.Time) bool {
	return visible(p.Subject, 1, 255) && !p.IssuedAt.IsZero() && !p.IssuedAt.After(at) && p.ExpiresAt.After(p.IssuedAt) &&
		p.EvidenceExpiresAt.After(at) && !p.EvidenceExpiresAt.After(p.ExpiresAt) &&
		(p.HasAuthenticationTime && !p.AuthenticationTime.IsZero() && !p.AuthenticationTime.After(p.IssuedAt) || !p.HasAuthenticationTime && p.AuthenticationTime.IsZero())
}

func (c *ProxyOIDCEvidenceCodec) current(b ProxyOIDCEvidenceBinding, profile proxyOIDCProfile, observed time.Time) bool {
	at := c.clock.Now()
	return !at.Before(observed) && at.Before(b.ExpiresAt) && profile.validAt(at)
}

func (c *ProxyOIDCEvidenceCodec) begin(ctx context.Context, b ProxyOIDCEvidenceBinding) (time.Time, context.Context, context.CancelFunc, error) {
	if ctx == nil || c == nil || c.crypto == nil || c.clock == nil || c.active == "" || !b.valid() {
		return time.Time{}, nil, nil, failure(InvalidInput, ctx)
	}
	at := c.clock.Now()
	if ctx.Err() != nil || at.Before(b.IssuedAt) || !at.Before(b.ExpiresAt) {
		return time.Time{}, nil, nil, failure(InvalidProof, ctx)
	}
	work, cancel := context.WithTimeout(ctx, min(proxyOIDCKeyBudget, b.ExpiresAt.Sub(at)))
	return at, work, cancel, nil
}

func (b ProxyOIDCEvidenceBinding) valid() bool {
	if !identifier(b.ProductionDeployment) || !identifier(b.PreviewDeployment) || b.ProductionDeployment == b.PreviewDeployment ||
		!identifier(b.ProviderID) || b.ProviderVersion == 0 || !httpsURL(b.Issuer) || !visible(b.ClientID, 1, 1024) ||
		!identifier(b.Recipient) || !identifier(b.ClaimsProfile) || b.ClaimsVersion == 0 || !proxyOIDCPreviewTarget(b.PreviewOrigin, b.PreviewRedirect) ||
		b.RequestFingerprint == ([32]byte{}) || b.StateDigest == ([32]byte{}) || b.PKCEChallengeDigest == ([32]byte{}) ||
		b.IssuedAt.IsZero() || b.IssuedAt.Year() < 1 || b.ExpiresAt.Year() > 9999 || !b.ExpiresAt.After(b.IssuedAt) || b.ExpiresAt.Sub(b.IssuedAt) > proxyOIDCLifetime {
		return false
	}
	_, tenant := identity.ParseIdentifierID(string(b.TenantID))
	_, command := identity.ParseCommandID(string(b.CommandID))
	_, transaction := identity.ParsePreAuthTransactionID(string(b.TransactionID))
	_, remember := b.Remember.Bindings()
	return tenant == nil && command == nil && transaction == nil && remember == nil
}

// Only registered canonical HTTPS DNS endpoints are accepted here, not paths
// selected by input, wildcards, escaped aliases or implicitly normalized URLs.
func proxyOIDCPreviewTarget(origin, redirect string) bool {
	if !httpsURL(origin) || !httpsURL(redirect) {
		return false
	}
	a, _ := url.Parse(origin)
	b, _ := url.Parse(redirect)
	host := a.Hostname()
	if a.Path != "" || a.Host != b.Host || len(host) > 253 || host != strings.ToLower(host) || !strings.Contains(host, ".") || b.Path == "" || b.Path == "/" ||
		b.RawPath != "" || strings.Contains(b.EscapedPath(), "%") || path.Clean(b.Path) != b.Path {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !identifier(label) || len(label) > 63 || strings.Contains(label, "_") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	if last := labels[len(labels)-1][0]; last < 'a' || last > 'z' {
		return false // Numeric host spellings can be interpreted as IPv4 by browsers.
	}
	port := a.Port()
	if port == "" {
		return a.Host == host
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && n != 443 && strconv.Itoa(n) == port
}

func (b ProxyOIDCEvidenceBinding) context(key string) (secretenvelope.Context, error) {
	remember, err := b.Remember.Bindings()
	if err != nil {
		return secretenvelope.Context{}, err
	}
	purpose := proxyOIDCContext
	if b.ProviderAuthorityEpoch != 0 {
		purpose = proxyOIDCAuthorityV2
	}
	fields := []any{purpose, "verified-oidc", b.TenantID, b.CommandID, b.TransactionID,
		b.RequestFingerprint, b.StateDigest, b.PKCEChallengeDigest, b.ProductionDeployment, b.PreviewDeployment,
		b.ProviderID, b.ProviderVersion, b.Issuer, b.ClientID, b.PreviewOrigin, b.PreviewRedirect, b.Recipient,
		b.ClaimsProfile, b.ClaimsVersion, remember, b.IssuedAt.UTC(), b.ExpiresAt.UTC(), key}
	if b.ProviderAuthorityEpoch != 0 {
		fields = append(fields, b.ProviderAuthorityEpoch)
	}
	frame, err := json.Marshal(fields)
	defer clear(frame)
	if err != nil {
		return secretenvelope.Context{}, err
	}
	digest := sha256.Sum256(frame)
	return secretenvelope.NewContext(map[string]string{"purpose": purpose, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
