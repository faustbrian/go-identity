package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const (
	proxyBindingDomain       = "identity.oauth.postgres.proxy-original-binding.v1"
	proxyBindingMaximumPlain = 16384
	proxyBindingMaximumWire  = 65536
)

var errProxyBinding = errors.New("oauth postgres: invalid proxy binding custody")

// These independently loaded row values are authenticated, not recovered from
// the ciphertext they locate. Current expiry, registration and lifecycle
// admission remain the native command owner's responsibility.
type proxyBindingLocator struct {
	Tenant                         identity.TenantID
	Transaction                    identity.PreAuthTransactionID
	OriginCommand, CallbackCommand identity.CommandID
	Production, Provider           string
	CallbackURI                    string
	ProviderVersion                uint64
	StateKeyVersion                uint32
	LookupDigest                   [32]byte
	IssuedAt, ExpiresAt            time.Time
}

type proxyOriginalBinding struct {
	Evidence                     oauth.ProxyOIDCEvidenceBinding
	CallbackNonce                string
	GlobalVersion, TenantVersion uint64
}

func (proxyOriginalBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.proxyOriginalBinding(redacted)"))
}

func (proxyOriginalBinding) MarshalJSON() ([]byte, error) { return nil, errProxyBinding }
func (proxyOriginalBinding) MarshalText() ([]byte, error) { return nil, errProxyBinding }

// Evidence deliberately refuses implicit JSON persistence. This versioned
// scalar projection is the sole native storage profile; no raw state, PKCE,
// authorization code, capability proof or provider token belongs here.
type proxyBindingRecord struct {
	Version                                                   uint8
	Tenant, Transaction, Command                              string
	RequestFingerprint, StateDigest, PKCEChallengeDigest      [32]byte
	ProductionDeployment, PreviewDeployment, Provider, Issuer string
	Client, PreviewOrigin, PreviewRedirect, Recipient         string
	ClaimsProfile                                             string
	ProviderVersion, ClaimsVersion                            uint64
	Remember                                                  session.RememberPolicySpec
	IssuedAt, ExpiresAt                                       time.Time
	CallbackNonce                                             string
	GlobalVersion, TenantVersion                              uint64
	ProviderAuthorityEpoch                                    uint64 `json:",omitempty"`
}

func sealProxyOriginalBinding(ctx context.Context, service *secretenvelope.Service, keyRef string, l proxyBindingLocator, original proxyOriginalBinding) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || service == nil {
		return nil, proxyBindingFailure(ctx)
	}
	aad, err := proxyBindingAAD(l, keyRef)
	if err != nil {
		return nil, errProxyBinding
	}
	record, err := freezeProxyEvidence(original.Evidence)
	if err != nil {
		return nil, errProxyBinding
	}
	record.CallbackNonce, record.GlobalVersion, record.TenantVersion = original.CallbackNonce, original.GlobalVersion, original.TenantVersion
	if _, err := record.original(l); err != nil {
		return nil, errProxyBinding
	}
	plain, err := json.Marshal(record)
	defer clear(plain)
	if err != nil || len(plain) > proxyBindingMaximumPlain {
		return nil, errProxyBinding
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	envelope, err := service.Encrypt(work, secretenvelope.EncryptRequest{Plaintext: plain, KeyReference: keyRef, Context: aad})
	if err != nil || envelope.KeyReference() != keyRef || work.Err() != nil {
		return nil, proxyBindingFailure(work)
	}
	wire, err := envelope.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > proxyBindingMaximumWire || work.Err() != nil {
		clear(wire)
		return nil, proxyBindingFailure(work)
	}
	return wire, nil
}

func freezeProxyEvidence(b oauth.ProxyOIDCEvidenceBinding) (proxyBindingRecord, error) {
	remember, err := b.Remember.Bindings()
	if err != nil {
		return proxyBindingRecord{}, errProxyBinding
	}
	var version uint8 = 1
	if b.ProviderAuthorityEpoch != 0 {
		version = 2
	}
	return proxyBindingRecord{
		Version: version, Tenant: string(b.TenantID), Transaction: string(b.TransactionID), Command: string(b.CommandID),
		RequestFingerprint: b.RequestFingerprint, StateDigest: b.StateDigest, PKCEChallengeDigest: b.PKCEChallengeDigest,
		ProductionDeployment: b.ProductionDeployment, PreviewDeployment: b.PreviewDeployment, Provider: b.ProviderID, Issuer: b.Issuer,
		Client: b.ClientID, PreviewOrigin: b.PreviewOrigin, PreviewRedirect: b.PreviewRedirect, Recipient: b.Recipient,
		ClaimsProfile: b.ClaimsProfile, ProviderVersion: b.ProviderVersion, ClaimsVersion: b.ClaimsVersion, Remember: remember,
		IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt, ProviderAuthorityEpoch: b.ProviderAuthorityEpoch,
	}, nil
}

func openProxyOriginalBinding(ctx context.Context, service *secretenvelope.Service, l proxyBindingLocator, ciphertext []byte) (proxyOriginalBinding, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || len(ciphertext) == 0 || len(ciphertext) > proxyBindingMaximumWire {
		return proxyOriginalBinding{}, proxyBindingFailure(ctx)
	}
	envelope, err := secretenvelope.ParseEnvelope(ciphertext)
	if err != nil {
		return proxyOriginalBinding{}, errProxyBinding
	}
	// The existing service resolves retained references; rotating the active
	// writing key does not rewrite the original record or extend its deadline.
	aad, err := proxyBindingAAD(l, envelope.KeyReference())
	if err != nil {
		return proxyOriginalBinding{}, errProxyBinding
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	plain, err := service.Decrypt(work, secretenvelope.DecryptRequest{Envelope: envelope, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > proxyBindingMaximumPlain || work.Err() != nil {
		return proxyOriginalBinding{}, proxyBindingFailure(work)
	}
	var record proxyBindingRecord
	if json.Unmarshal(plain, &record) != nil {
		return proxyOriginalBinding{}, errProxyBinding
	}
	canonical, err := json.Marshal(record)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || work.Err() != nil {
		return proxyOriginalBinding{}, proxyBindingFailure(work)
	}
	return record.original(l)
}

func proxyBindingAAD(l proxyBindingLocator, key string) (secretenvelope.Context, error) {
	_, originErr := identity.ParseCommandID(string(l.OriginCommand))
	_, callbackErr := identity.ParseCommandID(string(l.CallbackCommand))
	_, transactionErr := identity.ParsePreAuthTransactionID(string(l.Transaction))
	if !rpDirectoryID(string(l.Tenant)) || originErr != nil || callbackErr != nil || transactionErr != nil || l.OriginCommand == l.CallbackCommand ||
		!rpProviderID(l.Production) || !rpProviderID(l.Provider) || l.ProviderVersion == 0 ||
		proxyBindingHTTPS(l.CallbackURI) == nil || l.StateKeyVersion == 0 || l.LookupDigest == ([32]byte{}) ||
		!proxyBindingSQLTime(l.IssuedAt) || !proxyBindingSQLTime(l.ExpiresAt) || !l.ExpiresAt.After(l.IssuedAt) || l.ExpiresAt.Sub(l.IssuedAt) > 5*time.Minute ||
		!rpASCII(key, 1, 256) || strings.ContainsAny(key, " \t") {
		return secretenvelope.Context{}, errProxyBinding
	}
	frame, err := json.Marshal([]any{
		proxyBindingDomain, string(l.Tenant), string(l.Transaction), string(l.OriginCommand), string(l.CallbackCommand),
		l.Production, l.Provider, l.ProviderVersion, l.CallbackURI, l.StateKeyVersion, l.LookupDigest, l.IssuedAt, l.ExpiresAt, key,
	})
	defer clear(frame)
	if err != nil {
		return secretenvelope.Context{}, errProxyBinding
	}
	digest := sha256.Sum256(frame)
	aad, err := secretenvelope.NewContext(map[string]string{
		"purpose": proxyBindingDomain, "binding": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		return secretenvelope.Context{}, errProxyBinding
	}
	return aad, nil
}

func (r proxyBindingRecord) original(l proxyBindingLocator) (proxyOriginalBinding, error) {
	if r.Tenant != string(l.Tenant) || r.Transaction != string(l.Transaction) || r.Command != string(l.OriginCommand) ||
		r.ProductionDeployment != l.Production || r.Provider != l.Provider || r.ProviderVersion != l.ProviderVersion ||
		r.IssuedAt != l.IssuedAt || r.ExpiresAt != l.ExpiresAt ||
		!proxyBindingNonce(r.CallbackNonce) || r.GlobalVersion == 0 || r.TenantVersion == 0 {
		return proxyOriginalBinding{}, errProxyBinding
	}
	b, err := r.evidence()
	if err != nil {
		return proxyOriginalBinding{}, err
	}
	return proxyOriginalBinding{Evidence: b, CallbackNonce: r.CallbackNonce, GlobalVersion: r.GlobalVersion, TenantVersion: r.TenantVersion}, nil
}

func (r proxyBindingRecord) evidence() (oauth.ProxyOIDCEvidenceBinding, error) {
	if !(r.Version == 1 && r.ProviderAuthorityEpoch == 0 || r.Version == 2 && r.ProviderAuthorityEpoch != 0) ||
		r.RequestFingerprint == ([32]byte{}) || r.StateDigest == ([32]byte{}) || r.PKCEChallengeDigest == ([32]byte{}) ||
		!rpProviderID(r.PreviewDeployment) || r.PreviewDeployment == r.ProductionDeployment ||
		proxyBindingHTTPS(r.Issuer) == nil || !rpASCII(r.Client, 1, 1024) ||
		!proxyBindingPreviewTarget(r.PreviewOrigin, r.PreviewRedirect) || !rpProviderID(r.Recipient) || !rpProviderID(r.ClaimsProfile) || r.ClaimsVersion == 0 {
		return oauth.ProxyOIDCEvidenceBinding{}, errProxyBinding
	}
	remember, err := session.NewRememberPolicy(r.Remember)
	if err != nil {
		return oauth.ProxyOIDCEvidenceBinding{}, errProxyBinding
	}
	return oauth.ProxyOIDCEvidenceBinding{
		TenantID: identity.TenantID(r.Tenant), TransactionID: identity.PreAuthTransactionID(r.Transaction), CommandID: identity.CommandID(r.Command),
		RequestFingerprint: r.RequestFingerprint, StateDigest: r.StateDigest, PKCEChallengeDigest: r.PKCEChallengeDigest,
		ProductionDeployment: r.ProductionDeployment, PreviewDeployment: r.PreviewDeployment, ProviderID: r.Provider, ProviderVersion: r.ProviderVersion,
		ProviderAuthorityEpoch: r.ProviderAuthorityEpoch,
		Issuer:                 r.Issuer, ClientID: r.Client, PreviewOrigin: r.PreviewOrigin, PreviewRedirect: r.PreviewRedirect, Recipient: r.Recipient,
		ClaimsProfile: r.ClaimsProfile, ClaimsVersion: r.ClaimsVersion, Remember: remember, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
	}, nil
}

func proxyBindingSQLTime(t time.Time) bool {
	// PostgreSQL timestamptz stores microseconds. Refuse inputs that would be
	// silently rounded or normalized before becoming independent row locators.
	return rpUTCTime(t) && t == t.UTC() && t.Nanosecond()%1000 == 0
}

func proxyBindingNonce(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	var decoded [32]byte
	defer clear(decoded[:])
	n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], []byte(raw))
	return err == nil && n == len(decoded)
}

// Shape validation mirrors the consumed OAuth evidence profile, not deployment
// registration. The native owner must still select its exact configured target.
func proxyBindingHTTPS(raw string) *url.URL {
	if !rpASCII(raw, 1, 2048) || strings.ContainsAny(raw, " \\#*%") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != raw {
		return nil
	}
	return u
}

func proxyBindingPreviewTarget(origin, redirect string) bool {
	a, b := proxyBindingHTTPS(origin), proxyBindingHTTPS(redirect)
	if a == nil || b == nil || a.Path != "" || a.Host != b.Host || b.Path == "" || b.Path == "/" || path.Clean(b.Path) != b.Path {
		return false
	}
	host := a.Hostname()
	if len(host) > 253 || !strings.Contains(host, ".") || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !rpProviderID(label) || len(label) > 63 || strings.Contains(label, "_") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	if top := labels[len(labels)-1][0]; top < 'a' || top > 'z' {
		return false
	}
	if a.Port() == "" {
		return a.Host == host
	}
	port, err := strconv.Atoi(a.Port())
	return err == nil && port > 0 && port <= 65535 && port != 443 && strconv.Itoa(port) == a.Port()
}

type proxyBindingContextError struct{ cause error }

func (proxyBindingContextError) Error() string {
	return "oauth postgres: invalid proxy binding custody"
}
func (e proxyBindingContextError) Is(target error) bool {
	return target == errProxyBinding || target == e.cause
}

func proxyBindingFailure(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return proxyBindingContextError{cause: ctx.Err()}
	}
	return errProxyBinding
}
