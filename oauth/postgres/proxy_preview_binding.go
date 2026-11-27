package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const proxyPreviewBindingDomain = "identity.oauth.postgres.proxy-preview-binding.v1"

// Load the locator from the preview's own row, never from the delivered envelope.
// ExpiresAt may be earlier than the production evidence deadline, never later.
type proxyPreviewBindingLocator struct {
	Tenant                         identity.TenantID
	Flow                           identity.PreAuthTransactionID
	OriginCommand, CallbackCommand identity.CommandID
	IssuedAt, ExpiresAt            time.Time
}

type proxyPreviewBinding struct {
	Evidence                     oauth.ProxyOIDCEvidenceBinding
	PreAuthDigest                [32]byte
	GlobalVersion, TenantVersion uint64
}

func (proxyPreviewBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.proxyPreviewBinding(redacted)"))
}

func (proxyPreviewBinding) MarshalJSON() ([]byte, error) { return nil, errProxyBinding }
func (proxyPreviewBinding) MarshalText() ([]byte, error) { return nil, errProxyBinding }

// The stable grant commitment covers this canonical plaintext in its own
// domain. Randomized wrapping and retained-key rotation cannot change it.
type proxyPreviewBindingRecord struct {
	Expected                     proxyBindingRecord
	PreAuthDigest                [32]byte
	GlobalVersion, TenantVersion uint64
}

func (r proxyPreviewBindingRecord) original(l proxyPreviewBindingLocator) (proxyPreviewBinding, error) {
	e := r.Expected
	if e.Tenant != string(l.Tenant) || e.Transaction != string(l.Flow) || e.Command != string(l.OriginCommand) ||
		e.IssuedAt != l.IssuedAt || !proxyBindingSQLTime(e.ExpiresAt) || e.ExpiresAt.Nanosecond() != 0 ||
		e.ExpiresAt.Before(l.ExpiresAt) || e.ExpiresAt.Sub(e.IssuedAt) > 5*time.Minute ||
		!rpProviderID(e.ProductionDeployment) || !rpProviderID(e.Provider) || e.ProviderVersion == 0 ||
		e.CallbackNonce != "" || e.GlobalVersion != 0 || e.TenantVersion != 0 ||
		r.PreAuthDigest == ([32]byte{}) || r.GlobalVersion == 0 || r.TenantVersion == 0 {
		return proxyPreviewBinding{}, errProxyBinding
	}
	b, err := e.evidence()
	if err != nil {
		return proxyPreviewBinding{}, err
	}
	return proxyPreviewBinding{Evidence: b, PreAuthDigest: r.PreAuthDigest, GlobalVersion: r.GlobalVersion, TenantVersion: r.TenantVersion}, nil
}

func proxyPreviewBindingAAD(l proxyPreviewBindingLocator, key string) (envelope.Context, error) {
	_, flowErr := identity.ParsePreAuthTransactionID(string(l.Flow))
	_, originErr := identity.ParseCommandID(string(l.OriginCommand))
	_, callbackErr := identity.ParseCommandID(string(l.CallbackCommand))
	if !rpDirectoryID(string(l.Tenant)) || flowErr != nil || originErr != nil || callbackErr != nil || l.OriginCommand == l.CallbackCommand ||
		!proxyBindingSQLTime(l.IssuedAt) || l.IssuedAt.Unix() <= 0 || l.IssuedAt.Nanosecond() != 0 ||
		!proxyBindingSQLTime(l.ExpiresAt) || l.ExpiresAt.Nanosecond() != 0 || !l.ExpiresAt.After(l.IssuedAt) || l.ExpiresAt.Sub(l.IssuedAt) > 5*time.Minute ||
		!rpASCII(key, 1, 256) || strings.ContainsAny(key, " \t") {
		return envelope.Context{}, errProxyBinding
	}
	frame, err := json.Marshal([]any{proxyPreviewBindingDomain, string(l.Tenant), string(l.Flow), string(l.OriginCommand),
		string(l.CallbackCommand), l.IssuedAt, l.ExpiresAt, key})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, errProxyBinding
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"purpose": proxyPreviewBindingDomain, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func sealProxyPreviewBinding(ctx context.Context, service *envelope.Service, key string, l proxyPreviewBindingLocator, b proxyPreviewBinding) ([]byte, [32]byte, error) {
	if ctx == nil || ctx.Err() != nil || service == nil {
		return nil, [32]byte{}, proxyBindingFailure(ctx)
	}
	aad, err := proxyPreviewBindingAAD(l, key)
	if err != nil {
		return nil, [32]byte{}, errProxyBinding
	}
	base, err := freezeProxyEvidence(b.Evidence)
	if err != nil {
		return nil, [32]byte{}, err
	}
	r := proxyPreviewBindingRecord{Expected: base, PreAuthDigest: b.PreAuthDigest, GlobalVersion: b.GlobalVersion, TenantVersion: b.TenantVersion}
	if _, err := r.original(l); err != nil {
		return nil, [32]byte{}, err
	}
	plain, err := json.Marshal(r)
	defer clear(plain)
	if err != nil || len(plain) > proxyBindingMaximumPlain {
		return nil, [32]byte{}, errProxyBinding
	}
	work, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	sealed, err := service.Encrypt(work, envelope.EncryptRequest{Plaintext: plain, KeyReference: key, Context: aad})
	if err != nil || sealed.KeyReference() != key || work.Err() != nil {
		return nil, [32]byte{}, proxyBindingFailure(work)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > proxyBindingMaximumWire || work.Err() != nil {
		clear(wire)
		return nil, [32]byte{}, proxyBindingFailure(work)
	}
	return wire, proxyPreviewBindingDigest(l, plain), nil
}

func openProxyPreviewBinding(ctx context.Context, service *envelope.Service, l proxyPreviewBindingLocator, wire []byte) (proxyPreviewBinding, [32]byte, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || len(wire) == 0 || len(wire) > proxyBindingMaximumWire {
		return proxyPreviewBinding{}, [32]byte{}, proxyBindingFailure(ctx)
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return proxyPreviewBinding{}, [32]byte{}, errProxyBinding
	}
	aad, err := proxyPreviewBindingAAD(l, sealed.KeyReference())
	if err != nil {
		return proxyPreviewBinding{}, [32]byte{}, errProxyBinding
	}
	work, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	plain, err := service.Decrypt(work, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > proxyBindingMaximumPlain || work.Err() != nil {
		return proxyPreviewBinding{}, [32]byte{}, proxyBindingFailure(work)
	}
	var record proxyPreviewBindingRecord
	if json.Unmarshal(plain, &record) != nil {
		return proxyPreviewBinding{}, [32]byte{}, errProxyBinding
	}
	canonical, err := json.Marshal(record)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || work.Err() != nil {
		return proxyPreviewBinding{}, [32]byte{}, proxyBindingFailure(work)
	}
	b, err := record.original(l)
	if err != nil {
		return proxyPreviewBinding{}, [32]byte{}, err
	}
	return b, proxyPreviewBindingDigest(l, canonical), nil
}

func proxyPreviewBindingDigest(l proxyPreviewBindingLocator, canonical []byte) [32]byte {
	digest := sha256.New()
	digest.Write([]byte(proxyPreviewBindingDomain + "\x00"))
	digest.Write([]byte(l.CallbackCommand)) // Canonical command IDs have exactly 22 bytes.
	var cutoff [8]byte
	binary.BigEndian.PutUint64(cutoff[:], uint64(l.ExpiresAt.Unix()))
	digest.Write(cutoff[:])
	digest.Write(canonical)
	var sum [32]byte
	digest.Sum(sum[:0])
	return sum
}
