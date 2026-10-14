package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ErrBrowserDeviceDenied uniformly rejects invalid, expired or mismatched
// browser-device custody. It reveals no token, key or previously seen browser.
var ErrBrowserDeviceDenied = errors.New("session: browser device denied")

// BrowserDeviceKey is immutable dedicated HMAC material. It cannot substitute
// for session lookup, CSRF or MFA keys. Deploy independent CSPRNG material,
// never reuse a version for different bytes, and retain old versions until all
// issued cookies expire. Zero is invalid; copies are safe for concurrent use.
type BrowserDeviceKey struct{ key DigestKey }

// NewBrowserDeviceKey copies 32..64 bytes under a positive rotation version.
// All-zero material denies. Source erasure and key distribution are caller-owned.
func NewBrowserDeviceKey(version uint32, material []byte) (BrowserDeviceKey, error) {
	k, err := NewDigestKey(version, material)
	if err != nil {
		return BrowserDeviceKey{}, ErrInvalidPolicy
	}
	nonzero := byte(0)
	for _, b := range material {
		nonzero |= b
	}
	if nonzero == 0 {
		return BrowserDeviceKey{}, ErrInvalidPolicy
	}
	return BrowserDeviceKey{key: k}, nil
}

// BrowserDeviceConfig is copied at construction. Namespace is the stable
// deployment/environment separation (1..128 visible ASCII bytes). Keys contains
// 1..16 distinct dedicated versions; ActiveVersion must be the greatest version.
// Lifetime is whole seconds in 1 hour..7 days. Cookie must use the existing
// __Host-identity_device Lax/Strict host-only profile. Policy/key removal may
// deliberately invalidate old cookies; it must never renew their original TTL.
type BrowserDeviceConfig struct {
	Namespace     string
	Keys          []BrowserDeviceKey
	ActiveVersion uint32
	Lifetime      time.Duration
	Cookie        CookiePolicy
}

// BrowserDeviceCodec owns no store, callbacks or goroutines. It issues and
// verifies a bounded server-random browser correlation cookie, not a session,
// authentication proof, hardware fingerprint or MFA trusted-device credential.
// Clearing/copying cookies can evade/share this signal; IP and identifier abuse
// controls must remain independent. Zero denies; methods are concurrency-safe.
type BrowserDeviceCodec struct {
	namespace string
	keys      map[uint32]BrowserDeviceKey
	active    uint32
	lifetime  time.Duration
	cookie    CookiePolicy
}

// BrowserDevice is immutable non-authoritative correlation and original expiry.
// Zero is invalid. Only Issue retains a cookie header; Resolve cannot renew or
// redeliver it. Explicit projections are sensitive. No account authority or
// durable identity is established by any field or successful resolution.
type BrowserDevice struct{ state *browserDeviceState }

// Like Token and DigestKey, pointer custody prevents inline disclosure when
// fmt bypasses methods on a consumer's unexported enclosing field.
type browserDeviceState struct {
	id, cookie string
	expires    time.Time
}

// NewBrowserDeviceCodec validates explicit policy and freezes key selection
// without entropy or IO. It does not select an HTTP route or issue a cookie.
func NewBrowserDeviceCodec(c BrowserDeviceConfig) (*BrowserDeviceCodec, error) {
	if !authorityKey(c.Namespace, 128) || len(c.Keys) < 1 || len(c.Keys) > 16 ||
		c.Lifetime < time.Hour || c.Lifetime > 7*24*time.Hour || c.Lifetime%time.Second != 0 || c.Cookie.name != "__Host-identity_device" {
		return nil, ErrInvalidPolicy
	}
	keys := make(map[uint32]BrowserDeviceKey, len(c.Keys))
	maximum := uint32(0)
	for _, k := range c.Keys {
		if k.key.state == nil || keys[k.key.state.version].key.state != nil {
			return nil, ErrInvalidPolicy
		}
		keys[k.key.state.version] = k
		maximum = max(maximum, k.key.state.version)
	}
	if c.ActiveVersion == 0 || c.ActiveVersion != maximum {
		return nil, ErrInvalidPolicy
	}
	return &BrowserDeviceCodec{namespace: strings.Clone(c.Namespace), keys: keys, active: c.ActiveVersion, lifetime: c.Lifetime, cookie: c.Cookie}, nil
}

// Issue creates one fresh random correlation cookie after trusted transport
// admission. now is trusted time; tenant/origin must be the exact HTTPS mapping
// resolved by the current request, not JSON or arbitrary headers. Context must
// be nonnil and live. The only entropy source is standard-library crypto/rand;
// no resource ownership transfers. Time is rounded down to whole UTC seconds,
// never extending Lifetime. Call once per deliberate browser initialization,
// reuse an existing valid cookie across flows, and never mint on ambiguity.
func (c *BrowserDeviceCodec) Issue(ctx context.Context, now time.Time, tenant identity.TenantID, origin string) (BrowserDevice, error) {
	if !c.admit(ctx, now, tenant, origin) {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	now = now.UTC().Truncate(time.Second)
	expires := now.Add(c.lifetime)
	if !validTime(expires) {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	var wire [85]byte
	wire[0] = 1
	binary.BigEndian.PutUint32(wire[1:5], c.active)
	binary.BigEndian.PutUint64(wire[5:13], uint64(now.Unix()))
	binary.BigEndian.PutUint64(wire[13:21], uint64(expires.Unix()))
	rand.Read(wire[21:53])
	if ctx.Err() != nil {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	sum := c.mac(c.keys[c.active], tenant, origin, wire[:53])
	copy(wire[53:], sum)
	cookie := c.cookie.base()
	cookie.Value = base64.RawURLEncoding.EncodeToString(wire[:])
	cookie.Expires, cookie.MaxAge = expires, int(expires.Sub(now)/time.Second)
	return BrowserDevice{state: &browserDeviceState{id: c.signal(tenant, origin, wire[21:53]), expires: expires, cookie: cookie.String()}}, nil
}

// Resolve verifies exactly one canonical 114-byte unpadded base64url value.
// The transport must first reject duplicate/alternative cookie channels and
// validate HTTPS host/origin. Missing, malformed, unknown-key, cross-scope,
// future-issued, expired or policy-incompatible cookies uniformly deny. It
// never issues credentials, extends expiry, touches a store or authenticates.
func (c *BrowserDeviceCodec) Resolve(ctx context.Context, now time.Time, tenant identity.TenantID, origin, token string) (BrowserDevice, error) {
	if !c.admit(ctx, now, tenant, origin) || len(token) != 114 {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	wire, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(wire) != 85 || wire[0] != 1 {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	k := c.keys[binary.BigEndian.Uint32(wire[1:5])]
	if k.key.state == nil || !hmac.Equal(wire[53:], c.mac(k, tenant, origin, wire[:53])) {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	i, e := binary.BigEndian.Uint64(wire[5:13]), binary.BigEndian.Uint64(wire[13:21])
	// Check unsigned timestamps before conversion/subtraction; durable time is
	// bounded to the same supported calendar as sessions.
	if i == 0 || e > 253402300799 || e <= i || e-i > uint64(c.lifetime/time.Second) {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	issued, expires := time.Unix(int64(i), 0).UTC(), time.Unix(int64(e), 0).UTC()
	if now.Before(issued) || !now.Before(expires) || ctx.Err() != nil {
		return BrowserDevice{}, ErrBrowserDeviceDenied
	}
	return BrowserDevice{state: &browserDeviceState{id: c.signal(tenant, origin, wire[21:53]), expires: expires}}, nil
}

func (c *BrowserDeviceCodec) admit(ctx context.Context, now time.Time, tenant identity.TenantID, origin string) bool {
	return c != nil && c.active != 0 && ctx != nil && ctx.Err() == nil && validTime(now) && now.Unix() > 0 &&
		authorityKey(string(tenant), 128) && strings.HasPrefix(origin, "https://") && preAuthURL(origin, true)
}

func (c *BrowserDeviceCodec) frame(tenant identity.TenantID, origin string, payload []byte) []byte {
	var out []byte
	for _, s := range []string{c.namespace, string(tenant), origin} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
		out = append(out, s...)
	}
	return append(out, payload...)
}

func (c *BrowserDeviceCodec) mac(k BrowserDeviceKey, tenant identity.TenantID, origin string, payload []byte) []byte {
	h := hmac.New(sha256.New, k.key.state.material[:k.key.state.size])
	h.Write([]byte("golib.browser-device.cookie.v1\x00"))
	h.Write(c.frame(tenant, origin, payload))
	return h.Sum(nil)
}

func (c *BrowserDeviceCodec) signal(tenant identity.TenantID, origin string, nonce []byte) string {
	h := sha256.New()
	h.Write([]byte("golib.browser-device.signal.v1\x00"))
	h.Write(c.frame(tenant, origin, nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// DeviceID exposes the scoped non-authoritative abuse correlation, never a
// credential. It must not become an authentication, user or MFA device ID.
func (d BrowserDevice) DeviceID() string {
	if d.state == nil {
		return ""
	}
	return d.state.id
}

// ExpiresAt returns the original cookie expiry; it cannot be refreshed by Resolve.
func (d BrowserDevice) ExpiresAt() time.Time {
	if d.state == nil {
		return time.Time{}
	}
	return d.state.expires
}

// CookieHeader exposes sensitive Set-Cookie only for the original Issue result.
// It is reusable delivery metadata, not a one-time or authentication credential.
func (d BrowserDevice) CookieHeader() string {
	if d.state == nil {
		return ""
	}
	return d.state.cookie
}

// Format redacts key material.
func (BrowserDeviceKey) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// LogValue redacts key material.
func (BrowserDeviceKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON denies implicit key export.
func (BrowserDeviceKey) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit key export.
func (BrowserDeviceKey) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts configuration and keys.
func (BrowserDeviceConfig) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// LogValue redacts configuration and keys.
func (BrowserDeviceConfig) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON denies implicit configuration export.
func (BrowserDeviceConfig) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit configuration export.
func (BrowserDeviceConfig) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts retained keys.
func (*BrowserDeviceCodec) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// LogValue redacts retained keys.
func (*BrowserDeviceCodec) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON denies implicit owner export.
func (*BrowserDeviceCodec) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit owner export.
func (*BrowserDeviceCodec) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// Format redacts token and stable device correlation.
func (BrowserDevice) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// LogValue redacts token and stable device correlation.
func (BrowserDevice) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON denies implicit correlation export.
func (BrowserDevice) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies implicit correlation export.
func (BrowserDevice) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
