// Package apikeyvalkey stores encrypted positive modern USER metadata only.
// Every admitted verification still invokes its real AtomicVerifier once.
package apikeyvalkey

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

var (
	// ErrInvalidInput rejects malformed/unselected composition before source IO.
	ErrInvalidInput = errors.New("apikey/valkey: invalid input")
	// ErrUnavailable redacts transport/closure/admission failures. Native source
	// errors and quota/commit uncertainty retain their original classification.
	ErrUnavailable = errors.New("apikey/valkey: unavailable")
)

// Secret copies opaque deployment credentials, never an API-key bearer/digest.
// Copies share immutable custody. Zero is invalid; formatting is redacted and
// serialization forbidden. Retain only for the configured cache's lifetime.
type Secret struct{ state *secretState }
type secretState struct{ value string }

// NewSecret copies 32..4096 bytes. A NamespaceKey must additionally be exactly
// 32 random bytes independent of API-key pepper, wrapping and transport keys.
func NewSecret(value []byte) (Secret, error) {
	if len(value) < 32 || len(value) > 4096 {
		return Secret{}, ErrInvalidInput
	}
	return Secret{state: &secretState{value: string(value)}}, nil
}
func (Secret) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "apikey/valkey.Secret(redacted)") }
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }
func (Secret) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// Config selects only positive-projection/standalone with verified TLS 1.3.
// Endpoint is rediss://host:port without credentials/path/query/fragment.
// Username is 1..128 printable ASCII; TrustPEM is explicit, bounded CA trust.
// MaximumDuration (1ms..5s) bounds the whole admitted call, including native
// work. CacheTimeout (1ms..1s) is smaller, leaving primary fallback time.
// MaximumConcurrent is 1..128; MaximumPayloadBytes is 1024..262144 and must
// equal the root codec's bound. Namespace/deployment come only from that codec
// config, preventing divergent transport and ciphertext scope selection.
type Config struct {
	Profile, Topology, Endpoint, Username  string
	Password, NamespaceKey                 Secret
	TrustPEM                               []byte
	MaximumDuration, CacheTimeout          time.Duration
	MaximumConcurrent, MaximumPayloadBytes int
}

func (Config) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "apikey/valkey.Config(redacted)") }
func (Config) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

func (c Config) validate() (string, string, *x509.CertPool, error) {
	if c.Profile != "positive-projection" || c.Topology != "standalone" || !printable(c.Username, 128) {
		return "", "", nil, ErrInvalidInput
	}
	if c.Password.state == nil || c.NamespaceKey.state == nil || len(c.Password.state.value) < 32 || len(c.Password.state.value) > 4096 || len(c.NamespaceKey.state.value) != 32 {
		return "", "", nil, ErrInvalidInput
	}
	durationsValid := c.MaximumDuration >= time.Millisecond && c.MaximumDuration <= 5*time.Second && c.CacheTimeout >= time.Millisecond && c.CacheTimeout <= time.Second && c.CacheTimeout < c.MaximumDuration
	limitsValid := c.MaximumConcurrent >= 1 && c.MaximumConcurrent <= 128 && c.MaximumPayloadBytes >= 1024 && c.MaximumPayloadBytes <= 262144
	if !durationsValid || !limitsValid || len(c.TrustPEM) == 0 || len(c.TrustPEM) > 65536 {
		return "", "", nil, ErrInvalidInput
	}
	address, name, err := parseEndpoint(c.Endpoint)
	if err != nil {
		return "", "", nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.TrustPEM) {
		return "", "", nil, ErrInvalidInput
	}
	return address, name, roots, nil
}

// Validate performs only bounded structural checks, without network, sources,
// entropy or clock calls. It does not establish server health/authentication.
func (c Config) Validate() error { _, _, _, err := c.validate(); return err }

func parseEndpoint(value string) (string, string, error) {
	if len(value) == 0 || len(value) > 2048 || strings.Contains(value, "#") {
		return "", "", ErrInvalidInput
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "rediss" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" {
		return "", "", ErrInvalidInput
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != net.JoinHostPort(u.Hostname(), u.Port()) {
		return "", "", ErrInvalidInput
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil || host != u.Hostname() || portText != u.Port() {
		return "", "", ErrInvalidInput
	}
	return u.Host, u.Hostname(), nil
}
func printable(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

// Cache borrows real source owners/crypto/clock and owns only bounded transport
// clients/admission. It has no background fill, subscriber, quota allowance or
// invalidation authority. Every call starts with current native verification;
// epoch-bound addressing logically invalidates old values even if events are
// lost. All values expire at their original <=20s deadline. Share its pointer;
// do not copy a Cache after construction or first use.
type Cache struct{ state *cacheState }
type cacheState struct {
	config     Config
	projection apikey.PositiveProjectionConfig
	codec      *apikey.PositiveProjectionCodec
	address    string
	tls        *tls.Config
	sem        chan struct{}
	mu         sync.Mutex
	closed     bool
	lifetime   context.Context
	stop       context.CancelFunc
	wg         sync.WaitGroup
}

// New validates actual source composition and probes a real standalone primary
// over explicit verified TLS. It never creates a source-free degraded cache or
// enables legacy/organization projection. Dependencies remain borrowed; Close
// owns only this adapter's operations/connections, not sources/crypto/clock.
func New(ctx context.Context, c Config, projection apikey.PositiveProjectionConfig) (*Cache, error) {
	if ctx == nil {
		return nil, ErrInvalidInput
	}
	codec, err := apikey.NewPositiveProjectionCodec(projection)
	if err != nil {
		return nil, ErrInvalidInput
	}
	address, name, roots, err := c.validate()
	if err != nil {
		return nil, err
	}
	if projection.MaximumBytes != c.MaximumPayloadBytes || projection.MaximumDuration != c.MaximumDuration {
		return nil, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	c.TrustPEM = nil
	lifetime, stop := context.WithCancel(context.Background())
	cache := &Cache{state: &cacheState{config: c, projection: projection, codec: codec, address: address, tls: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: name, RootCAs: roots}, sem: make(chan struct{}, c.MaximumConcurrent), lifetime: lifetime, stop: stop}}
	if cache.now().IsZero() {
		cache.Close()
		return nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, c.MaximumDuration)
	defer cancel()
	if err := cache.probe(bounded); err != nil {
		cache.Close()
		return nil, err
	}
	return cache, nil
}

func (Cache) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "apikey/valkey.Cache(redacted)") }
func (Cache) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// Close is idempotent, rejects new calls, cancels owned operations and waits for
// clients to close. An in-flight source may still report its known original
// outcome; it must not be relabeled noncommit merely because transport closed.
func (c *Cache) Close() {
	if c == nil || c.state == nil {
		return
	}
	s := c.state
	s.mu.Lock()
	s.closed = true
	if s.stop != nil {
		s.stop()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	s.config.Password = Secret{}
	s.config.NamespaceKey = Secret{}
	s.codec = nil
	s.projection = apikey.PositiveProjectionConfig{}
	s.mu.Unlock()
}

func (c *Cache) begin(ctx context.Context) (context.Context, func(), error) {
	if c == nil || c.state == nil || ctx == nil {
		return nil, nil, ErrInvalidInput
	}
	s := c.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	if s.codec == nil || s.lifetime == nil || s.stop == nil {
		s.mu.Unlock()
		return nil, nil, ErrInvalidInput
	}
	s.wg.Add(1)
	s.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	stop := context.AfterFunc(s.lifetime, cancel)
	select {
	case s.sem <- struct{}{}:
		return bounded, func() { <-s.sem; stop(); cancel(); s.wg.Done() }, nil
	case <-bounded.Done():
		stop()
		cancel()
		s.wg.Done()
		return nil, nil, ErrUnavailable
	}
}

func (c *Cache) now() (now time.Time) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
		}
	}()
	now = c.state.projection.Clock.Now()
	if now.Year() < 1 || now.Year() > 9999 {
		return time.Time{}
	}
	return now
}
