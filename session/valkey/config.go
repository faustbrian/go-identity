package sessionvalkey

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

	"github.com/faustbrian/go-identity/session"
	valkey "github.com/valkey-io/valkey-go"
)

var (
	// ErrInvalidInput rejects unsupported profiles and malformed bounded input.
	ErrInvalidInput = errors.New("session/valkey: invalid input")
	// ErrUnavailable redacts transport failures, closed caches and uncertain writes.
	// An invalidation failure does not prove rollback. Retry only to discard more
	// cached evidence; primary authority and the original deadline remain binding.
	ErrUnavailable = errors.New("session/valkey: unavailable")
)

// Secret holds deployment-owned key/password bytes without printable contents.
// Copies share immutable custody. Zero is invalid; serialization is forbidden.
type Secret struct{ state *secretState }
type secretState struct{ value string }

// NewSecret copies 32..4096 bytes of deployment credentials. NamespaceKey must
// additionally contain exactly 32 bytes, independent of lookup/encryption keys.
func NewSecret(value []byte) (Secret, error) {
	if len(value) < 32 || len(value) > 4096 {
		return Secret{}, ErrInvalidInput
	}
	return Secret{&secretState{string(value)}}, nil
}

// Format always redacts deployment credentials.
func (Secret) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }

// MarshalJSON prevents accidental credential serialization.
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrInvalidInput }

// MarshalText prevents accidental credential serialization.
func (Secret) MarshalText() ([]byte, error) { return nil, ErrInvalidInput }

// Config selects only standalone TLS positive caching, never session authority.
// Endpoint is rediss://host:port without credentials, paths, query or fragment.
// TrustPEM is an explicit private/public CA bundle, copied at construction;
// hostname verification and TLS 1.3 cannot be disabled. Username is 1..128 ASCII
// bytes. Password and NamespaceKey are independent deployment credentials.
// Namespace (1..128 ASCII bytes) and positive DeploymentEpoch isolate deployments.
// LookupKeys must equal the codec service's retained 1..4 distinct lookup keys.
// MaximumDuration (1ms..5s) bounds the whole operation; CacheTimeout (1ms..1s)
// bounds each cache operation and must be smaller, leaving primary fallback time.
// MaximumConcurrent is 1..128; MaximumScopes is 1..4096 metadata generations per
// tenant. Exhaustion rotates the cache epoch and safely discards all positives.
// MaximumPayloadBytes is 256..32768 and must cover the codec envelope bound.
type Config struct {
	Profile, Topology, Endpoint, Username, Namespace      string
	Password, NamespaceKey                                Secret
	TrustPEM                                              []byte
	DeploymentEpoch                                       uint64
	LookupKeys                                            []session.DigestKey
	MaximumDuration, CacheTimeout                         time.Duration
	MaximumConcurrent, MaximumScopes, MaximumPayloadBytes int
}

// Cache borrows the original codec/clock and owns no session store or authority.
// Concurrent calls are safe with concurrent-safe borrowed dependencies. Each
// bounded operation owns and closes its TLS client; there is no background fill,
// subscriber, invalidation journal or autonomous retry. This favors explicit
// lifetime over pooled-handshake performance, for which no claim is made.
// Do not copy a Cache after construction or first use; share its pointer.
type Cache struct {
	config   Config
	codec    *session.EncryptedCacheCodec
	clock    session.IssuerClock
	tls      *tls.Config
	address  string
	sem      chan struct{}
	mu       sync.Mutex
	closed   bool
	lifetime context.Context
	stop     context.CancelFunc
	wg       sync.WaitGroup
}

// New freezes trusted configuration and probes a real standalone primary over
// verified TLS. Replica/cluster/sentinel and cache-only profiles fail. A failed
// probe returns no cache, never an alternative authentication implementation.
func New(ctx context.Context, config Config, codec *session.EncryptedCacheCodec, clock session.IssuerClock) (*Cache, error) {
	if ctx == nil || codec == nil || clock == nil || !validConfig(config) {
		return nil, ErrInvalidInput
	}
	address, serverName, err := parseEndpoint(config.Endpoint)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.TrustPEM) {
		return nil, ErrInvalidInput
	}
	config.TrustPEM = nil
	config.LookupKeys = append([]session.DigestKey(nil), config.LookupKeys...)
	lifetime, cancel := context.WithCancel(context.Background())
	c := &Cache{config: config, codec: codec, clock: clock, tls: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}, address: address, sem: make(chan struct{}, config.MaximumConcurrent), lifetime: lifetime, stop: cancel}
	if c.now().IsZero() {
		c.Close()
		return nil, ErrInvalidInput
	}
	if _, err := c.run(ctx, "probe", "", nil, nil); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func validConfig(config Config) bool {
	if config.Profile != "positive-cache" || config.Topology != "standalone" || !ascii(config.Username, 128) || !ascii(config.Namespace, 128) || config.DeploymentEpoch == 0 {
		return false
	}
	if config.Password.state == nil || config.NamespaceKey.state == nil || len(config.Password.state.value) < 32 || len(config.NamespaceKey.state.value) != 32 {
		return false
	}
	if len(config.TrustPEM) == 0 || len(config.TrustPEM) > 65536 || config.MaximumPayloadBytes < 256 || config.MaximumPayloadBytes > 32768 {
		return false
	}
	if config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second || config.CacheTimeout < time.Millisecond || config.CacheTimeout > time.Second || config.CacheTimeout >= config.MaximumDuration {
		return false
	}
	if config.MaximumConcurrent < 1 || config.MaximumConcurrent > 128 || config.MaximumScopes < 1 || config.MaximumScopes > 4096 || len(config.LookupKeys) < 1 || len(config.LookupKeys) > 4 {
		return false
	}
	seen := make(map[uint32]bool)
	validationToken, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for _, key := range config.LookupKeys {
		// Digest validates opaque key custody without reading secret material.
		digest, err := validationToken.Digest(key, "configuration-validation")
		if err != nil || seen[digest.KeyVersion] {
			return false
		}
		seen[digest.KeyVersion] = true
	}
	return true
}

func parseEndpoint(endpoint string) (address, serverName string, err error) {
	if len(endpoint) == 0 || len(endpoint) > 2048 || strings.Contains(endpoint, "#") {
		return "", "", ErrInvalidInput
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "rediss" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" {
		return "", "", ErrInvalidInput
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Host != net.JoinHostPort(u.Hostname(), u.Port()) {
		return "", "", ErrInvalidInput
	}
	return u.Host, u.Hostname(), nil
}

// Format redacts transport and cached credential metadata.
func (*Cache) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[REDACTED]") }

// Close is idempotent: cancel owned operations, reject new work and wait for
// their clients to close. It does not close the borrowed codec, clock or primary.
func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	if c.stop != nil {
		c.stop()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

func ascii(value string, limit int) bool {
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

func (c *Cache) begin(ctx context.Context) (context.Context, func(), error) {
	if c == nil || ctx == nil || c.codec == nil || c.clock == nil || c.lifetime == nil || c.stop == nil {
		return nil, nil, ErrInvalidInput
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	c.wg.Add(1)
	c.mu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, c.config.MaximumDuration)
	stop := context.AfterFunc(c.lifetime, cancel)
	select {
	case c.sem <- struct{}{}:
		return bounded, func() { <-c.sem; stop(); cancel(); c.wg.Done() }, nil
	case <-bounded.Done():
		stop()
		cancel()
		c.wg.Done()
		return nil, nil, ErrUnavailable
	}
}

func (c *Cache) client(ctx context.Context) (valkey.Client, error) {
	sockets := &socketSet{}
	aborted := make(chan struct{})
	stopAbort := context.AfterFunc(ctx, func() { sockets.close(); close(aborted) })
	release := func(client valkey.Client) {
		// The driver's idle-pipe Close starts background PING and clears its
		// deadline (valkey-go v1.0.78 pipe.go). Raw ownership must end first.
		sockets.close()
		if !stopAbort() {
			<-aborted
		}
		if client != nil {
			client.Close()
		}
	}
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{c.address}, Username: c.config.Username, Password: c.config.Password.state.value,
		TLSConfig: c.tls.Clone(), DisableRetry: true, DisableCache: true, ForceSingleClient: true,
		DisableAutoPipelining: true, BlockingPoolSize: 1, PipelineMultiplex: -1,
		ConnWriteTimeout: c.config.CacheTimeout, Dialer: net.Dialer{Timeout: c.config.CacheTimeout},
		DialCtxFn: func(_ context.Context, address string, dialer *net.Dialer, tlsConfig *tls.Config) (net.Conn, error) {
			raw, e := dialer.DialContext(ctx, "tcp", address)
			if e != nil {
				return nil, e
			}
			if !sockets.add(raw) {
				_ = raw.Close()
				return nil, ErrUnavailable
			}
			if deadline, ok := ctx.Deadline(); ok {
				if e = raw.SetDeadline(deadline); e != nil {
					return nil, e
				}
			}
			secured := tls.Client(raw, tlsConfig)
			if e = secured.HandshakeContext(ctx); e != nil {
				return nil, e
			}
			return secured, nil
		},
	})
	if err != nil {
		release(client)
		return nil, unavailable("connect", err)
	}
	return &ownedClient{Client: client, release: func() { release(client) }}, nil
}

// Only static phase/classes survive this boundary, never raw driver/server
// errors (which can contain keys, commands or connection credentials).
func unavailable(phase string, cause error) error {
	class := "other"
	if cause == nil {
		class = "shape"
	} else if errors.Is(cause, context.Canceled) {
		class = "canceled"
	} else if errors.Is(cause, context.DeadlineExceeded) {
		class = "deadline"
	} else if verify := new(tls.CertificateVerificationError); errors.As(cause, &verify) {
		class = "certificate"
	} else if _, ok := valkey.IsValkeyErr(cause); ok {
		class = "server"
	} else {
		var transport net.Error
		if errors.As(cause, &transport) {
			class = "transport"
		}
	}
	return fmt.Errorf("session/valkey %s/%s: %w", phase, class, ErrUnavailable)
}

// Keep user-controlled text out of errors; server diagnostics include key names.
func cleanError(err error) error {
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Clock panics/invalid samples cannot leak dependency diagnostics or turn a
// malformed trusted dependency into an authenticated result.
func (c *Cache) now() (now time.Time) {
	defer func() {
		if recover() != nil {
			now = time.Time{}
		}
	}()
	now = c.clock.Now()
	if now.Year() < 1 || now.Year() > 9999 {
		return time.Time{}
	}
	return now
}
