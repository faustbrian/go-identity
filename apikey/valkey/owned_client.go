package apikeyvalkey

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	valkey "github.com/valkey-io/valkey-go"
)

// The pinned driver opens HELLO and blocking-pool connections. Permit one
// replacement of each, not an unbounded reconnect/socket population.
const maximumClientSockets = 4

type socketSet struct {
	mu          sync.Mutex
	closed      bool
	connections []net.Conn
}

func (s *socketSet) add(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.connections) >= maximumClientSockets {
		return false
	}
	s.connections = append(s.connections, connection)
	return true
}
func (s *socketSet) close() {
	s.mu.Lock()
	s.closed = true
	connections := s.connections
	s.connections = nil
	s.mu.Unlock()
	// Close raw TCP, not TLS close_notify, and never hold synchronization over IO.
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type ownedClient struct {
	valkey.Client
	once    sync.Once
	release func()
}

func (c *ownedClient) Close() { c.once.Do(c.release) }

func (c *Cache) client(ctx context.Context) (valkey.Client, error) {
	s := c.state
	sockets := &socketSet{}
	aborted := make(chan struct{})
	stopAbort := context.AfterFunc(ctx, func() { sockets.close(); close(aborted) })
	release := func(client valkey.Client) {
		// valkey-go v1.0.78 pipe.Close may clear deadlines/start background PING.
		// End raw socket ownership first so silent peers cannot delay cleanup.
		sockets.close()
		if !stopAbort() {
			<-aborted
		}
		if client != nil {
			client.Close()
		}
	}
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{s.address}, Username: s.config.Username, Password: s.config.Password.state.value,
		TLSConfig: s.tls.Clone(), DisableRetry: true, DisableCache: true, ForceSingleClient: true,
		DisableAutoPipelining: true, BlockingPoolSize: 1, PipelineMultiplex: -1,
		ConnWriteTimeout: s.config.CacheTimeout, Dialer: net.Dialer{Timeout: s.config.CacheTimeout},
		DialCtxFn: func(_ context.Context, address string, dialer *net.Dialer, tlsConfig *tls.Config) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			if !sockets.add(raw) {
				_ = raw.Close()
				return nil, ErrUnavailable
			}
			if deadline, ok := ctx.Deadline(); ok {
				if err := raw.SetDeadline(deadline); err != nil {
					return nil, err
				}
			}
			secured := tls.Client(raw, tlsConfig)
			if err := secured.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return secured, nil
		},
	})
	if err != nil {
		release(client)
		return nil, ErrUnavailable
	}
	return &ownedClient{Client: client, release: func() { release(client) }}, nil
}
