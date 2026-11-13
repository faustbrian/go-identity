package sessionvalkey

import (
	"net"
	"sync"

	valkey "github.com/valkey-io/valkey-go"
)

// The pinned driver opens an initial HELLO connection and a blocking-pool
// connection. Allow one replacement of each, never unbounded reconnects.
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
	// Close underlying TCP, not tls.Conn.Close: close_notify must not wait for
	// a silent peer. Never hold synchronization across network operations.
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
