package oauth

import (
	"io"
	"sync"
)

// net/http's RoundTripper contract permits body access/Close after RoundTrip
// returns (Go1.27 net/http/client.go). Read and terminal Close therefore share
// ownership: cancellation cleanup cannot clear bytes under an asynchronous read.
// The HTTP request has no GetBody, so these single-use bytes cannot be replayed.
type tokenRequestBody struct {
	mu     sync.Mutex
	value  []byte
	offset int
	closed bool
}

// newTokenRequestBody takes ownership of the bounded encoded form, not a copy.
func newTokenRequestBody(value []byte) *tokenRequestBody { return &tokenRequestBody{value: value} }

func (b *tokenRequestBody) Read(destination []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.EOF
	}
	if len(destination) == 0 {
		return 0, nil
	}
	n := copy(destination, b.value[b.offset:])
	b.offset += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *tokenRequestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	clear(b.value)
	b.value = nil
	b.offset = 0
	return nil
}
