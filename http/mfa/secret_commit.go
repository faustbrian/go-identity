package mfahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type secretCommitKey struct{}

// One synchronous request owns the borrowed body and its original validity.
// Final-status middleware cannot turn failed delivery into secret disclosure.
type secretCommit struct {
	ctx           context.Context
	body, failure []byte
	fresh         func() bool
	status        int
	written       bool
}

func (s *secretCommit) valid(r *http.Request) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return s != nil && s.fresh != nil && s.ctx != nil && s.ctx.Err() == nil && r.Context().Err() == nil && s.fresh()
}

func writeSecretJSON(w http.ResponseWriter, r *http.Request, body []byte, observation map[string]any, fresh func() bool) {
	s, ok := r.Context().Value(secretCommitKey{}).(*secretCommit)
	if !ok || s == nil || s.fresh != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	observation["error"] = "unavailable"
	failure, err := json.Marshal(observation)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer clear(failure)
	s.body, s.failure, s.fresh = body, failure, fresh
	s.ctx = r.Context()
	defer func() { s.body, s.failure, s.fresh = nil, nil, nil }()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *secretCommit) write(r *http.Request, data []byte, next func([]byte) (int, error)) (int, error) {
	if s.fresh == nil {
		return next(data)
	}
	if s.written {
		return len(data), nil
	}
	s.written = true
	if s.status == http.StatusOK && s.valid(r) && bytes.Equal(data, s.body) {
		return next(data)
	}
	_, err := next(s.failure)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (s *secretCommit) readFrom(r *http.Request, reader io.Reader, write func([]byte) (int, error), next func(io.Reader) (int64, error)) (int64, error) {
	if s.fresh == nil {
		return next(reader)
	}
	// Streaming cannot use the underlying fast path. Borrow only the owner's
	// frozen body plus one overflow witness, then use the same custody guard.
	data, err := io.ReadAll(io.LimitReader(reader, int64(len(s.body))+1))
	defer clear(data)
	if err != nil {
		return 0, err
	}
	n, err := s.write(r, data, write)
	return int64(n), err
}
