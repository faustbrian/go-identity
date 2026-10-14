// Package identityhttp owns opt-in identity HTTP transport. The current
// development surface provides server lifecycle and probes, not domain routes or deployment
// composition. Handlers must honor cancellation and own their bounded callbacks.
package identityhttp

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrInvalidInput rejects invalid configuration, nil contexts and zero owners.
var ErrInvalidInput = errors.New("identityhttp: invalid input")

// ErrLifecycle rejects a second start, including after a failed start or stop.
var ErrLifecycle = errors.New("identityhttp: lifecycle conflict")

// ErrUnavailable reports a bind or serving failure without disclosing addresses,
// peer values or underlying transport diagnostics.
var ErrUnavailable = errors.New("identityhttp: unavailable")

// ServerConfig is copied by NewHTTPServer. Address is an explicit TCP host:port
// (port zero permits an ephemeral listener). All durations must be 1ns..24h;
// HandlerTimeout cannot exceed WriteTimeout. MaximumHeaderBytes is 1KiB..64KiB.
// These are reusable bounds, not the stricter reference deployment profile.
// TLS termination belongs to deployment or a TLS listener supplied to Serve.
// No defaults, provider calls or listener acquisition occur during construction.
type ServerConfig struct {
	Address            string
	ReadHeaderTimeout  time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	HandlerTimeout     time.Duration
	ShutdownDrain      time.Duration
	MaximumHeaderBytes uint32
}

// ServerState is a lifecycle snapshot, not dependency or identity readiness.
// Zero is invalid. A server never restarts after a start attempt or shutdown.
type ServerState uint8

const (
	// ServerNew owns no listener and has not begun starting.
	ServerNew ServerState = iota + 1
	// ServerStarting has reserved its only start attempt.
	ServerStarting
	// ServerRunning has acquired its listener and permits handler admission.
	ServerRunning
	// ServerDraining refuses new admission while existing requests finish.
	ServerDraining
	// ServerStopped is terminal, including a bind failure or pre-start shutdown.
	ServerStopped
)

// HTTPServer owns its accepted listener, HTTP connections and cancellation
// watcher. It does not close feature stores, pools or provider owners. Immutable
// config and handler may be shared; mu alone owns mutable lifecycle state.
// Its zero value is invalid. All public methods are safe for concurrent calls.
type HTTPServer struct {
	mu           sync.Mutex
	config       ServerConfig
	server       *http.Server
	state        ServerState
	address      string
	cancel       context.CancelFunc
	started      chan struct{}
	shutdownDone chan struct{}
	shutdownOnce sync.Once
	shutdownErr  error
}

// NewHTTPServer validates and copies config without IO. A nil interface or nil
// http.HandlerFunc is rejected. Other implementations must be usable non-nil
// handlers; their internal validity is the caller's contract. The server does
// not reflect into arbitrary handler values. Handlers must not hijack connections
// or start detached work; the response writer deliberately exposes no Hijacker.
func NewHTTPServer(config ServerConfig, handler http.Handler) (*HTTPServer, error) {
	if handler == nil {
		return nil, ErrInvalidInput
	}
	if f, ok := handler.(http.HandlerFunc); ok && f == nil {
		return nil, ErrInvalidInput
	}
	if len(config.Address) == 0 || len(config.Address) > 512 || strings.ContainsAny(config.Address, "\r\n\t /\\") {
		return nil, ErrInvalidInput
	}
	_, port, err := net.SplitHostPort(config.Address)
	if err != nil || port == "" {
		return nil, ErrInvalidInput
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(n, 10) != port {
		return nil, ErrInvalidInput
	}
	for _, d := range []time.Duration{config.ReadHeaderTimeout, config.ReadTimeout, config.WriteTimeout, config.IdleTimeout, config.HandlerTimeout, config.ShutdownDrain} {
		if d <= 0 || d > 24*time.Hour {
			return nil, ErrInvalidInput
		}
	}
	if config.HandlerTimeout > config.WriteTimeout || config.MaximumHeaderBytes < 1024 || config.MaximumHeaderBytes > 65536 {
		return nil, ErrInvalidInput
	}
	s := &HTTPServer{config: config, state: ServerNew, started: make(chan struct{}), shutdownDone: make(chan struct{})}
	s.server = &http.Server{ReadHeaderTimeout: config.ReadHeaderTimeout, ReadTimeout: config.ReadTimeout,
		WriteTimeout: config.WriteTimeout, IdleTimeout: config.IdleTimeout, MaxHeaderBytes: int(config.MaximumHeaderBytes),
		// net/http's panic/error diagnostics may contain request secrets. A later
		// transport observer may expose safe classifications, never raw logs.
		ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			admit := s.state == ServerRunning
			s.mu.Unlock()
			if !admit {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), config.HandlerTimeout)
			defer cancel()
			// Bound response streaming as well as cooperative domain work. An
			// earlier inbound deadline is retained by WithTimeout.
			deadline, _ := ctx.Deadline()
			if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
				return
			}
			// A request context alone does not interrupt a blocked Body.Read.
			// Interrupt only when it expires: setting a future read deadline here
			// could extend net/http's earlier ReadTimeout. Join any fired callback
			// before the writer's ownership ends.
			interrupted := make(chan struct{})
			stop := context.AfterFunc(ctx, func() {
				defer close(interrupted)
				http.NewResponseController(w).SetReadDeadline(time.Now())
			})
			defer func() {
				if !stop() {
					<-interrupted
				}
			}()
			handler.ServeHTTP(&deadlineWriter{ResponseWriter: w, ctx: ctx}, r.WithContext(ctx))
		})}
	return s, nil
}

// State returns an instantaneous lifecycle snapshot; zero owners return zero.
func (s *HTTPServer) State() ServerState {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Address returns the bound local address after listener acquisition, or empty
// before it. It remains available after stop for explicit operator inspection;
// callers must not expose it in public probes or error envelopes.
func (s *HTTPServer) Address() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.address
}

// Started closes once a listener is acquired and admission begins. It never
// closes after a failed/pre-cancelled start or pre-start shutdown; consumers must
// also observe Start/Serve's return. Zero owners return a nil channel.
func (s *HTTPServer) Started() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.started
}

func (s *HTTPServer) begin(ctx context.Context) (context.Context, error) {
	if s == nil || s.server == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != ServerNew {
		return nil, ErrLifecycle
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.state = ServerStarting
	s.server.BaseContext = func(net.Listener) context.Context { return runCtx }
	return runCtx, nil
}

// Start binds the configured address and blocks until serving and owned cleanup
// finish. Bind failure is terminal and sanitized as ErrUnavailable. A cancelled
// context before start leaves the owner reusable; cancellation after reservation
// shuts it down and returns the context error. Ordinary Shutdown returns nil.
func (s *HTTPServer) Start(ctx context.Context) error {
	runCtx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(runCtx, "tcp", s.config.Address)
	if err != nil {
		// Capture before finish cancels runCtx itself. An ordinary concurrent
		// shutdown may interrupt DNS/binding without cancelling the caller.
		interrupted := runCtx.Err() != nil
		s.finish()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if interrupted {
			return nil
		}
		return ErrUnavailable
	}
	return s.serve(ctx, runCtx, ln)
}

// Serve is Start with a deployment-supplied listener (including TLS). Ownership
// transfers only after argument validation and successful start reservation;
// on ErrInvalidInput/ErrLifecycle or an already cancelled context the caller
// retains it. The accepted listener is always closed, including serving failure.
// An implementation must honor Close and return promptly from a closed Accept.
func (s *HTTPServer) Serve(ctx context.Context, ln net.Listener) error {
	if ln == nil {
		return ErrInvalidInput
	}
	runCtx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	return s.serve(ctx, runCtx, ln)
}

func (s *HTTPServer) serve(ctx, runCtx context.Context, ln net.Listener) error {
	defer ln.Close()
	address := ln.Addr().String()
	s.mu.Lock()
	if s.state != ServerStarting || runCtx.Err() != nil {
		s.mu.Unlock()
		s.Shutdown(context.Background())
		s.finish()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	s.address = address
	s.state = ServerRunning
	close(s.started)
	s.mu.Unlock()
	watchStop, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-runCtx.Done():
			s.Shutdown(context.Background())
		case <-watchStop:
		}
	}()
	err := s.server.Serve(ln)
	s.mu.Lock()
	draining := s.state == ServerDraining
	s.mu.Unlock()
	if draining {
		<-s.shutdownDone
	}
	close(watchStop)
	<-watchDone
	s.finish()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return ErrUnavailable
	}
	return nil
}

// Shutdown is terminal even before start. It refuses new admission immediately
// and drains with the earlier of ctx's deadline and ShutdownDrain. Concurrent
// callers wait under their own same bound; repeated calls return the original
// shutdown result. On deadline/cancellation it cancels requests and force-closes
// connections. Cooperative handlers must release owned work on cancellation;
// Go cannot terminate arbitrary caller code that ignores it. Neither cancellation
// nor connection closure proves an authoritative mutation rolled back.
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.ShutdownDrain)
	defer cancel()
	s.mu.Lock()
	switch s.state {
	case ServerNew:
		s.state = ServerStopped
		s.shutdownOnce.Do(func() { close(s.shutdownDone) })
		s.mu.Unlock()
		return nil
	case ServerStopped:
		err := s.shutdownErr
		s.mu.Unlock()
		return err
	case ServerDraining:
		s.mu.Unlock()
		select {
		case <-s.shutdownDone:
			s.mu.Lock()
			err := s.shutdownErr
			s.mu.Unlock()
			return err
		case <-bounded.Done():
			return bounded.Err()
		}
	default:
		s.state = ServerDraining
		s.mu.Unlock()
	}
	err := s.server.Shutdown(bounded)
	if err != nil {
		// Shutdown can return a supplied listener's raw Close diagnostic.
		// Preserve only our authoritative context classification, never a
		// listener-selected error identity or message, even on replay.
		if bounded.Err() != nil {
			if errors.Is(bounded.Err(), context.DeadlineExceeded) {
				err = context.DeadlineExceeded
			} else {
				err = context.Canceled
			}
		} else {
			err = ErrUnavailable
		}
		s.cancel()
		s.server.Close()
	} else {
		s.cancel()
	}
	s.mu.Lock()
	s.shutdownErr = err
	s.state = ServerStopped
	s.shutdownOnce.Do(func() { close(s.shutdownDone) })
	s.mu.Unlock()
	return err
}

func (s *HTTPServer) finish() {
	s.cancel()
	s.server.Close()
	s.mu.Lock()
	s.state = ServerStopped
	s.shutdownOnce.Do(func() { close(s.shutdownDone) })
	s.mu.Unlock()
}

// deadlineWriter deliberately does not expose Hijacker, ReaderFrom or Unwrap,
// which could bypass response ownership or the request deadline.
type deadlineWriter struct {
	http.ResponseWriter
	ctx context.Context
}

func (w *deadlineWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(p)
}
func (w *deadlineWriter) WriteHeader(code int) {
	if w.ctx.Err() == nil {
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *deadlineWriter) FlushError() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
