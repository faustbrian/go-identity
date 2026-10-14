package identityhttp_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func config() identityhttp.ServerConfig {
	return identityhttp.ServerConfig{Address: "127.0.0.1:0", ReadHeaderTimeout: time.Second,
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
		HandlerTimeout: time.Second, ShutdownDrain: time.Second, MaximumHeaderBytes: 4096}
}

func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle did not terminate")
		return nil
	}
}

// L01: constructor is bounded, explicit and acquires no listener.
func TestConstructor(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, field := range []string{"header", "read", "write", "idle", "handler", "drain"} {
		for _, d := range []time.Duration{-1, 0, 24*time.Hour + 1} {
			c := config()
			switch field {
			case "header":
				c.ReadHeaderTimeout = d
			case "read":
				c.ReadTimeout = d
			case "write":
				c.WriteTimeout = d
			case "idle":
				c.IdleTimeout = d
			case "handler":
				c.HandlerTimeout = d
			case "drain":
				c.ShutdownDrain = d
			}
			if _, err := identityhttp.NewHTTPServer(c, h); !errors.Is(err, identityhttp.ErrInvalidInput) {
				t.Fatalf("%s %s: %v", field, d, err)
			}
		}
	}
	for _, d := range []time.Duration{1, 24 * time.Hour} {
		c := config()
		c.ReadHeaderTimeout = d
		c.ReadTimeout = d
		c.WriteTimeout = d
		c.IdleTimeout = d
		c.HandlerTimeout = d
		c.ShutdownDrain = d
		if _, err := identityhttp.NewHTTPServer(c, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*identityhttp.ServerConfig){
		func(c *identityhttp.ServerConfig) { c.Address = "" }, func(c *identityhttp.ServerConfig) { c.Address = strings.Repeat("x", 513) },
		func(c *identityhttp.ServerConfig) { c.Address = "not-an-address" }, func(c *identityhttp.ServerConfig) { c.MaximumHeaderBytes = 0 },
		func(c *identityhttp.ServerConfig) { c.MaximumHeaderBytes = 65537 }, func(c *identityhttp.ServerConfig) { c.HandlerTimeout = 2 * time.Second },
	} {
		c := config()
		change(&c)
		if _, err := identityhttp.NewHTTPServer(c, h); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	for _, handler := range []http.Handler{nil, http.HandlerFunc(nil)} {
		if _, err := identityhttp.NewHTTPServer(config(), handler); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := config()
	c.Address = ln.Addr().String()
	if _, err = identityhttp.NewHTTPServer(c, h); err != nil {
		t.Fatal("constructor bound listener", err)
	}
}

// L02/L03/L07: real serving, immutable config, single start and terminal shutdown.
func TestNetworkLifecycle(t *testing.T) {
	c := config()
	s, err := identityhttp.NewHTTPServer(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "alive") }))
	if err != nil {
		t.Fatal(err)
	}
	c.Address = "invalid"
	c.HandlerTimeout = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(func() { s.Shutdown(context.Background()); wait(t, done) })
	select {
	case <-s.Started():
	case <-time.After(3 * time.Second):
		t.Fatal("not started")
	}
	if s.State() != identityhttp.ServerRunning {
		t.Fatal(s.State())
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://" + s.Address() + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != "alive" {
		t.Fatalf("response %q %v", b, err)
	}
	if err = s.Start(ctx); !errors.Is(err, identityhttp.ErrLifecycle) {
		t.Fatal(err)
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.State() != identityhttp.ServerStopped {
		t.Fatal(s.State())
	}
	if _, err = client.Get("http://" + s.Address() + "/"); err == nil {
		t.Fatal("accepted after shutdown")
	}
	ln, err := net.Listen("tcp", s.Address())
	if err != nil {
		t.Fatal("listener retained", err)
	}
	ln.Close()
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx); !errors.Is(err, identityhttp.ErrLifecycle) {
		t.Fatal(err)
	}
}

// L04: graceful shutdown admits no new requests and does not cancel active work.
func TestGracefulDrain(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			io.WriteString(w, "complete")
		case <-r.Context().Done():
			t.Error("graceful drain cancelled handler")
		}
	}))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), ln) }()
	response := make(chan error, 1)
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	go func() {
		resp, err := client.Get("http://" + ln.Addr().String())
		if err == nil {
			b, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil {
				err = e
			} else if string(b) != "complete" {
				err = errors.New("incomplete response")
			}
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler absent")
	}
	shutdown := make(chan error, 1)
	go func() { shutdown <- s.Shutdown(context.Background()) }()
	for s.State() != identityhttp.ServerDraining {
		select {
		case <-shutdown:
			t.Fatal("drain completed before handler")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := client.Get("http://" + ln.Addr().String()); err == nil {
		t.Error("new request admitted")
	}
	close(release)
	if err := wait(t, response); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, shutdown); err != nil {
		t.Fatal(err)
	}
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

// L05: caller's earlier drain deadline is retained; force close cancels work.
func TestBoundedDrain(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(exited) }))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), ln) }()
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	response := make(chan error, 1)
	go func() {
		resp, err := client.Get("http://" + ln.Addr().String())
		if resp != nil {
			resp.Body.Close()
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler absent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("handler not cancelled")
	}
	wait(t, response)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

// L03/L07: invalid/cancelled calls never acquire ownership; shutdown is one-shot.
func TestInvalidLifecycle(t *testing.T) {
	var zero identityhttp.HTTPServer
	if err := zero.Start(context.Background()); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	if err := zero.Shutdown(context.Background()); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := s.Start(nil); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.Shutdown(nil); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); !errors.Is(err, identityhttp.ErrLifecycle) {
		t.Fatal(err)
	}
}

// L03/L08: failed listener acquisition and serving are terminal, sanitized,
// and release ownership rather than leaving an unobservable background failure.
func TestStartupFailureAndOwnership(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := config()
	c.Address = ln.Addr().String()
	s, _ := identityhttp.NewHTTPServer(c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err = s.Start(context.Background()); err != identityhttp.ErrUnavailable {
		t.Fatal(err)
	}
	if s.State() != identityhttp.ServerStopped {
		t.Fatal(s.State())
	}
	if err = s.Start(context.Background()); !errors.Is(err, identityhttp.ErrLifecycle) {
		t.Fatal(err)
	}
	s, _ = identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err = s.Serve(nil, ln); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	if err = ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("rejected listener was closed", err)
	}
	if err = s.Serve(context.Background(), nil); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal(err)
	}
	f := &failedListener{address: ln.Addr(), closed: make(chan struct{})}
	if err = s.Serve(context.Background(), f); err != identityhttp.ErrUnavailable {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("failed listener not closed")
	}
}

type failedListener struct {
	address net.Addr
	closed  chan struct{}
	once    sync.Once
}

func (l *failedListener) Accept() (net.Conn, error) {
	return nil, errors.New("private listener diagnostic")
}
func (l *failedListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *failedListener) Addr() net.Addr { return l.address }

func serve(t *testing.T, c identityhttp.ServerConfig, h http.Handler) (*identityhttp.HTTPServer, chan error) {
	t.Helper()
	s, err := identityhttp.NewHTTPServer(c, h)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Start(context.Background()) }()
	t.Cleanup(func() { s.Shutdown(context.Background()); wait(t, done) })
	select {
	case <-s.Started():
	case <-time.After(time.Second):
		t.Fatal("start timeout")
	}
	return s, done
}

// L06: an incomplete header cannot hold a connection to the read timeout.
func TestHeaderDeadline(t *testing.T) {
	c := config()
	c.ReadHeaderTimeout = 30 * time.Millisecond
	s, _ := serve(t, c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("incomplete headers reached handler") }))
	conn, err := net.DialTimeout("tcp", s.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n")
	var b [1]byte
	if _, err = conn.Read(b[:]); err == nil {
		t.Fatal("incomplete header accepted")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("header timeout was not enforced")
	}
}

// L06: reading a stalled body is bounded independently from handler execution.
func TestBodyReadDeadline(t *testing.T) {
	c := config()
	c.ReadTimeout = 30 * time.Millisecond
	read := make(chan error, 1)
	s, _ := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, err := io.Copy(io.Discard, r.Body); read <- err }))
	conn, err := net.DialTimeout("tcp", s.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10\r\n\r\nx")
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("stalled body read succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("body read not bounded")
	}
}

// L06: idle keep-alive ownership expires without requiring another request.
func TestIdleDeadline(t *testing.T) {
	c := config()
	c.IdleTimeout = 30 * time.Millisecond
	s, _ := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
	}))
	conn, err := net.DialTimeout("tcp", s.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("unexpected idle bytes")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle connection retained")
	}
}

// L06: the handler context ends before the broader socket write timeout, and
// delayed writes cannot expose data after cancellation. Hijack is unavailable.
func TestHandlerDeadlineAndOwnership(t *testing.T) {
	c := config()
	c.HandlerTimeout = 30 * time.Millisecond
	result := make(chan error, 1)
	s, _ := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Hijacker); ok {
			t.Error("unowned hijack available")
		}
		<-r.Context().Done()
		_, err := w.Write([]byte("must not be emitted"))
		result <- err
	}))
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	resp, _ := client.Get("http://" + s.Address())
	if resp != nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(b) > 0 {
			t.Fatal("late response emitted")
		}
	}
	if err := wait(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// L07/L08: synchronized competing starts and shuts own exactly one listener;
// repeated cycles join the serving goroutine and free the port.
func TestConcurrentLifecycle(t *testing.T) {
	for cycle := 0; cycle < 20; cycle++ {
		s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		start := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() { <-start; results <- s.Start(context.Background()) }()
		}
		close(start)
		select {
		case <-s.Started():
		case <-time.After(time.Second):
			t.Fatal("not started")
		}
		shuts := make(chan error, 4)
		for i := 0; i < 4; i++ {
			go func() { shuts <- s.Shutdown(context.Background()) }()
		}
		for i := 0; i < 4; i++ {
			if err := wait(t, shuts); err != nil {
				t.Fatal(err)
			}
		}
		a, b := wait(t, results), wait(t, results)
		if !((a == nil && errors.Is(b, identityhttp.ErrLifecycle)) || (b == nil && errors.Is(a, identityhttp.ErrLifecycle))) {
			t.Fatalf("start results %v %v", a, b)
		}
		ln, err := net.Listen("tcp", s.Address())
		if err != nil {
			t.Fatal(err)
		}
		ln.Close()
	}
}

// L05/L07: cancellation of the owning serve context closes ingress and
// cancels request work; it does not turn into a successful ordinary stop.
func TestStartCancellation(t *testing.T) {
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	select {
	case <-s.Started():
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	cancel()
	if err := wait(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.State() != identityhttp.ServerStopped {
		t.Fatal(s.State())
	}
}

// L06: the complete handler deadline also interrupts a blocked request-body
// read; a broader server ReadTimeout must not keep domain work alive.
func TestHandlerDeadlineInterruptsBody(t *testing.T) {
	c := config()
	c.HandlerTimeout = 30 * time.Millisecond
	read := make(chan error, 1)
	s, _ := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, err := io.Copy(io.Discard, r.Body); read <- err }))
	conn, err := net.DialTimeout("tcp", s.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 10\r\n\r\nx")
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("incomplete body succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("handler deadline did not interrupt body read")
	}
}

// L06: a client that does not read cannot retain streaming ownership.
func TestStreamingWriteDeadline(t *testing.T) {
	c := config()
	c.WriteTimeout = 40 * time.Millisecond
	c.HandlerTimeout = 40 * time.Millisecond
	written := make(chan error, 1)
	s, _ := serve(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		block := make([]byte, 128*1024)
		for i := 0; i < 256; i++ {
			if _, err := w.Write(block); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}))
	conn, err := net.DialTimeout("tcp", s.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(1024)
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("unbounded streaming succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("streaming not bounded")
	}
}

// L05/L06: the server never renews an earlier owning context deadline when
// deriving request work; the handler observes the original absolute instant.
func TestEarlierInboundDeadline(t *testing.T) {
	deadline := time.Now().Add(500 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	observed := make(chan time.Time, 1)
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := r.Context().Deadline()
		observed <- d
		w.WriteHeader(204)
	}))
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(func() { s.Shutdown(context.Background()); wait(t, done) })
	select {
	case <-s.Started():
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://" + s.Address())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case d := <-observed:
		if !d.Equal(deadline) {
			t.Fatal("inbound deadline changed")
		}
	case <-time.After(time.Second):
		t.Fatal("no context observed")
	}
}

// L03/L07: hold the native DNS boundary before any listener exists and shut
// down the owner. This is ordinary shutdown, not a bind outage. This test is
// deliberately non-parallel because net.Listen consumes the default resolver.
func TestShutdownDuringListenerAcquisition(t *testing.T) {
	previous := net.DefaultResolver
	entered := make(chan struct{})
	var once sync.Once
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	defer func() { net.DefaultResolver = previous }()
	c := config()
	c.Address = "identity-lifecycle-test.invalid:0"
	s, err := identityhttp.NewHTTPServer(c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("DNS not entered")
	}
	if s.State() != identityhttp.ServerStarting {
		t.Fatal(s.State())
	}
	if err = s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = wait(t, done); err != nil {
		t.Fatal("ordinary shutdown became bind failure", err)
	}
	if s.Address() != "" || s.State() != identityhttp.ServerStopped {
		t.Fatal("startup acquired unexpected ownership")
	}
}

// L08: even a listener that releases Accept correctly may return a private
// diagnostic. The public first/replayed stop outcome must not disclose it.
func TestShutdownSanitizesListenerCloseFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &diagnosticListener{Listener: ln, accepting: make(chan struct{})}
	s, _ := identityhttp.NewHTTPServer(config(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), l) }()
	select {
	case <-l.accepting:
	case <-time.After(time.Second):
		t.Fatal("listener not accepted")
	}
	first := s.Shutdown(context.Background())
	if err := wait(t, done); err != nil {
		t.Fatal("serving cleanup failed", err)
	}
	second := s.Shutdown(context.Background())
	if first != identityhttp.ErrUnavailable || second != identityhttp.ErrUnavailable {
		t.Fatal("private close error was not sanitized")
	}
	if s.State() != identityhttp.ServerStopped {
		t.Fatal(s.State())
	}
	rebound, err := net.Listen("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal("listener retained", err)
	}
	rebound.Close()
}

type diagnosticListener struct {
	net.Listener
	accepting chan struct{}
	once      sync.Once
}

func (l *diagnosticListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.accepting) })
	return l.Listener.Accept()
}
func (l *diagnosticListener) Close() error {
	l.Listener.Close()
	return errors.New("private listener diagnostic")
}
