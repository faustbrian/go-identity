package valkey

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// This fixture runs verified TLS and native RESP over memory-only net.Pipe.
// It implements just the deliberate server IO boundary, not Valkey counters.
type nativeWireFixture struct {
	mu           sync.Mutex
	requests     [][]string
	dials        int
	failures     []error
	reply        func([]string) string
	startupReply string
	peers        []net.Conn
	workers      sync.WaitGroup
}

func nativeTLSFixture(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "valkey.test"}, DNSNames: []string{"valkey.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{RootCAs: roots, ServerName: "valkey.test", MinVersion: tls.VersionTLS12}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
}

func nativeFixture(t *testing.T, reply func([]string) string) (*nativeTransport, *nativeWireFixture) {
	t.Helper()
	clientTLS, serverTLS := nativeTLSFixture(t)
	credential, err := newNativeCredential("default", []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := newNativeTransport(nativeTransportConfig{endpoint: "rediss://valkey.test:6379", tls: clientTLS, credential: credential, timeout: time.Second, poolSize: 2, topology: "standalone"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &nativeWireFixture{reply: reply, startupReply: "+OK\r\n*6\r\n$7\r\nversion\r\n$5\r\n8.0.0\r\n$5\r\nproto\r\n:2\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n"}
	transport.dial = func(ctx context.Context, address string) (net.Conn, error) {
		if address != "valkey.test:6379" {
			return nil, errors.New("unexpected endpoint")
		}
		client, server := net.Pipe()
		fixture.mu.Lock()
		fixture.dials++
		fixture.peers = append(fixture.peers, server)
		fixture.mu.Unlock()
		fixture.workers.Add(1)
		go func() {
			defer fixture.workers.Done()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			secured := tls.Server(server, serverTLS)
			if err := secured.HandshakeContext(ctx); err != nil {
				return
			}
			reader := bufio.NewReader(secured)
			auth, err := readNativeRequest(reader)
			if err != nil {
				return
			}
			hello, err := readNativeRequest(reader)
			if err != nil {
				return
			}
			if !reflect.DeepEqual(auth, []string{"AUTH", "default", "fixture-password"}) || !reflect.DeepEqual(hello, []string{"HELLO", "2"}) {
				fixture.mu.Lock()
				fixture.failures = append(fixture.failures, errors.New("unexpected handshake"))
				fixture.mu.Unlock()
				return
			}
			if _, err := io.WriteString(secured, fixture.startupReply); err != nil {
				return
			}
			for {
				request, err := readNativeRequest(reader)
				if err != nil {
					return
				}
				if len(request) == 1 && request[0] == "PING" {
					if _, err := io.WriteString(secured, "+PONG\r\n"); err != nil {
						return
					}
					continue
				}
				fixture.mu.Lock()
				fixture.requests = append(fixture.requests, request)
				fixture.mu.Unlock()
				response := fixture.reply(request)
				if response == "" {
					return
				}
				if _, err := io.WriteString(secured, response); err != nil {
					return
				}
			}
		}()
		return client, nil
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := transport.close(ctx); err != nil {
			t.Error("transport shutdown failed", err)
		}
		fixture.mu.Lock()
		for _, peer := range fixture.peers {
			_ = peer.Close()
		}
		fixture.mu.Unlock()
		fixture.workers.Wait()
		if len(fixture.failures) != 0 {
			t.Error("native wire contract mismatch")
		}
	})
	return transport, fixture
}

func readNativeRequest(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil || len(line) > 32 || !strings.HasPrefix(line, "*") || !strings.HasSuffix(line, "\r\n") {
		return nil, io.ErrUnexpectedEOF
	}
	count, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if err != nil || count < 1 || count > 64 {
		return nil, io.ErrUnexpectedEOF
	}
	fields := make([]string, count)
	for i := range fields {
		line, err = r.ReadString('\n')
		if err != nil || len(line) > 32 || !strings.HasPrefix(line, "$") || !strings.HasSuffix(line, "\r\n") {
			return nil, io.ErrUnexpectedEOF
		}
		size, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
		if err != nil || size < 0 || size > 32768 {
			return nil, io.ErrUnexpectedEOF
		}
		data := make([]byte, size+2)
		if _, err = io.ReadFull(r, data); err != nil || string(data[size:]) != "\r\n" {
			return nil, io.ErrUnexpectedEOF
		}
		fields[i] = string(data[:size])
	}
	return fields, nil
}

func nativeArray(fields []string) string {
	var wire strings.Builder
	fmt.Fprintf(&wire, "*%d\r\n", len(fields))
	for _, field := range fields {
		fmt.Fprintf(&wire, "$%d\r\n%s\r\n", len(field), field)
	}
	return wire.String()
}

func nativePlan(t *testing.T) (commandPlan, mutationDispatcher, risk.CounterCoordinator) {
	t.Helper()
	p, keys, c := commandFixture(t, 9, 8, 7, 6)
	layout, err := newCommandLayout("native-wire", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := layout.prepare(prepareFixture(t, c, "tenant", "attempt", "192.0.2.1"), [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	return plan, mutationDispatcher{layout: layout, timeout: time.Second}, c
}

func TestNativeTransportUsesExactEVALAndReusesBoundedConnection(t *testing.T) {
	plan, _, _ := nativePlan(t)
	args, err := mutationArguments(plan)
	if err != nil {
		t.Fatal(err)
	}
	transport, fixture := nativeFixture(t, func(request []string) string { return nativeArray([]string{"unavailable", plan.fingerprint}) })
	for range 4 {
		reply, err := transport.execute(context.Background(), plan)
		if err != nil || !reflect.DeepEqual(reply, []string{"unavailable", plan.fingerprint}) {
			t.Fatal("native acknowledgement changed", err)
		}
	}
	expected := append([]string{"EVAL", mutationScript, strconv.Itoa(len(plan.keys))}, plan.keys...)
	expected = append(expected, args...)
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.dials != 2 || len(fixture.requests) != 4 {
		t.Fatal("native atomic binding or connection reuse failed")
	}
	for _, request := range fixture.requests {
		if !reflect.DeepEqual(request, expected) {
			t.Fatal("native command binding changed")
		}
	}
}

func TestNativeTransportRejectsConfigurationWithoutIO(t *testing.T) {
	validTLS, _ := nativeTLSFixture(t)
	credential, _ := newNativeCredential("default", []byte("fixture-password"))
	base := nativeTransportConfig{endpoint: "rediss://valkey.test:6379", tls: validTLS, credential: credential, timeout: time.Second, poolSize: 2, topology: "standalone"}
	for _, modify := range []func(*nativeTransportConfig){
		func(c *nativeTransportConfig) { c.endpoint += "#" },
		func(c *nativeTransportConfig) { c.credential.username = strings.Repeat("x", 129) },
		func(c *nativeTransportConfig) { c.endpoint = "redis://valkey.test:6379" }, func(c *nativeTransportConfig) { c.endpoint = "rediss://user:password@valkey.test:6379" }, func(c *nativeTransportConfig) { c.endpoint += "?x=1" }, func(c *nativeTransportConfig) { c.endpoint += "#x" }, func(c *nativeTransportConfig) { c.endpoint = "rediss://valkey.test:6379/0" }, func(c *nativeTransportConfig) { c.endpoint = "rediss://valkey.test:0" }, func(c *nativeTransportConfig) { c.endpoint = "rediss://valkey.test:65536" }, func(c *nativeTransportConfig) { c.endpoint = "rediss://valkey.test" }, func(c *nativeTransportConfig) { c.tls = nil }, func(c *nativeTransportConfig) { c.tls.InsecureSkipVerify = true }, func(c *nativeTransportConfig) { c.tls.ServerName = "foreign.test" }, func(c *nativeTransportConfig) { c.tls.RootCAs = nil }, func(c *nativeTransportConfig) { c.tls.MinVersion = tls.VersionTLS11 }, func(c *nativeTransportConfig) { c.credential = nativeCredential{} }, func(c *nativeTransportConfig) { c.timeout = 100*time.Millisecond - time.Nanosecond }, func(c *nativeTransportConfig) { c.timeout = 10*time.Second + time.Nanosecond }, func(c *nativeTransportConfig) { c.poolSize = 0 }, func(c *nativeTransportConfig) { c.poolSize = 201 }, func(c *nativeTransportConfig) { c.topology = "cluster" },
	} {
		cfg := base
		cfg.tls = base.tls.Clone()
		modify(&cfg)
		if _, err := newNativeTransport(cfg); !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("invalid config admitted", err)
		}
	}
	for _, pool := range []int{1, 200} {
		for _, timeout := range []time.Duration{100 * time.Millisecond, 10 * time.Second} {
			cfg := base
			cfg.poolSize = pool
			cfg.timeout = timeout
			owner, err := newNativeTransport(cfg)
			if err != nil {
				t.Fatal("valid bound rejected", err)
			}
			if err := owner.close(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNativeTransportErrorsCannotResendOrLeak(t *testing.T) {
	plan, _, _ := nativePlan(t)
	for _, response := range []string{"", "-MOVED 1 private-endpoint\r\n", "-ASK 1 private-endpoint\r\n", "-NOSCRIPT private-credential\r\n", "$9007199254740991\r\n", "*9007199254740991\r\n", "+OK\r\n", "*2\r\n:1\r\n+ok\r\n", "*2\r\n$-1\r\n+ok\r\n", "*2\r\n*0\r\n+ok\r\n", "*2\r\n$2\r\nx", "%1\r\n", nativeArray(make([]string, 20)), "$129\r\n"} {
		t.Run(fmt.Sprintf("response_%d", len(response)), func(t *testing.T) {
			transport, fixture := nativeFixture(t, func([]string) string { return response })
			reply, err := transport.execute(context.Background(), plan)
			if len(reply) != 0 || !errors.Is(err, ErrOutcomeUnknown) || strings.Contains(err.Error(), "private-") {
				t.Fatal("ambiguous reply admitted or diagnostic leaked", err)
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.dials != 1 || len(fixture.requests) != 1 {
				t.Fatal("mutation resent")
			}
		})
	}
}

func TestNativeTransportCancellationClosesInFlightIO(t *testing.T) {
	plan, _, _ := nativePlan(t)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	transport, fixture := nativeFixture(t, func([]string) string { entered <- struct{}{}; <-release; return "+OK\r\n" })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := transport.execute(ctx, plan); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("mutation did not enter native IO")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("cancellation fabricated noncommit", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancellation ignored before deadline")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.dials != 1 || len(fixture.requests) != 1 {
		t.Fatal("cancelled mutation resent")
	}
}

func TestNativeTransportCapacityAndConcurrentShutdown(t *testing.T) {
	plan, _, _ := nativePlan(t)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	defer close(release)
	transport, fixture := nativeFixture(t, func([]string) string { entered <- struct{}{}; <-release; return "+OK\r\n" })
	done := make(chan error, 2)
	for range 2 {
		go func() { _, err := transport.execute(context.Background(), plan); done <- err }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("capacity operation did not enter IO")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := transport.execute(ctx, plan); !errors.Is(err, ErrUnavailable) {
		t.Fatal("capacity wait ignored caller bound", err)
	}
	closing := make(chan error, 2)
	for range 2 {
		go func() { closing <- transport.close(context.Background()) }()
	}
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("shutdown lost in-flight uncertainty", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown did not terminate operation")
		}
	}
	for range 2 {
		select {
		case err := <-closing:
			if err != nil {
				t.Fatal("concurrent shutdown failed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown deadlocked")
		}
	}
	if _, err := transport.execute(context.Background(), plan); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed transport admitted IO", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.dials != 2 || len(fixture.requests) != 2 {
		t.Fatal("physical capacity bound exceeded")
	}
}

func TestNativeTransportAcknowledgementReachesCore(t *testing.T) {
	_, dispatcher, c := nativePlan(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	transport, _ := nativeFixture(t, func(request []string) string {
		count, _ := strconv.Atoi(request[2])
		args := request[3+count:]
		fields := []string{"committed", args[1], strconv.FormatInt(now.UnixMicro(), 10)}
		for _, kind := range args[5:] {
			fields = append(fields, kind, "11", strconv.FormatInt(now.UnixMicro(), 10), strconv.FormatInt(now.Add(5*time.Minute).UnixMicro(), 10))
		}
		return nativeArray(fields)
	})
	dispatcher.execute = transport.execute
	p, keys := dispatcher.layout.policy, dispatcher.layout.keys
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(ctx context.Context, cmd risk.CounterCommand) (risk.CounterResult, error) {
		return dispatcher.mutate(ctx, cmd, [16]byte{1})
	}), Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	result, err := c.Mutate(context.Background(), command)
	if err != nil || result.Outcome != risk.CounterCommitted || result.Signal.State != risk.SignalThrottle {
		t.Fatal("native acknowledged post-state lost", err)
	}
}

func TestNativeTransportPreIOAndCredentialCustody(t *testing.T) {
	plan, _, _ := nativePlan(t)
	transport, fixture := nativeFixture(t, func([]string) string { t.Error("invalid input reached server"); return "" })
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if _, err := transport.execute(ctx, plan); err == nil {
			t.Fatal("invalid context admitted")
		}
	}
	if _, err := transport.execute(context.Background(), commandPlan{}); err == nil {
		t.Fatal("invalid plan admitted")
	}
	var zero nativeTransport
	if _, err := zero.execute(context.Background(), plan); err == nil {
		t.Fatal("zero owner admitted")
	}
	if err := zero.close(context.Background()); err == nil {
		t.Fatal("zero owner closed as valid")
	}
	if err := transport.close(nil); err == nil {
		t.Fatal("nil close context admitted")
	}
	fixture.mu.Lock()
	if fixture.dials != 0 {
		t.Error("pre-IO input dialled")
	}
	fixture.mu.Unlock()
	for _, input := range []struct {
		username string
		password []byte
	}{{"", []byte("x")}, {"default", nil}, {strings.Repeat("x", 129), []byte("x")}, {"default", make([]byte, 4097)}} {
		if _, err := newNativeCredential(input.username, input.password); err == nil {
			t.Fatal("invalid credential admitted")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", transport), "fixture-password") || strings.Contains(fmt.Sprintf("%+v", transport.config), "valkey.test") || strings.Contains(fmt.Sprintf("%+v", transport.config.credential), "fixture-password") {
		t.Fatal("native custody leaked in formatting")
	}
	for _, value := range []any{transport, transport.config, transport.config.credential} {
		if _, err := json.Marshal(value); !errors.Is(err, risk.ErrSensitiveSerialization) {
			t.Fatal("native custody serialized", err)
		}
	}
}

func TestNativeTransportCancellationDuringEstablishment(t *testing.T) {
	plan, _, _ := nativePlan(t)
	for _, handshake := range []bool{false, true} {
		t.Run(fmt.Sprintf("handshake_%t", handshake), func(t *testing.T) {
			transport, _ := nativeFixture(t, func([]string) string { t.Error("cancelled establishment reached EVAL"); return "" })
			entered := make(chan struct{})
			var peer net.Conn
			transport.dial = func(ctx context.Context, _ string) (net.Conn, error) {
				if !handshake {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				var raw net.Conn
				raw, peer = net.Pipe()
				close(entered)
				return raw, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := transport.execute(ctx, plan); result <- err }()
			<-entered
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrOutcomeUnknown) && !errors.Is(err, ErrUnavailable) {
					t.Fatal("unexpected establishment result", err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Fatal("cancellation did not bound establishment")
			}
			if peer != nil {
				_ = peer.Close()
			}
		})
	}
}

func TestNativeWireRequestBoundsAndShortWrites(t *testing.T) {
	fields := []string{"AUTH", "default", "binary\x00\r\npassword"}
	wire, err := encodeNativeRequests([][]string{fields})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := readNativeRequest(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil || !reflect.DeepEqual(decoded, fields) {
		t.Fatal("binary request changed")
	}
	for _, requests := range [][][]string{nil, {{}}, {make([]string, 65)}, {{strings.Repeat("x", 8193)}}, {make([]string, 64), make([]string, 64), make([]string, 64)}} {
		if _, err := encodeNativeRequests(requests); err == nil {
			t.Fatal("unbounded request admitted")
		}
	}
	var output bytes.Buffer
	if err := writeNativeRequest(shortNativeWriter{&output}, wire); err != nil || !bytes.Equal(output.Bytes(), wire) {
		t.Fatal("short write truncated request", err)
	}
	if err := writeNativeRequest(zeroNativeWriter{}, wire); err == nil {
		t.Fatal("zero-progress write admitted")
	}
}

type shortNativeWriter struct{ output *bytes.Buffer }

func (w shortNativeWriter) Write(p []byte) (int, error) { return w.output.Write(p[:min(3, len(p))]) }

type zeroNativeWriter struct{}

func (zeroNativeWriter) Write([]byte) (int, error) { return 0, nil }

func TestNativeTransportRejectsUnprovedStartup(t *testing.T) {
	plan, _, _ := nativePlan(t)
	for _, startup := range []string{"-ERR private-credential\r\n", "+OK\r\n+OK\r\n", "+OK\r\n*2\r\n:1\r\n:2\r\n", "+OK\r\n*2\r\n$5\r\nproto\r\n:3\r\n", "+OK\r\n*2\r\n$5\r\nproto\r\n:2\r\n"} {
		transport, fixture := nativeFixture(t, func([]string) string { return nativeArray([]string{"unavailable", plan.fingerprint}) })
		fixture.startupReply = startup
		if _, err := transport.execute(context.Background(), plan); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("unproved startup admitted", err)
		}
		fixture.mu.Lock()
		requests := len(fixture.requests)
		fixture.mu.Unlock()
		if requests != 0 {
			t.Fatal("unproved startup reached mutation")
		}
	}
}

func TestNativeTransportDrainIncludesLifetimeCallback(t *testing.T) {
	transport, _ := nativeFixture(t, func([]string) string { return "" })
	transport.mu.Lock()
	transport.active = 1
	transport.mu.Unlock()
	callbackDone := make(chan struct{})
	stopObserved := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		transport.finishExecution(context.Background(), nil, false, false, func() bool { close(stopObserved); return false }, callbackDone)
		close(finished)
	}()
	<-stopObserved
	closed := make(chan error, 1)
	go func() { closed <- transport.close(context.Background()) }()
	select {
	case err := <-closed:
		close(callbackDone)
		<-finished
		t.Fatal("shutdown preceded callback completion", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(callbackDone)
	<-finished
	if err := <-closed; err != nil {
		t.Fatal("completed callback did not release shutdown", err)
	}
}

// AfterFunc is the standard cancellation-registration boundary. Delaying its
// stopper models cleanup scheduling, without a production callback/test hook.
type gatedNativeLifetime struct {
	context.Context
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (*gatedNativeLifetime) Value(any) any { return nil }
func (c *gatedNativeLifetime) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(c.Context, f)
	return func() bool {
		c.once.Do(func() { close(c.entered); <-c.release })
		return stop()
	}
}

func TestNativeTransportDeadlineDuringCleanupCannotGrantAdmission(t *testing.T) {
	_, dispatcher, _ := nativePlan(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	transport, fixture := nativeFixture(t, func(request []string) string {
		count, _ := strconv.Atoi(request[2])
		args := request[3+count:]
		fields := []string{"committed", args[1], strconv.FormatInt(now.UnixMicro(), 10)}
		for _, kind := range args[5:] {
			fields = append(fields, kind, "1", strconv.FormatInt(now.UnixMicro(), 10), strconv.FormatInt(now.Add(5*time.Minute).UnixMicro(), 10))
		}
		return nativeArray(fields)
	})
	transport.config.timeout = 100 * time.Millisecond
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	lifetime := &gatedNativeLifetime{Context: transport.lifetime, entered: make(chan struct{}), release: release}
	transport.lifetime = lifetime
	originalDial := transport.dial
	dialContext := make(chan context.Context, 1)
	transport.dial = func(ctx context.Context, address string) (net.Conn, error) {
		dialContext <- ctx
		return originalDial(ctx, address)
	}
	dispatcher.timeout = 2 * time.Second
	dispatcher.execute = transport.execute
	var storeError error
	core, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: dispatcher.layout.policy, Keys: dispatcher.layout.keys, Store: replyStoreFunc(func(ctx context.Context, cmd risk.CounterCommand) (risk.CounterResult, error) {
		result, err := dispatcher.mutate(ctx, cmd, [16]byte{1})
		storeError = err
		return result, err
	}), Clock: func() time.Time { return now }, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	command := prepareFixture(t, core, "tenant", "attempt", "192.0.2.1")
	finished := make(chan struct{})
	var committed bool
	var signal risk.SignalState
	var mutationError error
	go func() {
		defer close(finished)
		result, err := core.Mutate(context.Background(), command)
		committed = result.Outcome == risk.CounterCommitted
		signal = result.Signal.State
		mutationError = err
	}()
	select {
	case <-lifetime.entered:
	case <-time.After(time.Second):
		unblock()
		<-finished
		t.Fatal("cleanup barrier not reached")
	}
	bounded := <-dialContext
	<-bounded.Done()
	select {
	case <-finished:
		t.Fatal("returned before cleanup joined")
	default:
	}
	unblock()
	<-finished
	if !committed || signal != risk.SignalUnavailable || !errors.Is(storeError, context.DeadlineExceeded) || mutationError != nil {
		t.Fatal("late native deadline admitted clean state", committed, signal, storeError, mutationError)
	}
	fixture.mu.Lock()
	requests := len(fixture.requests)
	fixture.mu.Unlock()
	if requests != 1 {
		t.Fatal("deadline cleanup resent mutation")
	}
	transport.mu.Lock()
	active := transport.active
	transport.mu.Unlock()
	if active != 0 {
		t.Fatal("cleanup ownership retained")
	}
	for range transport.config.poolSize {
		if cell := <-transport.slots; cell != nil {
			cell.close()
			t.Fatal("expired connection returned healthy")
		}
	}
}
