package valkey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// Native configuration is retained only by the owned public recovery boundary.
// A credential handle is copied at construction; no connection or health is
// granted by constructing the transport. Rotation requires a new transport.
type nativeCredential struct{ username, password string }

func newNativeCredential(username string, password []byte) (nativeCredential, error) {
	if !boundedScope(username) || len(password) < 1 || len(password) > 4096 {
		return nativeCredential{}, risk.ErrInvalidPolicy
	}
	return nativeCredential{username: username, password: string(password)}, nil
}
func (nativeCredential) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.nativeCredential(redacted)")
}
func (nativeCredential) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (nativeCredential) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

type nativeTransportConfig struct {
	endpoint   string
	tls        *tls.Config
	credential nativeCredential
	timeout    time.Duration
	poolSize   int
	topology   string
}

func (nativeTransportConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.nativeTransportConfig(redacted)")
}
func (nativeTransportConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (nativeTransportConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// Each adapter slot owns exactly one client and physical connection, with one
// operation at a time. Synchronous RESP2 IO has no background client workers,
// discovery, reconnects or redirects. Only standalone RESP2 is activated by this private
// profile; replicated/cluster ownership and interoperability remain required.
type nativeTransport struct {
	config                  nativeTransportConfig
	address                 string
	dial                    func(context.Context, string) (net.Conn, error)
	slots                   chan *nativeConnection
	lifetime                context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	active                  int
	boot                    string
	evictions               uint64
	continuityLost          bool
	closed, cleanupComplete bool
	drained                 chan struct{}
}
type nativeConnection struct {
	raw     net.Conn
	secured *tls.Conn
	reader  *boundedResponseReader
}

func (*nativeTransport) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.nativeTransport(redacted)")
}
func (*nativeTransport) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (*nativeTransport) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }

func newNativeTransport(c nativeTransportConfig) (*nativeTransport, error) {
	if len(c.endpoint) < 1 || len(c.endpoint) > 512 || c.timeout < 100*time.Millisecond || c.timeout > 10*time.Second || c.poolSize < 1 || c.poolSize > 200 || c.topology != "standalone" || !boundedScope(c.credential.username) || len(c.credential.password) < 1 || len(c.credential.password) > 4096 || c.tls == nil {
		return nil, risk.ErrInvalidPolicy
	}
	u, err := url.Parse(c.endpoint)
	if err != nil || u.Scheme != "rediss" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return nil, risk.ErrInvalidPolicy
	}
	host, port, err := net.SplitHostPort(u.Host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || number == 0 || strconv.FormatUint(number, 10) != port || !nativeHostname(host) || u.Hostname() != host || c.endpoint != "rediss://"+u.Host {
		return nil, risk.ErrInvalidPolicy
	}
	if c.tls.ServerName != host || !supportedNativeTLS(c.tls) {
		return nil, risk.ErrInvalidPolicy
	}
	c.tls = c.tls.Clone()
	c.tls.RootCAs = c.tls.RootCAs.Clone()
	c.tls.CipherSuites = slices.Clone(c.tls.CipherSuites)
	c.tls.CurvePreferences = slices.Clone(c.tls.CurvePreferences)
	c.tls.SessionTicketsDisabled = true
	c.tls.ClientSessionCache = nil
	lifetime, cancel := context.WithCancel(context.Background())
	owner := &nativeTransport{config: c, address: u.Host, slots: make(chan *nativeConnection, c.poolSize), lifetime: lifetime, cancel: cancel, drained: make(chan struct{})}
	for range c.poolSize {
		owner.slots <- nil
	}
	owner.dial = func(ctx context.Context, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: c.timeout, KeepAlive: -1}).DialContext(ctx, "tcp", address)
	}
	return owner, nil
}

// TLS authentication is server trust plus native credentials, not arbitrary
// caller work hidden in a handshake. Unsupported certificate, clock, entropy,
// ALPN/ECH and session callbacks are rejected. The remaining caller-owned
// preference slices are bounded here and cloned before the owner is exposed.
func supportedNativeTLS(c *tls.Config) bool {
	if c.RootCAs == nil || len(c.RootCAs.Subjects()) == 0 || c.InsecureSkipVerify || c.MinVersion < tls.VersionTLS12 || c.MinVersion > tls.VersionTLS13 || c.MaxVersion != 0 && c.MaxVersion < c.MinVersion || c.Renegotiation != tls.RenegotiateNever {
		return false
	}
	if c.VerifyConnection != nil || c.VerifyPeerCertificate != nil || c.GetClientCertificate != nil || c.GetCertificate != nil || c.GetConfigForClient != nil || c.KeyLogWriter != nil || c.Time != nil || c.Rand != nil || c.WrapSession != nil || c.UnwrapSession != nil || c.EncryptedClientHelloRejectionVerify != nil {
		return false
	}
	return len(c.CipherSuites) <= 16 && len(c.CurvePreferences) <= 8 && len(c.NextProtos) == 0 && len(c.Certificates) == 0 && len(c.NameToCertificate) == 0 && c.ClientCAs == nil && c.ClientAuth == tls.NoClientCert && len(c.EncryptedClientHelloConfigList) == 0
}

func nativeHostname(host string) bool {
	if len(host) < 1 || len(host) > 253 || net.ParseIP(host) != nil || strings.ToLower(host) != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if b != '-' && (b < 'a' || b > 'z') && (b < '0' || b > '9') {
				return false
			}
		}
	}
	return true
}

// stopCallback joins a cancellation callback if it already started. No owned
// callback may survive operation completion or race connection reuse.
func stopCallback(stop func() bool, done <-chan struct{}) {
	if !stop() {
		<-done
	}
}

func (t *nativeTransport) execute(ctx context.Context, plan commandPlan) (reply []string, err error) {
	args, err := mutationArguments(plan)
	if err != nil {
		return nil, err
	}
	return t.executeScript(ctx, mutationScript, plan.keys, args)
}

func (t *nativeTransport) executeScript(ctx context.Context, script string, keys, args []string) (reply []string, err error) {
	if t == nil || t.slots == nil || t.dial == nil {
		return nil, risk.ErrInvalidPolicy
	}
	if ctx == nil {
		return nil, risk.ErrInvalidContext
	}
	bounded, cancel := context.WithTimeout(ctx, t.config.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	var cell *nativeConnection
	held := false
	t.mu.Lock()
	if t.closed || bounded.Err() != nil {
		t.mu.Unlock()
		return nil, ErrUnavailable
	}
	t.active++
	t.mu.Unlock()
	lifeDone := make(chan struct{})
	stopLife := context.AfterFunc(t.lifetime, func() { cancel(); close(lifeDone) })
	defer func() {
		t.finishExecution(bounded, cell, held, err != nil, stopLife, lifeDone)
		// Cleanup can itself cross the native deadline. Preserve the complete
		// acknowledgement, but never let a longer outer context grant admission.
		if err == nil || errors.Is(err, errNativeContinuity) {
			contextErr := bounded.Err()
			if contextErr == nil {
				contextErr = ctx.Err()
			}
			// Socket deadlines can fire before the context timer publishes Err.
			// Both enforce this same monotonic deadline, not separate budgets.
			if deadline, ok := bounded.Deadline(); contextErr == nil && ok && !time.Now().Before(deadline) {
				contextErr = context.DeadlineExceeded
			}
			if contextErr != nil {
				err = contextErr
			}
		}
		if err == nil {
			t.mu.Lock()
			lost := t.continuityLost
			t.mu.Unlock()
			if lost {
				err = errNativeContinuity
			}
		}
	}()
	select {
	case cell = <-t.slots:
		held = true
	case <-bounded.Done():
		return nil, ErrUnavailable
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed || bounded.Err() != nil {
		return nil, ErrUnavailable
	}
	if cell == nil {
		cell, err = t.open(bounded)
		if err != nil {
			return nil, ErrOutcomeUnknown
		}
	}
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	deadline, _ := bounded.Deadline()
	if cell.raw.SetDeadline(deadline) != nil {
		return nil, ErrOutcomeUnknown
	}
	ioDone := make(chan struct{})
	stopIO := context.AfterFunc(bounded, func() { _ = cell.raw.Close(); close(ioDone) })
	defer stopCallback(stopIO, ioDone)
	if err := t.checkProfile(cell); err != nil {
		if contextErr := bounded.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	values, evalErr := cell.eval(script, keys, args)
	if evalErr != nil {
		return nil, evalErr
	}
	// A late profile failure cannot rewrite an acknowledged native effect into
	// noncommit. The dispatcher preserves that effect while denying admission.
	if err := t.checkProfile(cell); err != nil {
		if contextErr := bounded.Err(); contextErr != nil {
			return values, contextErr
		}
		return values, err
	}
	return values, bounded.Err()
}

func (cell *nativeConnection) eval(script string, keys, args []string) ([]string, error) {
	fields := []string{"EVAL", script, strconv.Itoa(len(keys))}
	fields = append(fields, keys...)
	fields = append(fields, args...)
	wire, encodeErr := encodeNativeRequests([][]string{fields})
	if encodeErr != nil {
		return nil, ErrOutcomeUnknown
	}
	defer clear(wire)
	if writeNativeRequest(cell.secured, wire) != nil {
		return nil, ErrOutcomeUnknown
	}
	frame, readErr := readNativeFrame(cell.reader)
	if readErr != nil {
		return nil, ErrOutcomeUnknown
	}
	defer clear(frame)
	values, decodeErr := nativeStringArray(frame)
	if decodeErr != nil || len(values) < 2 || len(values) > 19 {
		return nil, ErrOutcomeUnknown
	}
	return values, nil
}

// Drainage belongs to the execution owner, including its cancellation callback.
// Connection release and the active-count transition have one synchronization
// owner; callbacks and socket closing never run under that lock.
func (t *nativeTransport) finishExecution(ctx context.Context, cell *nativeConnection, held, discard bool, stopLife func() bool, lifeDone <-chan struct{}) {
	stopCallback(stopLife, lifeDone)
	t.mu.Lock()
	lost := t.continuityLost
	t.mu.Unlock()
	if discard || ctx.Err() != nil || lost {
		if cell != nil {
			cell.close()
		}
		cell = nil
	}
	t.mu.Lock()
	if !t.closed && held {
		select {
		case t.slots <- cell:
		default:
			t.mu.Unlock()
			panic("native slot ownership violated")
		}
		t.active--
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	if cell != nil {
		cell.close()
	}
	t.mu.Lock()
	t.active--
	if t.active == 0 && t.cleanupComplete {
		close(t.drained)
	}
	t.mu.Unlock()
}

func (t *nativeTransport) open(ctx context.Context) (*nativeConnection, error) {
	raw, err := t.dial(ctx, t.address)
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, ErrOutcomeUnknown
	}
	cell := &nativeConnection{raw: raw}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(done) })
	defer stopCallback(stop, done)
	deadline, _ := ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	secured := tls.Client(raw, t.config.tls)
	if secured.HandshakeContext(ctx) != nil {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	cell.secured = secured
	cell.reader = newBoundedResponseReader(secured)
	wire, err := encodeNativeRequests([][]string{{"AUTH", t.config.credential.username, t.config.credential.password}, {"HELLO", "2"}})
	if err != nil {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	defer clear(wire)
	if writeNativeRequest(secured, wire) != nil {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	auth, authErr := readNativeFrame(cell.reader)
	validAuth := authErr == nil && string(auth) == "+OK\r\n"
	clear(auth)
	if !validAuth {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	hello, helloErr := readNativeFrame(cell.reader)
	validHello := helloErr == nil && nativeHello(hello)
	clear(hello)
	if !validHello || ctx.Err() != nil {
		cell.close()
		return nil, ErrOutcomeUnknown
	}
	return cell, nil
}
func (c *nativeConnection) close() {
	_ = c.raw.Close()
}

// close cancels active work, closes every idle connection and waits for active
// cleanup within the caller/adapter bound. A timeout leaves closing permanent;
// a later call can wait again. No new work may enter after the transition.
func (t *nativeTransport) close(ctx context.Context) error {
	if t == nil || t.slots == nil {
		return risk.ErrInvalidPolicy
	}
	if ctx == nil {
		return risk.ErrInvalidContext
	}
	bounded, cancel := context.WithTimeout(ctx, t.config.timeout)
	defer cancel()
	t.mu.Lock()
	first := !t.closed
	var idle []*nativeConnection
	if first {
		t.closed = true
		for i := 0; i < t.config.poolSize; i++ {
			select {
			case c := <-t.slots:
				if c != nil {
					idle = append(idle, c)
				}
			default:
			}
		}
	}
	t.mu.Unlock()
	if first {
		t.cancel()
		for _, cell := range idle {
			cell.close()
		}
		t.mu.Lock()
		t.cleanupComplete = true
		if t.active == 0 {
			close(t.drained)
		}
		t.mu.Unlock()
	}
	// A valid Close consumes ownership even when the caller can no longer
	// wait. Applying its deadline before cancellation would leave previously
	// issued handles live. Preserve attribution deterministically when both
	// the completed drain and the canceled context are ready.
	if err := bounded.Err(); err != nil {
		return err
	}
	select {
	case <-t.drained:
		return nil
	case <-bounded.Done():
		return bounded.Err()
	}
}
