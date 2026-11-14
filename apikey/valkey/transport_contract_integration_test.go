//go:build integration

package apikeyvalkey_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	apikeyvalkey "github.com/faustbrian/go-identity/apikey/valkey"
)

// This bounded stdlib control connection only injects/restores a pause in the
// task-owned real server. It implements no source, projection or quota logic.
type valkeyControl struct {
	raw    net.Conn
	tls    *tls.Conn
	reader *bufio.Reader
}

func openValkeyControl(t *testing.T) *valkeyControl {
	t.Helper()
	u, err := url.Parse(os.Getenv("APIKEY_VALKEY_ENDPOINT"))
	if err != nil || u.Scheme != "rediss" || u.Hostname() != "127.0.0.1" {
		t.Fatal("owned loopback TLS endpoint required")
	}
	trust, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("owned TLS trust required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		t.Fatal("owned TLS trust invalid")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", u.Host)
	if err != nil {
		t.Fatal("owned server control unavailable")
	}
	secured := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: u.Hostname(), RootCAs: roots})
	if secured.HandshakeContext(ctx) != nil {
		_ = raw.Close()
		t.Fatal("owned TLS control handshake failed")
	}
	c := &valkeyControl{raw: raw, tls: secured, reader: bufio.NewReaderSize(secured, 4096)}
	t.Cleanup(func() { _ = raw.Close() })
	password, err := os.ReadFile(os.Getenv("APIKEY_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("owned authentication required")
	}
	defer clear(password)
	if c.command([]byte("AUTH"), []byte("default"), password) != nil {
		t.Fatal("owned TLS control authentication failed")
	}
	return c
}

func (c *valkeyControl) command(args ...[]byte) error {
	if c.raw.SetDeadline(time.Now().Add(time.Second)) != nil {
		return apikeyvalkey.ErrUnavailable
	}
	if _, err := fmt.Fprintf(c.tls, "*%d\r\n", len(args)); err != nil {
		return apikeyvalkey.ErrUnavailable
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(c.tls, "$%d\r\n", len(arg)); err != nil {
			return apikeyvalkey.ErrUnavailable
		}
		if _, err := c.tls.Write(arg); err != nil {
			return apikeyvalkey.ErrUnavailable
		}
		if _, err := c.tls.Write([]byte("\r\n")); err != nil {
			return apikeyvalkey.ErrUnavailable
		}
	}
	line, err := c.reader.ReadSlice('\n')
	if err != nil || string(line) != "+OK\r\n" {
		return apikeyvalkey.ErrUnavailable
	}
	return nil
}

func pauseOwnedValkey(t *testing.T) *valkeyControl {
	t.Helper()
	c := openValkeyControl(t)
	if c.command([]byte("CLIENT"), []byte("PAUSE"), []byte("500"), []byte("ALL")) != nil {
		t.Fatal("owned service pause failed")
	}
	t.Cleanup(func() {
		if c.command([]byte("CLIENT"), []byte("UNPAUSE")) != nil {
			t.Error("owned service pause restoration failed")
		}
	})
	return c
}

func TestRealValkeyOutageUsesAlreadyCommittedSourceWithoutRetry(t *testing.T) {
	cache, source, request := valkeyProjectionFixture(t)
	pauseOwnedValkey(t)
	started := time.Now()
	out, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request))
	if err != nil || out.Validate() != nil || out.Result == nil || out.Quota == nil || out.Quota.Remaining != 9 || source.calls != 1 {
		t.Fatal("cache outage hid known source result or repeated debit", err)
	}
	if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
		t.Fatal("silent cache exceeded bounded fallback budget", elapsed)
	}
}

func TestRealValkeyCloseCancelsSilentPeerAndRejectsNewSourceWork(t *testing.T) {
	cache, source, request := valkeyProjectionFixture(t)
	pauseOwnedValkey(t)
	baseline := runtime.NumGoroutine()
	type answer struct {
		out apikey.AtomicVerificationResult
		err error
	}
	finished := make(chan answer, 1)
	request = projectionAttempt(t, request)
	go func() { out, err := cache.VerifyAndConsume(t.Context(), request); finished <- answer{out, err} }()
	deadline := time.Now().Add(time.Second)
	for {
		source.mu.Lock()
		calls := source.calls
		source.mu.Unlock()
		if calls == 1 {
			break
		}
		if time.Now().After(deadline) {
			cache.Close()
			<-finished
			t.Fatal("source call was not reached")
		}
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	cache.Close()
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatal("close waited for silent cache beyond lifetime budget", elapsed)
	}
	got := <-finished
	if got.out.State != apikey.VerificationAttemptDebited || got.out.Quota == nil || got.out.Quota.Remaining != 9 || source.calls != 1 {
		t.Fatal("closure rewrote known source debit or retried it", got.err)
	}
	if got.out.Result != nil && got.err != nil {
		t.Fatal("failed closure returned a principal")
	}
	if _, err := cache.VerifyAndConsume(t.Context(), projectionAttempt(t, request)); !errors.Is(err, apikeyvalkey.ErrUnavailable) || source.calls != 1 {
		t.Fatal("closed cache admitted another source invocation", err)
	}
	leakDeadline := time.Now().Add(500 * time.Millisecond)
	for runtime.NumGoroutine() > baseline+2 {
		if time.Now().After(leakDeadline) {
			t.Fatal("closed adapter retained driver/background work")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
