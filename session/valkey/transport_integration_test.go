//go:build integration

package sessionvalkey

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"runtime"
	"testing"
	"time"
)

// This is a real-server transport lifetime regression, not session authority
// evidence. The public native consumer separately owns authentication proof.
func TestClientCloseBudget(t *testing.T) {
	baseline := runtime.NumGoroutine()
	ca, err := os.ReadFile(os.Getenv("SESSION_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit TLS fixture required")
	}
	password, err := os.ReadFile(os.Getenv("SESSION_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit password fixture required")
	}
	secret, err := NewSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	c := &Cache{config: Config{Username: "default", Password: secret, CacheTimeout: 300 * time.Millisecond}, address: os.Getenv("SESSION_VALKEY_ADDRESS"), tls: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	defer stop()
	client, err := c.client(bounded)
	if err != nil {
		t.Fatal("real TLS client", err)
	}
	defer client.Close()
	// Warm the native client's initial HELLO connection and blocking EVAL pool
	// connection before making the actual peer silent.
	if err = client.Do(bounded, client.B().Ping().Build()).Error(); err != nil {
		t.Fatal("real client warmup")
	}
	control, err := c.client(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err = control.Do(ctx, control.B().Arbitrary("CLIENT").Args("PAUSE", "800", "ALL").Build()).Error(); err != nil {
		t.Fatal("fixture pause")
	}
	started := time.Now()
	client.Close()
	elapsed := time.Since(started)
	if elapsed > 150*time.Millisecond {
		t.Fatalf("owned client cleanup exceeded150ms while peer silent: %s", elapsed)
	}
	control.Close()
	cancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for runtime.NumGoroutine() > baseline+2 {
		if time.Now().After(deadline) {
			t.Fatal("closed clients retained background work")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
