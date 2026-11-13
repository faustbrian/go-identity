//go:build integration

package sessionvalkey_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
	cache "github.com/faustbrian/go-identity/session/valkey"
	valkey "github.com/valkey-io/valkey-go"
)

// The diagnostic is deliberately one native admission and one exact restart,
// not the aggregate consumer. Logged errors contain only static adapter phases.
func TestNativeTLSRestartBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, _, codec, request, clock, key, _ := primaryFixture(t, ctx)
	clock.set(clock.Now().Add(2 * time.Second))
	ca, err := os.ReadFile(os.Getenv("SESSION_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit CA required")
	}
	password, err := os.ReadFile(os.Getenv("SESSION_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit fixture credential required")
	}
	secret, err := cache.NewSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := cache.NewSecret(bytes.Repeat([]byte{99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := cache.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: os.Getenv("SESSION_VALKEY_ENDPOINT"), Username: "default", Password: secret, Namespace: "restart-only", NamespaceKey: namespaceKey, TrustPEM: ca, DeploymentEpoch: 1, LookupKeys: []session.DigestKey{key}, MaximumDuration: 2 * time.Second, CacheTimeout: 300 * time.Millisecond, MaximumConcurrent: 4, MaximumScopes: 2, MaximumPayloadBytes: 32768}
	c, err := cache.New(ctx, config, codec, clock)
	if err != nil {
		t.Fatal("initial constructor", err)
	}
	defer c.Close()
	positive, err := c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal("initial native admission", err)
	}
	checkpoint, err := c.Checkpoint(ctx, request)
	if err != nil {
		t.Fatal("pre-restart checkpoint", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.families SET state='revoked'`); err != nil {
		t.Fatal("primary withdrawal")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	control, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("SESSION_VALKEY_ADDRESS")}, Username: "default", Password: string(password), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots}, ForceSingleClient: true, DisableCache: true, DisableRetry: true})
	if err != nil {
		t.Fatal("fixture control")
	}
	defer control.Close()
	if err = control.Do(ctx, control.B().Save().Build()).Error(); err != nil {
		t.Fatal("fixture SAVE")
	}
	directory := os.Getenv("SESSION_VALKEY_RESTART_DIR")
	if directory == "" {
		t.Fatal("explicit restart directory required")
	}
	if err = os.WriteFile(filepath.Join(directory, "ready"), []byte("restart one persisted admission"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, e := os.Stat(filepath.Join(directory, "restarted")); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("restart handshake deadline")
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Preserve the original failing boundary: Fill is the FIRST host operation.
	// Probe/Seal run only on failure to discriminate, never make the test pass.
	started := time.Now()
	filled, e := c.Fill(ctx, checkpoint, positive)
	t.Logf("phase=post-restart-fill elapsed=%s error=%v", time.Since(started), e)
	if e != nil {
		started = time.Now()
		probe, probeErr := cache.New(ctx, config, codec, clock)
		t.Logf("phase=diagnostic-constructor elapsed=%s error=%v", time.Since(started), probeErr)
		if probe != nil {
			probe.Close()
		}
		started = time.Now()
		blob, sealErr := codec.Seal(ctx, positive)
		t.Logf("phase=diagnostic-seal elapsed=%s error=%v", time.Since(started), sealErr)
		clear(blob)
		t.Fatal("first post-restart Fill failed; later probes cannot satisfy it")
	}
	if filled {
		t.Fatal("restored marker epoch rejection not proved")
	}
	if got, e := c.Get(ctx, request); e != nil || got.Authenticated {
		t.Fatal("restored ciphertext did not use withdrawn primary", e)
	}
}

func TestNativeTLSShortBudgetFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, primary, codec, request, clock, key, _ := primaryFixture(t, ctx)
	ca, err := os.ReadFile(os.Getenv("SESSION_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit CA required")
	}
	password, err := os.ReadFile(os.Getenv("SESSION_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit fixture credential required")
	}
	secret, err := cache.NewSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := cache.NewSecret(bytes.Repeat([]byte{99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := cache.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: os.Getenv("SESSION_VALKEY_ENDPOINT"), Username: "default", Password: secret, Namespace: "short-budget", NamespaceKey: namespaceKey, TrustPEM: ca, DeploymentEpoch: 1, LookupKeys: []session.DigestKey{key}, MaximumDuration: 400 * time.Millisecond, CacheTimeout: 300 * time.Millisecond, MaximumConcurrent: 1, MaximumScopes: 2, MaximumPayloadBytes: 32768}
	c, err := cache.New(ctx, config, codec, clock)
	if err != nil {
		t.Fatal("initial construction", err)
	}
	defer c.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid fixture CA")
	}
	control, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("SESSION_VALKEY_ADDRESS")}, Username: "default", Password: string(password), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots}, ForceSingleClient: true, DisableCache: true, DisableRetry: true})
	if err != nil {
		t.Fatal("fixture control")
	}
	defer control.Close()
	if err = control.Do(ctx, control.B().Arbitrary("CLIENT").Args("PAUSE", "800", "ALL").Build()).Error(); err != nil {
		t.Fatal("fixture pause")
	}
	started := time.Now()
	got, err := c.Get(ctx, request)
	if err != nil || !got.Authenticated || time.Since(started) > 450*time.Millisecond {
		t.Fatalf("healthy-primary fallback lost400ms operation budget: elapsed=%s error=%v", time.Since(started), err)
	}
	if err = control.Do(ctx, control.B().Ping().Build()).Error(); err != nil {
		t.Fatal("fixture resume")
	}
	config.MaximumDuration = 2 * time.Second
	config.CacheTimeout = time.Second
	closing, err := cache.New(ctx, config, codec, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer closing.Close()
	if err = control.Do(ctx, control.B().Arbitrary("CLIENT").Args("PAUSE", "2000", "ALL").Build()).Error(); err != nil {
		t.Fatal("fixture second pause")
	}
	finished := make(chan error, 1)
	go func() {
		result, e := closing.Get(ctx, request)
		if result.Authenticated {
			finished <- cache.ErrInvalidInput
			return
		}
		finished <- e
	}()
	for !cache.ActiveForTest(closing) {
		select {
		case <-ctx.Done():
			t.Fatal("operation never admitted")
		case <-time.After(time.Millisecond):
		}
	}
	started = time.Now()
	closing.Close()
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("in-flight Close exceeded150ms: %s", elapsed)
	}
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("canceled operation reported success")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("canceled operation leaked")
	}
	if result, e := primary.Get(ctx, request); e != nil || !result.Authenticated {
		t.Fatal("cache Close closed borrowed primary", e)
	}
}
