package valkey

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

func TestPublicVelocityOwnerCanceledCloseIsPermanent(t *testing.T) {
	for _, mode := range []string{"canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfirmationFixture(t, 0)
			credential, err := NewCredential("default", []byte("fixture-password"))
			if err != nil {
				t.Fatal(err)
			}
			transport := f.owner.transport.config
			owner, err := NewVelocityRecovery(VelocityRecoveryConfig{Namespace: f.owner.layout.namespace, ReplaySecret: f.owner.layout.secret, Policy: f.owner.layout.policy, Keys: f.owner.layout.keys, Endpoint: transport.endpoint, TLS: &tls.Config{ServerName: transport.tls.ServerName, MinVersion: tls.VersionTLS12}, TrustPEM: f.wire.trustPEM, Credential: credential, Timeout: transport.timeout, PoolSize: transport.poolSize, Topology: "standalone"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := owner.Close(context.Background()); err != nil {
					t.Error("owner cleanup failed", err)
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			expected := context.Canceled
			if mode == "expired" {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				expected = context.DeadlineExceeded
			}
			cancel()
			if err := owner.Close(ctx); !errors.Is(err, expected) {
				t.Fatal("shutdown lost original caller bound", err)
			}
			if _, _, err := owner.PrimaryAuthorities(); err == nil {
				t.Fatal("canceled shutdown left native owner admitting authority")
			}
		})
	}
}

func TestNativeCanceledCloseCancelsExistingIO(t *testing.T) {
	plan, _, _ := nativePlan(t)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	transport, fixture := nativeFixture(t, func([]string) string {
		entered <- struct{}{}
		<-release
		return "+OK\r\n"
	})
	done := make(chan error, 1)
	go func() { _, err := transport.execute(context.Background(), plan); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("native work did not reach controlled IO")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := transport.close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled Close lost caller attribution", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatal("shutdown erased in-flight uncertainty", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("canceled Close did not cancel existing IO")
	}
	if _, err := transport.execute(context.Background(), plan); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed lifetime admitted a new native invocation", err)
	}
	if err := transport.close(context.Background()); err != nil {
		t.Fatal("repeat Close could not join cleanup", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.dials != 1 || len(fixture.requests) != 1 {
		t.Fatal("shutdown resent or redialed native work")
	}
}
