package identityhttp_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleHTTPServer() {
	mux := http.NewServeMux()
	server, err := identityhttp.NewHTTPServer(identityhttp.ServerConfig{
		Address: "127.0.0.1:0", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, HandlerTimeout: 15 * time.Second,
		ShutdownDrain: 30 * time.Second, MaximumHeaderBytes: 65536,
	}, mux)
	if err != nil {
		panic(err)
	}
	live, ready, err := identityhttp.NewProbeHandlers(identityhttp.ProbeConfig{
		State: server.State, Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
			// This lifecycle-only example selects no domain dependencies. A real
			// composition must check every selected store, migration and key.
			return identityhttp.ReadinessSnapshot{Ready: true}, ctx.Err()
		}},
	})
	if err != nil {
		panic(err)
	}
	mux.Handle("/healthz", live)
	mux.Handle("/readyz", ready)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), listener) }()
	<-server.Started()
	if err := server.Shutdown(context.Background()); err != nil {
		panic(err)
	}
	if err := <-done; err != nil {
		panic(err)
	}
	fmt.Println(server.State() == identityhttp.ServerStopped)
	// Output: true
}
