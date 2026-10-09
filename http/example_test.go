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

func ExampleNewOperationDescriptors() {
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{})
	if err != nil {
		panic(err)
	}
	fmt.Println(len(operations))
	probes, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
		State:   func() identityhttp.ServerState { return identityhttp.ServerStarting },
		Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(ctx context.Context) (identityhttp.ReadinessSnapshot, error) {
			// No dependencies are selected in this construction-only example.
			return identityhttp.ReadinessSnapshot{Ready: true}, ctx.Err()
		}},
	})
	if err != nil {
		panic(err)
	}
	operations, err = identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{probes}})
	if err != nil {
		panic(err)
	}
	for _, operation := range operations {
		fmt.Println(operation.Record.OperationID, operation.Route.Path)
	}
	// Output:
	// 0
	// identity.health /healthz
	// identity.readiness /readyz
}

func ExampleNewRouter() {
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{})
	if err != nil {
		panic(err)
	}
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: identityhttp.NetworkConfig{PublicHosts: []string{"login.example"}, MaximumForwardedHops: 8,
			Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 65536,
				MaximumDecodedBytes: 65536, MaximumFields: 128, MaximumDepth: 16}},
		HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
	}, operations, nil)
	if err != nil {
		panic(err)
	}
	// Empty selection exposes no routes, probes or metadata endpoint. Real
	// applications explicitly select owned features before constructing a server.
	fmt.Println(handler != nil, document.Version(), len(document.Operations()))
	// Output: true 3.1.1 0
}
