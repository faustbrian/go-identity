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
	server, err := identityhttp.NewHTTPServer(identityhttp.ServerConfig{
		Address: "127.0.0.1:0", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, HandlerTimeout: 15 * time.Second,
		ShutdownDrain: 30 * time.Second, MaximumHeaderBytes: 65536,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if err != nil {
		panic(err)
	}
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
