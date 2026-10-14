package identityhttp_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleNewCORSHandler() {
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 8},
		MaximumForwardedHops: 8, PublicHosts: []string{"login.example"},
	})
	if err != nil {
		panic(err)
	}
	calls := 0
	handler, err := identityhttp.NewCORSHandler(identityhttp.CORSConfig{Network: network, Routes: []identityhttp.CORSRoutePolicy{
		{Method: "POST", Path: "/cookie", Credentials: identityhttp.CORSCookieCredentials, Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Content-Type", "X-CSRF-Token"}, MaxAge: 10 * time.Minute},
		{Method: "POST", Path: "/bearer", Credentials: identityhttp.CORSBearerCredentials, Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Authorization"}},
	}}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusAccepted) }))
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest("OPTIONS", "/cookie", nil)
	request.Host, request.RemoteAddr, request.TLS = "login.example", "198.51.100.7:1234", &tls.ConnectionState{}
	request.Header.Set("Origin", "https://client.example")
	request.Header.Set("Access-Control-Request-Method", "POST")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	fmt.Println(response.Code, calls, response.Header().Get("Access-Control-Allow-Credentials"))
	// The real owning router must still authenticate, authorize, rate-limit and
	// enforce token-bound CSRF. This example proves only CORS preflight admission.
	// Output: 204 0 true
}
