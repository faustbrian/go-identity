package identityhttp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func corsConfig(t testing.TB) identityhttp.CORSConfig {
	t.Helper()
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		t.Fatal(err)
	}
	return identityhttp.CORSConfig{Network: network, Routes: []identityhttp.CORSRoutePolicy{
		{Method: "POST", Path: "/cookie", Credentials: identityhttp.CORSCookieCredentials,
			Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Content-Type", "X-CSRF-Token"}, ExposedHeaders: []string{"ETag"}, MaxAge: 10 * time.Minute},
		{Method: "POST", Path: "/bearer", Credentials: identityhttp.CORSBearerCredentials,
			Origins: []identityhttp.Origin{"https://other.example"}, AllowedHeaders: []string{"Authorization"}, ExposedHeaders: []string{"Location"}},
	}}
}

func corsRequest(method, path, origin string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host, r.RemoteAddr, r.TLS = "login.example", "198.51.100.7:1234", &tls.ConnectionState{}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	return r
}

func TestCORSRouteAndCredentialIsolation(t *testing.T) {
	calls := 0
	h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, origin, credentials, expose string }{
		{"/cookie", "https://client.example", "true", "ETag"},
		{"/bearer", "https://other.example", "", "Location"},
	} {
		r := corsRequest("POST", tc.path, tc.origin)
		r.Header.Set("Cookie", "unrelated=ambient")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		headers := w.Result().Header
		if w.Code != http.StatusAccepted || headers.Get("Access-Control-Allow-Origin") != tc.origin || headers.Get("Access-Control-Allow-Credentials") != tc.credentials || headers.Get("Access-Control-Expose-Headers") != tc.expose {
			t.Fatal("route grant mismatch", w.Code, headers)
		}
		if tc.path == "/bearer" && headers.Get("Cache-Control") != "no-store" {
			t.Fatal("bearer response cacheable")
		}
	}
	if calls != 2 {
		t.Fatal("handler count", calls)
	}
	for _, tc := range []struct{ method, path, origin string }{
		{"POST", "/cookie", "https://other.example"}, {"POST", "/bearer", "https://client.example"},
		{"GET", "/cookie", "https://client.example"}, {"POST", "/unknown", "https://client.example"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest(tc.method, tc.path, tc.origin))
		if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" || calls != 2 {
			t.Fatal("cross-route request admitted", w.Code, calls)
		}
	}
}

func TestCORSPreflightStopsBeforeHandler(t *testing.T) {
	calls := 0
	h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	if err != nil {
		t.Fatal(err)
	}
	r := corsRequest("OPTIONS", "/cookie", "https://client.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type, X-CSRF-Token")
	body := &countedBody{Reader: strings.NewReader("body")}
	r.Body = body
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 || calls != 0 || body.reads != 0 || body.closes != 0 {
		t.Fatal("preflight called handler or returned payload", w.Code, calls)
	}
	if w.Header().Get("Access-Control-Allow-Methods") != "POST" || w.Header().Get("Access-Control-Allow-Headers") != "Content-Type, X-Csrf-Token" || w.Header().Get("Access-Control-Max-Age") != "600" {
		t.Fatal("incorrect preflight grants", w.Header())
	}
	for _, dimension := range []string{"origin", "access-control-request-method", "access-control-request-headers"} {
		if !strings.Contains(strings.ToLower(w.Header().Get("Vary")), dimension) {
			t.Fatal("missing cache dimension", dimension)
		}
	}
	for _, headers := range []http.Header{
		{"Access-Control-Request-Method": {"POST"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"GET"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST", "POST"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "access-control-request-method": {"POST"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"Authorization"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Private-Network": {"true"}},
	} {
		r := corsRequest("OPTIONS", "/cookie", "")
		r.Header = headers
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || calls != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("invalid preflight admitted", w.Code, calls)
		}
	}
}

func TestCORSDenialRemovesLocationAliases(t *testing.T) {
	h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("denial invoked handler") }))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	w.Header()["location"] = []string{"https://client.example/continuation"}
	w.Header().Set("Location", "https://client.example/other")
	h.ServeHTTP(w, corsRequest("POST", "/cookie", "https://evil.example"))
	for name := range w.Result().Header {
		if strings.EqualFold(name, "Location") {
			t.Fatal("denial retained redirect target")
		}
	}
}

type corsReadFromRecorder struct{ *httptest.ResponseRecorder }

func (w *corsReadFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w.ResponseRecorder, r)
}

type corsReaderFunc func([]byte) (int, error)

func (f corsReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestCORSReaderFromCallbackCannotWiden(t *testing.T) {
	h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		read := false
		_, _ = w.(io.ReaderFrom).ReadFrom(corsReaderFunc(func(p []byte) (int, error) {
			if read {
				return 0, io.EOF
			}
			read = true
			w.Header()["access-control-allow-origin"] = []string{"https://evil.example"}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Cache-Control", "public")
			w.Header().Del("Vary")
			return copy(p, "body"), nil
		}))
	}))
	if err != nil {
		t.Fatal(err)
	}
	w := &corsReadFromRecorder{httptest.NewRecorder()}
	h.ServeHTTP(w, corsRequest("POST", "/bearer", "https://other.example"))
	res := w.Result()
	defer res.Body.Close()
	assertCORSGrants(t, res.Header, "https://other.example", "", "Location")
	if res.Header.Get("Cache-Control") != "no-store" || !strings.Contains(strings.ToLower(res.Header.Get("Vary")), "origin") {
		t.Fatal("reader callback widened cache policy")
	}
}

func assertCORSGrants(t *testing.T, header http.Header, origin, credentials, expose string) {
	t.Helper()
	allowed := map[string]string{"access-control-allow-origin": origin, "access-control-allow-credentials": credentials, "access-control-expose-headers": expose}
	for name, values := range header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "access-control-") {
			continue
		}
		value, ok := allowed[lower]
		if !ok || value == "" || len(values) != 1 || values[0] != value || name != http.CanonicalHeaderKey(name) {
			t.Fatal("widened or ambiguous response grant", name)
		}
	}
	for name, value := range allowed {
		if header.Get(name) != value {
			t.Fatal("missing approved response grant", name)
		}
	}
}

func TestCORSResponseCustody(t *testing.T) {
	for _, path := range []string{"/cookie", "/bearer"} {
		for _, commitment := range []string{"status", "write", "flush", "read-from", "return"} {
			t.Run(path+commitment, func(t *testing.T) {
				origin, credentials, expose := "https://client.example", "true", "ETag"
				if path == "/bearer" {
					origin, credentials, expose = "https://other.example", "", "Location"
				}
				h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Header()["access-control-allow-origin"] = []string{"https://evil.example"}
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Expose-Headers", "*")
					w.Header().Set("Access-Control-Allow-Headers", "*")
					w.Header().Set("Access-Control-Allow-Methods", "DELETE")
					w.Header().Set("Access-Control-Max-Age", "86400")
					w.Header()["access-control-allow-private-network"] = []string{"true"}
					w.Header().Del("Vary")
					w.Header()["vary"] = []string{"Accept-Encoding"}
					w.Header().Set("Cache-Control", "public, max-age=3600")
					w.Header()["cache-control"] = []string{"public"}
					switch commitment {
					case "status":
						w.WriteHeader(http.StatusInternalServerError)
					case "write":
						_, _ = w.Write([]byte("body"))
					case "flush":
						w.(http.Flusher).Flush()
					case "read-from":
						_, _ = w.(io.ReaderFrom).ReadFrom(strings.NewReader("body"))
					}
				}))
				if err != nil {
					t.Fatal(err)
				}
				w := &corsReadFromRecorder{httptest.NewRecorder()}
				w.Header()["vary"] = []string{"Accept-Language"}
				h.ServeHTTP(w, corsRequest("POST", path, origin))
				res := w.Result()
				defer res.Body.Close()
				assertCORSGrants(t, res.Header, origin, credentials, expose)
				for _, dimension := range []string{"origin", "accept-encoding", "accept-language"} {
					if !strings.Contains(strings.ToLower(res.Header.Get("Vary")), dimension) {
						t.Fatal("Vary lost", dimension)
					}
				}
				if path == "/bearer" {
					for name, values := range res.Header {
						if strings.EqualFold(name, "Cache-Control") && (name != "Cache-Control" || len(values) != 1 || values[0] != "no-store") {
							t.Fatal("cache policy widened")
						}
					}
				}
			})
		}
	}
}

func TestCORSDisabledAndMissingOrigin(t *testing.T) {
	cfg := corsConfig(t)
	cfg.Routes = []identityhttp.CORSRoutePolicy{{Method: "POST", Path: "/bearer", Credentials: identityhttp.CORSBearerCredentials}}
	calls := 0
	h, err := identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Cache-Control", "public")
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "https://login.example"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest("POST", "/bearer", origin))
		assertCORSGrants(t, w.Header(), "", "", "")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("disabled route failed ordinary call")
		}
	}
	for _, r := range []*http.Request{corsRequest("POST", "/bearer", "https://client.example"), corsRequest("OPTIONS", "/bearer", "https://login.example")} {
		if r.Method == "OPTIONS" {
			r.Header.Set("Access-Control-Request-Method", "POST")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || calls != 2 {
			t.Fatal("disabled CORS granted or invoked handler")
		}
		assertCORSGrants(t, w.Header(), "", "", "")
	}
	cfg.Routes = nil
	h, err = identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Access-Control-Allow-Origin", "*") }))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, corsRequest("GET", "/unknown", ""))
	assertCORSGrants(t, w.Header(), "", "", "")
}

func TestCORSMalformedAndBodyOwnership(t *testing.T) {
	calls := 0
	h, err := identityhttp.NewCORSHandler(corsConfig(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []http.Header{
		{"Origin": {"null"}}, {"Origin": {""}}, {"Origin": {"https://CLIENT.example"}},
		{"Origin": {"http://client.example"}}, {"Origin": {"https://client.example:443"}}, {"Origin": {"https://client.example."}},
		{"Origin": {"https://client.example", "https://client.example"}}, {"Origin": {"https://client.example"}, "origin": {"https://client.example"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {""}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"post"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"Content-Type,"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"Content-Type, content-type"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"*"}},
		{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"Content-Type"}, "access-control-request-headers": {"Content-Type"}},
	} {
		r := corsRequest("OPTIONS", "/cookie", "")
		r.Header = header
		r.Header.Set("Referer", "https://client.example/safe")
		body := &countedBody{Reader: strings.NewReader("body")}
		r.Body = body
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || calls != 0 || body.reads != 0 || body.closes != 0 {
			t.Fatal("invalid CORS did work", w.Code, calls, body.reads, body.closes)
		}
		assertCORSGrants(t, w.Header(), "", "", "")
	}
	r := corsRequest("OPTIONS", "/cookie", "https://client.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestTimeout || calls != 0 {
		t.Fatal("cancelled request admitted")
	}
}

func TestCORSConfigurationAndCopy(t *testing.T) {
	for _, change := range []func(*identityhttp.CORSConfig){
		func(c *identityhttp.CORSConfig) { c.Network = nil },
		func(c *identityhttp.CORSConfig) { c.Network = &identityhttp.NetworkResolver{} },
		func(c *identityhttp.CORSConfig) { c.Routes = make([]identityhttp.CORSRoutePolicy, 1025) },
		func(c *identityhttp.CORSConfig) { c.Routes = append(c.Routes, c.Routes[0]) },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Method = "post" },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Path = "/a/../cookie" },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Credentials = 0 },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Credentials = 99 },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Origins = []identityhttp.Origin{"*"} },
		func(c *identityhttp.CORSConfig) { c.Routes[0].Origins = nil },
		func(c *identityhttp.CORSConfig) { c.Routes[0].AllowedHeaders = []string{"*"} },
		func(c *identityhttp.CORSConfig) {
			c.Routes[0].AllowedHeaders = []string{"Content-Type", "content-type"}
		},
		func(c *identityhttp.CORSConfig) { c.Routes[0].AllowedHeaders = make([]string, 65) },
		func(c *identityhttp.CORSConfig) { c.Routes[0].ExposedHeaders = []string{"Set-Cookie"} },
		func(c *identityhttp.CORSConfig) { c.Routes[0].ExposedHeaders = []string{"*"} },
		func(c *identityhttp.CORSConfig) { c.Routes[0].MaxAge = -time.Second },
		func(c *identityhttp.CORSConfig) { c.Routes[0].MaxAge = 24*time.Hour + time.Second },
		func(c *identityhttp.CORSConfig) { c.Routes[0].MaxAge = time.Nanosecond },
	} {
		cfg := corsConfig(t)
		change(&cfg)
		if h, err := identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	for _, next := range []http.Handler{nil, http.HandlerFunc(nil)} {
		if h, err := identityhttp.NewCORSHandler(corsConfig(t), next); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid handler accepted", err)
		}
	}
	cfg := corsConfig(t)
	var calls atomic.Int32
	h, err := identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routes[0].Origins[0] = "https://evil.example"
	cfg.Routes[0].AllowedHeaders[0] = "Evil"
	cfg.Routes[0].ExposedHeaders[0] = "Evil"
	cfg.Routes[0].Path = "/evil"
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 16 {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, corsRequest("POST", "/cookie", "https://client.example"))
				assertCORSGrants(t, w.Header(), "https://client.example", "true", "ETag")
				w = httptest.NewRecorder()
				h.ServeHTTP(w, corsRequest("POST", "/cookie", "https://evil.example"))
				if w.Code != 403 {
					t.Error("mutated policy leaked")
				}
			}
		})
	}
	wg.Wait()
	if calls.Load() != 256 {
		t.Fatal("incorrect concurrent handler admissions", calls.Load())
	}
}

func TestCORSCanonicalEngineCopyAndUncredentialedRoute(t *testing.T) {
	cfg := corsConfig(t)
	cfg.Routes[0].Credentials = identityhttp.CORSNoCredentials
	r := corsRequest("POST", "/cookie", "")
	r.Header["origin"] = []string{"https://client.example"}
	var observed *http.Request
	h, err := identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
		observed = got
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assertCORSGrants(t, w.Header(), "https://client.example", "", "ETag")
	if observed != r || r.Header.Get("Origin") != "" || len(r.Header["origin"]) != 1 {
		t.Fatal("borrowed request mutated or substituted")
	}
	r = corsRequest("OPTIONS", "/cookie", "")
	r.Header["origin"] = []string{"https://client.example"}
	r.Header["access-control-request-method"] = []string{"POST"}
	r.Header["access-control-request-headers"] = []string{"content-type"}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || r.Header.Get("Origin") != "" || r.Header.Get("Access-Control-Request-Method") != "" {
		t.Fatal("case-insensitive preflight failed or mutated request")
	}
}

func FuzzCORSPreflightAdmission(f *testing.F) {
	for _, seed := range [][2]string{{"https://client.example", "POST"}, {"null", "POST"}, {"https://client.example", "post"}, {"https://client.example:443", "POST"}, {"", "POST"}, {"https://client.example", "DELETE"}} {
		f.Add(seed[0], seed[1], "")
	}
	for _, headers := range []string{"Content-Type", "content-type, X-CSRF-Token", "Content-Type,content-type", "Authorization", ",", strings.Repeat("a", 8193), "Content-Type,", "*"} {
		f.Add("https://client.example", "POST", headers)
	}
	cfg := corsConfig(f)
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits:               identityhttp.Limits{MaximumHeaderBytes: 65536, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 8},
		MaximumForwardedHops: 8, PublicHosts: []string{"login.example"},
	})
	if err != nil {
		f.Fatal(err)
	}
	cfg.Network = network
	h, err := identityhttp.NewCORSHandler(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("preflight invoked next") }))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, origin, method, headers string) {
		r := corsRequest("OPTIONS", "/cookie", origin)
		r.Header["Access-Control-Request-Method"] = []string{method}
		if headers != "" {
			r.Header.Set("Access-Control-Request-Headers", headers)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := origin == "https://client.example" && method == "POST"
		if headers != "" {
			if len(headers) > 8192 {
				want = false
			} else {
				parts := strings.Split(headers, ",")
				if len(parts) > 2 {
					want = false
				}
				seen := map[string]bool{}
				for _, part := range parts {
					name := strings.Trim(part, " \t")
					for i := range name {
						if name[i] >= 128 {
							want = false
						}
					}
					lower := strings.ToLower(name)
					if lower != "content-type" && lower != "x-csrf-token" || seen[lower] {
						want = false
					}
					seen[lower] = true
				}
			}
		}
		if want {
			if w.Code != 204 {
				t.Fatal("exact preflight denied")
			}
		} else if w.Code < 400 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("nonexact preflight admitted")
		}
	})
}
