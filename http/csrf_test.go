package identityhttp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func csrfWire() string { return base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }

func csrfDecoder(t *testing.T) *identityhttp.CSRFDecoder {
	t.Helper()
	d, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: originGuard(t, identityhttp.RefererFallbackDeny), FormField: "csrf_token"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func csrfRequest(method, media, body string) *http.Request {
	r := originRequest("https://tenant.example")
	r.Method = method
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", media)
	return r
}

func copyCSRF(wire string) (auth.BearerCredential, error) { return auth.NewBearerCredential(wire), nil }

func TestDecodeCSRFCookieMutationChannels(t *testing.T) {
	d := csrfDecoder(t)
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		for _, form := range []bool{false, true} {
			media, body := "application/json", `{"name":"kept"}`
			if form {
				media, body = "application/x-www-form-urlencoded", "csrf_token="+csrfWire()+"&name=kept"
			}
			r := csrfRequest(method, media, body)
			if !form {
				r.Header.Set("X-CSRF-Token", csrfWire())
			}
			tracked := &countedBody{Reader: strings.NewReader(body)}
			r.Body = tracked
			calls := 0
			token, fields, err := identityhttp.DecodeCSRF(d, r, func(w string) (auth.BearerCredential, error) { calls++; return copyCSRF(w) })
			if err != nil || token.Token() != csrfWire() || calls != 1 || tracked.closes != 0 {
				t.Fatal("valid channel rejected or body ownership changed", err)
			}
			if form {
				if fields.Get("name") != "kept" || fields.Has("csrf_token") || tracked.reads == 0 {
					t.Fatal("form lost application fields or retained credential")
				}
			} else {
				if fields != nil || tracked.reads != 0 {
					t.Fatal("JSON body consumed during credential extraction")
				}
				decoder, _ := identityhttp.NewRequestDecoder(decoderLimits())
				got, err := identityhttp.DecodeJSON[struct {
					Name string `json:"name"`
				}](decoder, r)
				if err != nil || got.Name != "kept" {
					t.Fatal("JSON not usable by owning decoder", err)
				}
			}
		}
	}
}

func TestDecodeCSRFDeniesAmbiguousChannelsBeforeOwnerParser(t *testing.T) {
	d := csrfDecoder(t)
	for name, mutate := range map[string]func(*http.Request){
		"missing":        func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"empty":          func(r *http.Request) { r.Header.Set("X-CSRF-Token", "") },
		"duplicate":      func(r *http.Request) { r.Header.Add("X-CSRF-Token", csrfWire()) },
		"case duplicate": func(r *http.Request) { r.Header["x-csrf-token"] = []string{csrfWire()} },
		"comma":          func(r *http.Request) { r.Header.Set("X-CSRF-Token", csrfWire()+","+csrfWire()) },
		"query": func(r *http.Request) {
			r.URL.RawQuery = "%63srf_Token=" + csrfWire()
			r.RequestURI = r.URL.RequestURI()
		},
		"origin missing":       func(r *http.Request) { r.Header.Del("Origin") },
		"origin null":          func(r *http.Request) { r.Header.Set("Origin", "null") },
		"origin foreign":       func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"safe":                 func(r *http.Request) { r.Method = "GET" },
		"multipart":            func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=x") },
		"bearer cannot bypass": func(r *http.Request) { r.Header.Set("Authorization", "Bearer alternate"); r.Header.Del("X-CSRF-Token") },
	} {
		t.Run(name, func(t *testing.T) {
			r := csrfRequest("POST", "application/json", `{}`)
			r.Header.Set("X-CSRF-Token", csrfWire())
			mutate(r)
			calls := 0
			token, fields, err := identityhttp.DecodeCSRF(d, r, func(w string) (auth.BearerCredential, error) { calls++; return copyCSRF(w) })
			if err == nil || token.Token() != "" || fields != nil || calls != 0 {
				t.Fatal("ambiguous request reached owner or returned partial custody")
			}
		})
	}
	for _, body := range []string{"csrf_token=" + csrfWire(), "CSRF_TOKEN=" + csrfWire(), "csrf_token=" + csrfWire() + "&csrf_token=" + csrfWire(), "csrf_token=" + csrfWire() + "&CSRF_TOKEN=" + csrfWire()} {
		r := csrfRequest("POST", "application/x-www-form-urlencoded", body)
		r.Header.Set("X-CSRF-Token", csrfWire())
		r.Form, r.PostForm = url.Values{"name": {"cached"}}, url.Values{}
		if _, fields, err := identityhttp.DecodeCSRF(d, r, copyCSRF); err == nil || fields != nil {
			t.Fatal("form ambiguity accepted or cached fields trusted")
		}
	}
}

func TestDecodeCSRFRejectsNoncanonicalTokenAndParserErrors(t *testing.T) {
	d := csrfDecoder(t)
	for _, wire := range []string{"", strings.Repeat("A", 42), strings.Repeat("A", 44), csrfWire() + "=", " " + csrfWire(), csrfWire() + " ", strings.Repeat("A", 42) + "B", "+" + strings.Repeat("A", 42), "/" + strings.Repeat("A", 42), "é" + strings.Repeat("A", 41)} {
		r := csrfRequest("POST", "application/json", `{}`)
		r.Header.Set("X-CSRF-Token", wire)
		calls := 0
		got, fields, err := identityhttp.DecodeCSRF(d, r, func(w string) (auth.BearerCredential, error) { calls++; return copyCSRF(w) })
		if err == nil || got.Token() != "" || fields != nil || calls != 0 {
			t.Fatal("noncanonical credential accepted")
		}
	}
	r := csrfRequest("POST", "application/json", `{}`)
	r.Header.Set("X-CSRF-Token", csrfWire())
	got, fields, err := identityhttp.DecodeCSRF(d, r, func(string) (auth.BearerCredential, error) {
		return auth.NewBearerCredential("partial"), errors.New("sensitive owner diagnostic")
	})
	if err == nil || got.Token() != "" || fields != nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("owner failure leaked partial custody or diagnostics")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, fields, err = identityhttp.DecodeCSRF(d, r.WithContext(ctx), copyCSRF)
	if !errors.Is(err, context.Canceled) || got.Token() != "" || fields != nil {
		t.Fatal("cancellation lost or partial input escaped")
	}
}

func TestCSRFDecoderConfigurationAndVariantIsolation(t *testing.T) {
	for _, field := range []string{"", "CSRF_token", "1csrf", "csrf-token", "csrf token", "idempotency_key", "idempotencykey", strings.Repeat("a", 65)} {
		if got, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: originGuard(t, identityhttp.RefererFallbackDeny), FormField: field}); err == nil || got != nil {
			t.Fatal("invalid policy accepted")
		}
	}
	for _, origins := range []*identityhttp.OriginGuard{nil, {}} {
		if got, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"}); err == nil || got != nil {
			t.Fatal("invalid origin owner accepted")
		}
	}
	d := csrfDecoder(t)
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "CONNECT", "post"} {
		r := csrfRequest(method, "application/json", `{}`)
		body := &countedBody{Reader: strings.NewReader(`{}`)}
		r.Body = body
		if got, fields, err := identityhttp.DecodeCSRF(d, r, copyCSRF); err == nil || got.Token() != "" || fields != nil || body.reads != 0 || body.closes != 0 {
			t.Fatal("non-mutation profile consumed input")
		}
	}
	if _, _, err := identityhttp.DecodeCSRF[auth.BearerCredential](d, csrfRequest("POST", "application/json", `{}`), nil); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil owner parser accepted")
	}
	for _, invalid := range []*identityhttp.CSRFDecoder{nil, {}} {
		if _, _, err := identityhttp.DecodeCSRF(invalid, csrfRequest("POST", "application/json", `{}`), copyCSRF); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("zero decoder accepted")
		}
	}
	if _, _, err := identityhttp.DecodeCSRF(d, nil, copyCSRF); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil request accepted")
	}
	// Selecting a different exact form name never enables aliases or defaults.
	custom, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: originGuard(t, identityhttp.RefererFallbackDeny), FormField: "synchronizer"})
	if err != nil {
		t.Fatal(err)
	}
	r := csrfRequest("POST", "application/x-www-form-urlencoded", "synchronizer="+csrfWire()+"&name=kept")
	if got, fields, err := identityhttp.DecodeCSRF(custom, r, copyCSRF); err != nil || got.Token() != csrfWire() || fields.Has("synchronizer") {
		t.Fatal("explicit form selection lost", err)
	}
	for _, field := range []string{"csrf_token", "SYNCHRONIZER", "csrfToken", "x-csrf-token"} {
		r = csrfRequest("POST", "application/x-www-form-urlencoded", field+"="+csrfWire())
		if _, _, err := identityhttp.DecodeCSRF(custom, r, copyCSRF); err == nil {
			t.Fatal("undeclared form channel accepted")
		}
	}
}

func TestDecodeCSRFLimitsCancellationAndOwnership(t *testing.T) {
	d := csrfDecoder(t)
	prefix := "csrf_token=" + csrfWire() + "&name="
	for _, size := range []int{1024, 1025} {
		body := prefix + strings.Repeat("a", size-len(prefix))
		r := csrfRequest("POST", "application/x-www-form-urlencoded", body)
		tracked := &countedBody{Reader: strings.NewReader(body)}
		r.Body = tracked
		got, fields, err := identityhttp.DecodeCSRF(d, r, copyCSRF)
		if (err == nil) != (size == 1024) || tracked.closes != 0 || size == 1025 && (tracked.reads != 0 || got.Token() != "" || fields != nil) {
			t.Fatal("body limit or ownership failed")
		}
	}
	r := csrfRequest("POST", "application/x-www-form-urlencoded", prefix+"kept")
	r.ContentLength = -1
	tracked := &countedBody{Reader: strings.NewReader(prefix + strings.Repeat("a", 2000))}
	r.Body = tracked
	if got, fields, err := identityhttp.DecodeCSRF(d, r, copyCSRF); err == nil || got.Token() != "" || fields != nil || tracked.bytes > 1025 || tracked.closes != 0 {
		t.Fatal("unknown-length body exceeded bound or leaked partial input")
	}
	r = csrfRequest("POST", "application/json", `{}`)
	r.Header.Set("X-CSRF-Token", csrfWire())
	ctx, cancel := context.WithCancel(r.Context())
	got, fields, err := identityhttp.DecodeCSRF(d, r.WithContext(ctx), func(w string) (auth.BearerCredential, error) { cancel(); return copyCSRF(w) })
	if !errors.Is(err, context.Canceled) || got.Token() != "" || fields != nil {
		t.Fatal("owner callback cancellation leaked custody")
	}
	// Shared policy stores no per-request admission or credential state.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := csrfRequest("POST", "application/json", `{}`)
			r.Header.Set("X-CSRF-Token", csrfWire())
			if _, _, err := identityhttp.DecodeCSRF(d, r, copyCSRF); err != nil {
				t.Error("independent request rejected", err)
			}
		}()
	}
	wg.Wait()
}

func FuzzDecodeCSRFChannels(f *testing.F) {
	network, err := identityhttp.NewNetworkResolver(networkConfig())
	if err != nil {
		f.Fatal(err)
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}})
	if err != nil {
		f.Fatal(err)
	}
	d, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(csrfWire(), false)
	f.Add("csrf_token="+csrfWire()+"&name=kept", true)
	f.Add("csrf_token="+csrfWire()+"&CSRF_TOKEN="+csrfWire(), true)
	f.Add("csrf_token=%ff", true)
	f.Add(strings.Repeat("A", 42)+"B", false)
	f.Fuzz(func(t *testing.T, input string, form bool) {
		if len(input) > 2048 {
			return
		}
		media, body := "application/json", `{}`
		if form {
			media, body = "application/x-www-form-urlencoded", input
		}
		r := csrfRequest("POST", media, body)
		if !form {
			r.Header.Set("X-CSRF-Token", input)
		}
		got, fields, err := identityhttp.DecodeCSRF(d, r, copyCSRF)
		if err != nil {
			if got.Token() != "" || fields != nil {
				t.Fatal("partial credential escaped")
			}
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(got.Token())
		if err != nil || len(raw) != 32 || len(got.Token()) != 43 {
			t.Fatal("noncanonical credential admitted")
		}
		if form && fields.Has("csrf_token") {
			t.Fatal("credential remained in domain fields")
		}
	})
}
