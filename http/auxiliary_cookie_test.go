package identityhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestAuxiliaryCookieBearerPreservesSeparateAuthorization(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	r := httptest.NewRequest("POST", "/verify", nil)
	r.Header.Set("Authorization", "Bearer primary-original")
	r.Header.Set("Cookie", "__Host-device=aux-original; other=safe")
	body := &countedBody{Reader: strings.NewReader("unread")}
	r.Body = body
	got, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired)
	if err != nil || !present || got.Token() != "aux-original" || r.Header.Get("Authorization") != "Bearer primary-original" || r.Header.Get("Cookie") != "__Host-device=aux-original; other=safe" || body.reads != 0 || body.closes != 0 {
		t.Fatal("auxiliary custody changed primary/header/body")
	}
	if original, present, err := d.CookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present || original.Token() != "" {
		t.Fatal("cookie credential exclusivity weakened")
	}
	// Syntactic primary custody is required; it is still not authentication.
	r.Header.Set("Authorization", "malformed")
	if _, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present {
		t.Fatal("malformed primary accepted")
	}
}

func TestAuxiliaryCookieBearerRequiresOriginalSolePrimary(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Authorization") },
		func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") },
		func(r *http.Request) { r.Header["authorization"] = []string{"Bearer other"} },
		func(r *http.Request) { r.Header.Set("Authorization", "") },
		func(r *http.Request) { r.URL.RawQuery = "access_token=other" },
		func(r *http.Request) { r.Header.Add("Cookie", "__Host-device=other") },
		func(r *http.Request) { r.Header["cookie"] = []string{"__Host-device=other"} },
	} {
		r := httptest.NewRequest("POST", "/verify", nil)
		r.Header.Set("Authorization", "Bearer original")
		r.Header.Set("Cookie", "__Host-device=abc")
		mutate(r)
		if got, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
			t.Fatal("ambiguous original custody accepted")
		}
	}
}

func FuzzAuxiliaryCookieBearerBoundedCustody(f *testing.F) {
	for _, seed := range []string{"__Host-device=abc", "__Host-device=abc; __Host-device=other", "__Host-device=", "other=bad value", ""} {
		f.Add(seed)
	}
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 32768 {
			return
		}
		r := httptest.NewRequest("POST", "/verify", nil)
		r.Header.Set("Authorization", "Bearer original")
		r.Header.Set("Cookie", raw)
		got, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderOptional)
		if err != nil || !present {
			if present || got.Token() != "" {
				t.Fatal("partial custody on error or absence")
			}
		} else if got.Token() == "" || len(got.Token()) > 3800 || len(raw) > 16384 {
			t.Fatal("resource bounds escaped")
		}
		if r.Header.Get("Authorization") != "Bearer original" || r.Header.Get("Cookie") != raw {
			t.Fatal("original headers changed")
		}
	})
}

func TestAuxiliaryCookieBearerRejectsAmbiguousMalformedAndCanceledCustody(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, raw := range []string{"", "__Host-device=", "__Host-device=abc; __Host-device=def", `__Host-device="abc"`, "__Host-device=abc ", "other=bad value; __Host-device=abc", "__Host-device=" + strings.Repeat("x", 3800), strings.Repeat("x=y;", 32) + "__Host-device=abc"} {
		r := httptest.NewRequest("POST", "/verify", nil)
		r.Header.Set("Authorization", "Bearer primary-original")
		r.Header.Set("Cookie", raw)
		if got, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
			t.Fatal("malformed auxiliary custody accepted")
		}
	}
	r := httptest.NewRequest("POST", "/verify", nil)
	r.Header.Set("Authorization", "Bearer primary-original")
	r.Header.Set("Cookie", "__Host-device=abc")
	r.Header.Set("Proxy-Authorization", "Bearer proxy")
	if _, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present {
		t.Fatal("proxy credential accepted")
	}
	r.Header.Del("Proxy-Authorization")
	r.URL.RawQuery = "__Host-device=other"
	if _, present, err := d.AuxiliaryCookieBearer(r, "__Host-device", identityhttp.HeaderRequired); err == nil || present {
		t.Fatal("query alternative accepted")
	}
	r.URL.RawQuery = ""
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	if got, present, err := d.AuxiliaryCookieBearer(r.WithContext(ctx), "__Host-device", identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
		t.Fatal("canceled custody escaped")
	}
}
