package identityhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCookieBearerPreservesExactSelectedCustody(t *testing.T) {
	limits := decoderLimits()
	limits.MaximumHeaderBytes = 32768
	d, _ := identityhttp.NewRequestDecoder(limits)
	for _, raw := range []string{"a.b-c_d~+/==", strings.Repeat("x", 3700)} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header["cookie"] = []string{`other="safe"; __Host-flow=` + raw}
		got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired)
		if err != nil || !present || got.Token() != raw {
			t.Fatal("original cookie changed or rejected")
		}
	}
	for _, policy := range []identityhttp.HeaderRequirement{identityhttp.HeaderOptional, identityhttp.HeaderForbidden} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Cookie", "__host-flow=other")
		got, present, err := d.CookieBearer(r, "__Host-flow", policy)
		if err != nil || present || got.Token() != "" {
			t.Fatal("cookie names are not exact or absent rejected")
		}
	}
	for _, raw := range []string{"", "other", "other=bad value", "other=\"unterminated", "=value", "__Host-flow=", `__Host-flow="abc"`, "__Host-flow=abc; __Host-flow=def", "__Host-flow=abc,def", "__Host-flow=a=b", "__Host-flow==", "__Host-flow=" + strings.Repeat("x", 3800), "__Host-flow=abc;", "__Host-flow=abc ", "__Host-flow=abc\t", "__Host-flow=abc ; other=safe", "__Host-flow=abc\t; other=safe", "other=bad ; __Host-flow=abc", "other=bad\t; __Host-flow=abc", "__Host-flow=abc; other=bad ", "__Host-flow=abc; other=bad\t"} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Cookie", raw)
		got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired)
		var invalid identityhttp.DecodeError
		if !errors.As(err, &invalid) || present || got.Token() != "" {
			t.Fatal("malformed cookie escaped or partially returned")
		}
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header["cookie"] = []string{"__Host-flow=def"} },
		func(r *http.Request) { r.Header.Add("Cookie", "__Host-flow=def") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") },
		func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer abc") },
		func(r *http.Request) { r.URL.RawQuery = "__Host-flow=abc"; r.RequestURI = r.URL.RequestURI() },
		func(r *http.Request) { r.Header.Add("Cookie", strings.Repeat("x=y;", 32)+"z=y") },
		func(r *http.Request) { r.Header.Add("Cookie", "other="+strings.Repeat("x", 16384)) },
	} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Cookie", "__Host-flow=abc")
		mutate(r)
		if got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
			t.Fatal("ambiguous or over-limit credential accepted")
		}
	}
	r := httptest.NewRequest("POST", "/login", nil)
	r.Header.Set("Cookie", "__Host-flow=abc")
	if got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderForbidden); err == nil || present || got.Token() != "" {
		t.Fatal("forbidden cookie accepted")
	}
}

func TestCookieBearerRequiresValidOwnerAndDoesNotReadBody(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	body := &countedBody{Reader: strings.NewReader("unread")}
	r := httptest.NewRequest("POST", "/login", nil)
	r.Body = body
	r.Header.Set("Cookie", "__Host-flow=abc")
	if _, _, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "bad name", "bad=name", strings.Repeat("x", 129)} {
		if _, _, err := d.CookieBearer(r, name, identityhttp.HeaderRequired); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid selected cookie name accepted")
		}
	}
	if _, _, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequirement(255)); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("invalid policy accepted")
	}
	var zero identityhttp.RequestDecoder
	if _, _, err := zero.CookieBearer(r, "__Host-flow", identityhttp.HeaderOptional); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("zero owner accepted")
	}
	if _, _, err := d.CookieBearer(nil, "__Host-flow", identityhttp.HeaderOptional); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil request accepted")
	}
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	if got, present, err := d.CookieBearer(r.WithContext(ctx), "__Host-flow", identityhttp.HeaderRequired); !errors.Is(err, context.Canceled) || present || got.Token() != "" {
		t.Fatal("canceled extraction returned custody")
	}
	if body.reads != 0 || body.closes != 0 {
		t.Fatal("borrowed body consumed")
	}
}

func TestCookieBearerAggregateLimitsAndAbsentRequired(t *testing.T) {
	limits := decoderLimits()
	limits.MaximumHeaderBytes = 32768
	d, _ := identityhttp.NewRequestDecoder(limits)
	for _, count := range []int{31, 32} {
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header.Set("Cookie", strings.Repeat("x=y;", count-1)+"__Host-flow=abc")
		if _, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err != nil || !present {
			t.Fatal("in-bound parts rejected")
		}
	}
	r := httptest.NewRequest("POST", "/login", nil)
	if got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
		t.Fatal("missing required cookie accepted")
	}
	r.Header["Cookie"] = nil
	if _, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderOptional); err == nil || present {
		t.Fatal("empty represented header accepted")
	}
	r.Header["Cookie"] = []string{"__Host-flow=abc", "other=" + strings.Repeat("x", 16384-len("__Host-flow=abc")-len("other="))}
	if _, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err != nil || !present {
		t.Fatal("exact aggregate byte ceiling rejected")
	}
	r.Header["Cookie"][1] += "x"
	if _, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderRequired); err == nil || present {
		t.Fatal("aggregate ceiling plus one accepted")
	}
}

func FuzzCookieBearerBoundedAtomicCustody(f *testing.F) {
	for _, seed := range []string{"__Host-flow=abc", `other="safe"; __Host-flow=a-b_==`, "__Host-flow=abc; __Host-flow=def", "__Host-flow=\x00", "", "x=y;"} {
		f.Add(seed)
	}
	limits := decoderLimits()
	limits.MaximumHeaderBytes = 32768
	d, _ := identityhttp.NewRequestDecoder(limits)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 32768 {
			return
		}
		r := httptest.NewRequest("POST", "/login", nil)
		r.Header["Cookie"] = []string{raw}
		got, present, err := d.CookieBearer(r, "__Host-flow", identityhttp.HeaderOptional)
		if err != nil || !present {
			if got.Token() != "" || present {
				t.Fatal("error/absence retained credential custody")
			}
			return
		}
		if len(got.Token()) == 0 || len(got.Token()) > 3800 || len(raw) > 16384 {
			t.Fatal("successful custody violates resource bounds")
		}
	})
}
