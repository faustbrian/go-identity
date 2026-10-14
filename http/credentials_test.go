package identityhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestHeaderIdempotencyCustody(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, raw := range []string{"x", "MiXeD_+-.~", strings.Repeat("x", 256)} {
		r := httptest.NewRequest("POST", "/command", nil)
		r.Header.Set("Idempotency-Key", raw)
		got, present, err := d.IdempotencyKey(r, identityhttp.HeaderRequired)
		want, _ := identity.NewIdempotencyKey([]byte(raw))
		authority := [32]byte{1}
		gotDigest, gotErr := got.Digest(authority)
		wantDigest, _ := want.Digest(authority)
		if err != nil || !present || gotErr != nil || gotDigest != wantDigest {
			t.Fatal("exact header custody not preserved")
		}
	}
	for _, policy := range []identityhttp.HeaderRequirement{identityhttp.HeaderOptional, identityhttp.HeaderForbidden} {
		r := httptest.NewRequest("POST", "/command", nil)
		key, present, err := d.IdempotencyKey(r, policy)
		if err != nil || present || key != (identity.IdempotencyKey{}) {
			t.Fatal("absent optional/forbidden header rejected")
		}
	}
	mutations := []func(*http.Request){
		func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", " x") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "a,b") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", strings.Repeat("x", 257)) },
		func(r *http.Request) { r.Header.Add("Idempotency-Key", "x") },
		func(r *http.Request) { r.Header["idempotency-key"] = []string{"x"} },
		func(r *http.Request) { r.URL.RawQuery = "%69dempotency_key=x"; r.RequestURI = r.URL.RequestURI() },
		func(r *http.Request) { r.Header.Set("Cookie", "other=y; Idempotency-Key=x") },
		func(r *http.Request) { r.Trailer = http.Header{"Idempotency-Key": []string{"x"}} },
	}
	for i, mutate := range mutations {
		r := httptest.NewRequest("POST", "/command", nil)
		r.Header.Set("Idempotency-Key", "x")
		mutate(r)
		key, present, err := d.IdempotencyKey(r, identityhttp.HeaderRequired)
		var invalid identityhttp.DecodeError
		if !errors.As(err, &invalid) || present || key != (identity.IdempotencyKey{}) {
			t.Fatalf("invalid key source accepted at case %d", i)
		}
	}
	r := httptest.NewRequest("POST", "/command", nil)
	r.Header.Set("Idempotency-Key", "x")
	if _, present, err := d.IdempotencyKey(r, identityhttp.HeaderForbidden); err == nil || present {
		t.Fatal("forbidden key accepted")
	}
}

func TestHeaderBearerCustody(t *testing.T) {
	limits := decoderLimits()
	limits.MaximumHeaderBytes = 16384
	d, _ := identityhttp.NewRequestDecoder(limits)
	for _, raw := range []string{"Bearer a.b-c_d~+/==", "bEaReR abc", "Bearer " + strings.Repeat("x", 8192)} {
		r := httptest.NewRequest("POST", "/resource", nil)
		r.Header.Set("Authorization", raw)
		r.Header.Set("Cookie", "session=ignored")
		got, present, err := d.Bearer(r, identityhttp.HeaderRequired)
		_, token, _ := strings.Cut(raw, " ")
		if err != nil || !present || got.Token() != token {
			t.Fatal("valid bearer rejected or altered")
		}
	}
	for _, raw := range []string{"", "Bearer", "Bearer ", "Bearer  abc", "Bearer\tabc", " Bearer abc", "Basic abc", "Bearer abc ", "Bearer a,b", "Bearer a=b", "Bearer =", "Bearer a\x00b", "Bearer é", "Bearer " + strings.Repeat("x", 8193)} {
		r := httptest.NewRequest("POST", "/resource", nil)
		r.Header.Set("Authorization", raw)
		got, present, err := d.Bearer(r, identityhttp.HeaderRequired)
		var invalid identityhttp.DecodeError
		if !errors.As(err, &invalid) || present || got.Token() != "" {
			t.Fatal("malformed bearer accepted or partially returned")
		}
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("Authorization", "Bearer abc") },
		func(r *http.Request) { r.Header["authorization"] = []string{"Bearer abc"} },
		func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer abc") },
		func(r *http.Request) { r.URL.RawQuery = "access_token=abc"; r.RequestURI = r.URL.RequestURI() },
	} {
		r := httptest.NewRequest("POST", "/resource", nil)
		r.Header.Set("Authorization", "Bearer abc")
		mutate(r)
		if got, present, err := d.Bearer(r, identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
			t.Fatal("ambiguous bearer accepted")
		}
	}
	r := httptest.NewRequest("POST", "/resource", nil)
	r.Header.Set("Cookie", "session=abc")
	if got, present, err := d.Bearer(r, identityhttp.HeaderRequired); err == nil || present || got.Token() != "" {
		t.Fatal("cookie substituted for missing bearer")
	}
	if _, present, err := d.Bearer(r, identityhttp.HeaderOptional); err != nil || present {
		t.Fatal("absent optional bearer rejected")
	}
	r.Header.Set("Authorization", "Bearer abc")
	if _, present, err := d.Bearer(r, identityhttp.HeaderForbidden); err == nil || present {
		t.Fatal("bearer issue route accepted authorization")
	}
}

func TestHeaderPolicyCancellationAndOwnership(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	body := &countedBody{Reader: strings.NewReader("unread")}
	r := httptest.NewRequest("POST", "/command", nil)
	r.Body = body
	r.Header.Set("Idempotency-Key", "x")
	if _, present, err := d.IdempotencyKey(r, identityhttp.HeaderOptional); err != nil || !present {
		t.Fatal("valid optional protocol extension rejected")
	}
	if _, _, err := d.IdempotencyKey(r, identityhttp.HeaderRequirement(255)); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("unknown key policy accepted")
	}
	if _, _, err := d.Bearer(r, identityhttp.HeaderRequirement(255)); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("unknown bearer policy accepted")
	}
	var zero identityhttp.RequestDecoder
	if _, _, err := zero.Bearer(r, identityhttp.HeaderOptional); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("zero decoder accepted")
	}
	if _, _, err := d.IdempotencyKey(nil, identityhttp.HeaderOptional); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("nil request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = r.WithContext(ctx)
	if _, present, err := d.IdempotencyKey(r, identityhttp.HeaderRequired); !errors.Is(err, context.Canceled) || present {
		t.Fatal("cancelled key extraction accepted")
	}
	if _, present, err := d.Bearer(r, identityhttp.HeaderRequired); !errors.Is(err, context.Canceled) || present {
		t.Fatal("cancelled bearer extraction accepted")
	}
	if body.reads != 0 || body.closes != 0 {
		t.Fatal("header extraction touched borrowed body")
	}
}

func FuzzHeaderCustody(f *testing.F) {
	for _, seed := range []string{"Bearer abc", "bEaReR a+/==", "Bearer a=b", "Bearer a,b", "Bearer\tabc", "Bearer ", "Bearer é", "x", " a", "Idempotency-Key"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			return
		}
		d, _ := identityhttp.NewRequestDecoder(decoderLimits())
		r := httptest.NewRequest("POST", "/resource", nil)
		r.Header.Set("Authorization", raw)
		credential, present, err := d.Bearer(r, identityhttp.HeaderRequired)
		if err != nil {
			if present || credential.Token() != "" || err.Error() != "identity.http.invalid_request" {
				t.Fatal("bearer error retained partial input or unsafe diagnostics")
			}
		} else if !present || len(raw) < 8 || credential.Token() != raw[7:] {
			t.Fatal("bearer extraction changed bytes")
		}
		r.Header.Del("Authorization")
		r.Header.Set("Idempotency-Key", raw)
		key, present, err := d.IdempotencyKey(r, identityhttp.HeaderRequired)
		if err != nil {
			if present || key != (identity.IdempotencyKey{}) || err.Error() != "identity.http.invalid_request" {
				t.Fatal("key error retained partial input or unsafe diagnostics")
			}
			return
		}
		want, wantErr := identity.NewIdempotencyKey([]byte(raw))
		authority := [32]byte{1}
		gotDigest, digestErr := key.Digest(authority)
		wantDigest, _ := want.Digest(authority)
		if wantErr != nil || digestErr != nil || !present || gotDigest != wantDigest {
			t.Fatal("key extraction changed bytes or bypassed grammar")
		}
	})
}
