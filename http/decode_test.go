package identityhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

type countedBody struct {
	io.Reader
	reads, bytes, closes int
}

func (b *countedBody) Read(p []byte) (int, error) {
	b.reads++
	n, err := b.Reader.Read(p)
	b.bytes += n
	return n, err
}
func (b *countedBody) Close() error { b.closes++; return nil }

func decoderLimits() identityhttp.Limits {
	return identityhttp.Limits{MaximumHeaderBytes: 1024, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 10, MaximumDepth: 4}
}

func TestDecodeJSONAtomic(t *testing.T) {
	d, err := identityhttp.NewRequestDecoder(decoderLimits())
	if err != nil {
		t.Fatal(err)
	}
	type input struct {
		Name  string `json:"name"`
		Items []int  `json:"items"`
	}
	r := httptest.NewRequest("POST", "/input", strings.NewReader(`{"name":"sample","items":[1,2]}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	got, err := identityhttp.DecodeJSON[input](d, r)
	if err != nil || got.Name != "sample" || len(got.Items) != 2 {
		t.Fatal("valid typed JSON rejected", err)
	}
	for _, body := range []string{
		`{"name":"first","name":"second"}`, `{"name":"first","\u006eame":"second"}`,
		`{"name":"first","Name":"second"}`, `{"items":[1],"unknown":2}`,
		`{"name":"\ud800"}`, `{"name":"\udc00"}`, `{"name":"x"} {}`,
		`{"items":[01]}`, `{"name":"x","items":[1,"invalid"]}`, `null`, `[]`, ``,
	} {
		r := httptest.NewRequest("POST", "/input", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		got, err := identityhttp.DecodeJSON[input](d, r)
		var decode identityhttp.DecodeError
		if !errors.As(err, &decode) || got.Name != "" || got.Items != nil {
			t.Fatal("invalid JSON accepted or partial result escaped")
		}
	}
}

func TestDecodeFormAndQueryStaySeparate(t *testing.T) {
	d, err := identityhttp.NewRequestDecoder(decoderLimits())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/input?state=query", strings.NewReader("state=body&value=a%2Bb+c"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form, err := d.Form(r)
	if err != nil || form.Get("state") != "body" || form.Get("value") != "a+b c" {
		t.Fatal("form rejected or merged with query", err)
	}
	query, err := d.Query(r)
	if err != nil || query.Get("state") != "query" || len(query) != 1 {
		t.Fatal("query changed by form", err)
	}
	for _, raw := range []string{"state=one&state=two", "state=one&%73tate=two", "State=one&state=two", "a=%ff", "a=%", "a=%0x", "=value", "a=one;two", "a=1&", "&a=1", "idempotency_key=retry"} {
		r := httptest.NewRequest("POST", "/input", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		form, err := d.Form(r)
		var decode identityhttp.DecodeError
		if !errors.As(err, &decode) || form != nil {
			t.Fatal("ambiguous form accepted or partial result escaped")
		}
	}
}

func TestDecodeEnvelopeRejectsBeforeReading(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header["content-type"] = []string{"application/json"} },
		func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") },
		func(r *http.Request) { r.Header.Set("Content-Length", "3") },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Trailer = http.Header{"X-Late": []string{"value"}} },
		func(r *http.Request) { r.Header.Set("X-Big", strings.Repeat("x", 1024)) },
		func(r *http.Request) { r.RequestURI = "/" + strings.Repeat("x", 1024) },
		func(r *http.Request) { r.Header.Set("Host", "other.example"); r.Host = "example.com" },
	} {
		r := httptest.NewRequest("POST", "/input", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		body := &countedBody{Reader: r.Body}
		r.Body = body
		change(r)
		_, err := identityhttp.DecodeJSON[struct{}](d, r)
		var decode identityhttp.DecodeError
		if !errors.As(err, &decode) || body.reads != 0 || body.closes != 0 {
			t.Fatal("bad envelope read body or was accepted")
		}
	}
}

func TestDecodeCancellationAndBodyOwnership(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/input", strings.NewReader(`{}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	body := &countedBody{Reader: r.Body}
	r.Body = body
	if _, err := identityhttp.DecodeJSON[struct{}](d, r); !errors.Is(err, context.Canceled) || body.reads != 0 || body.closes != 0 {
		t.Fatal("cancellation lost or body consumed")
	}
	r = httptest.NewRequest("POST", "/input", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	body = &countedBody{Reader: r.Body}
	r.Body = body
	if _, err := identityhttp.DecodeJSON[struct{}](d, r); err != nil || body.bytes != 2 || body.closes != 0 {
		t.Fatal("body ownership changed", err)
	}
}

func TestDecodeLimits(t *testing.T) {
	setters := []struct {
		min, max uint64
		set      func(*identityhttp.Limits, uint64)
	}{
		{1024, 65536, func(l *identityhttp.Limits, v uint64) { l.MaximumHeaderBytes = uint32(v) }},
		{1024, 8192, func(l *identityhttp.Limits, v uint64) { l.MaximumURLBytes = uint32(v) }},
		{1024, 1048576, func(l *identityhttp.Limits, v uint64) { l.MaximumBodyBytes = v }},
		{1024, 1048576, func(l *identityhttp.Limits, v uint64) { l.MaximumDecodedBytes = v }},
		{1, 1000, func(l *identityhttp.Limits, v uint64) { l.MaximumFields = uint32(v) }},
		{1, 32, func(l *identityhttp.Limits, v uint64) { l.MaximumDepth = uint32(v) }},
	}
	for _, s := range setters {
		for _, value := range []uint64{0, s.min - 1, s.min, s.max, s.max + 1, uint64(^uint32(0))} {
			limits := decoderLimits()
			s.set(&limits, value)
			d, err := identityhttp.NewRequestDecoder(limits)
			valid := value >= s.min && value <= s.max
			if valid && (err != nil || d == nil) || !valid && (err != identityhttp.ErrInvalidInput || d != nil) {
				t.Fatal("configuration boundary misclassified")
			}
		}
	}
}

func TestDecodeResourceBoundaries(t *testing.T) {
	limits := decoderLimits()
	limits.MaximumBodyBytes = 4096
	d, _ := identityhttp.NewRequestDecoder(limits)
	for _, size := range []int{1023, 1024} {
		body := `{"a":"` + strings.Repeat("x", size) + `"}`
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		_, err := identityhttp.DecodeJSON[map[string]string](d, r)
		if (err == nil) != (size == 1023) {
			t.Fatal("decoded key/value boundary not enforced")
		}
	}
	limits = decoderLimits()
	limits.MaximumFields = 3
	limits.MaximumDepth = 2
	d, _ = identityhttp.NewRequestDecoder(limits)
	for _, test := range []struct {
		body  string
		valid bool
	}{
		{`{"items":[1,2]}`, true}, {`{"items":[1,2,3]}`, false},
		{`{"items":[[]]}`, false}, {`{"a":{"b":1}}`, true},
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		_, err := identityhttp.DecodeJSON[map[string]json.RawMessage](d, r)
		if (err == nil) != test.valid {
			t.Fatal("global field/depth boundary misclassified")
		}
	}
	for _, size := range []int{1024, 1025} {
		r := httptest.NewRequest("POST", "/", nil)
		r.ContentLength = -1
		r.Header.Set("Content-Type", "application/json")
		body := &countedBody{Reader: strings.NewReader(strings.Repeat(" ", size-2) + `{}`)}
		r.Body = body
		_, err := identityhttp.DecodeJSON[struct{}](d, r)
		if (err == nil) != (size == 1024) || body.bytes > 1025 || body.closes != 0 {
			t.Fatal("raw byte limit/ownership violated")
		}
	}
}

type failingDecodeReader struct{}

func (failingDecodeReader) Read([]byte) (int, error) { return 0, errors.New("private-reader-canary") }

func TestDecodeFramingAndReaderFailures(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, length := range []int64{1, 3, 1025} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.ContentLength = length
		r.Header.Set("Content-Type", "application/json")
		_, err := identityhttp.DecodeJSON[struct{}](d, r)
		var decode identityhttp.DecodeError
		if !errors.As(err, &decode) {
			t.Fatal("length mismatch accepted")
		}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.ContentLength = -1
	r.Body = &countedBody{Reader: failingDecodeReader{}}
	r.Header.Set("Content-Type", "application/json")
	_, err := identityhttp.DecodeJSON[struct{}](d, r)
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("reader diagnostic escaped")
	}
}

func TestDecodeHeaderAndURLByteBoundaries(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	for _, extra := range []int{0, 1} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		// final CRLF + represented Host + Content-Type + X-Pad name/framing.
		used := 2 + len(r.Host) + 8 + len("Content-Type") + len("application/json") + 4 + len("X-Pad") + 4
		r.Header.Set("X-Pad", strings.Repeat("x", 1024-used+extra))
		_, err := identityhttp.DecodeJSON[struct{}](d, r)
		if (err == nil) != (extra == 0) {
			t.Fatal("header byte limit misclassified")
		}
		r = httptest.NewRequest("POST", "/"+strings.Repeat("x", 1023+extra), strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		_, err = identityhttp.DecodeJSON[struct{}](d, r)
		if (err == nil) != (extra == 0) {
			t.Fatal("URL byte limit misclassified")
		}
	}
}

func TestDecodeConcurrentIsolation(t *testing.T) {
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				r := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"safe"}`))
				r.Header.Set("Content-Type", "application/json")
				value, err := identityhttp.DecodeJSON[struct {
					Value string `json:"value"`
				}](d, r)
				if err != nil || value.Value != "safe" {
					t.Error("decoder request state leaked")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzDecodeJSON(f *testing.F) {
	for _, seed := range []string{`{}`, `{"a":1}`, `{"a":1,"\u0061":2}`, `{"a":"\ud800"}`, `{"a":[[[[]]]]}`, `null`, "{\"a\":\"\xff\"}"} {
		f.Add(seed)
	}
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		value, err := identityhttp.DecodeJSON[map[string]json.RawMessage](d, r)
		if err == nil && (!json.Valid([]byte(raw)) || len(raw) > 1024 || value == nil) {
			t.Fatal("invalid/oversized document accepted")
		}
		if err != nil && err.Error() != "identity.http.invalid_request" {
			t.Fatal("unexpected diagnostic")
		}
	})
}

func FuzzDecodeForm(f *testing.F) {
	for _, seed := range []string{"", "a=b", "a=1&a=2", "a=%ff", "a=%", "a=%0d%0a", "idempotency-key=x", "a=1&"} {
		f.Add(seed)
	}
	d, _ := identityhttp.NewRequestDecoder(decoderLimits())
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			t.Skip()
		}
		r := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		value, err := d.Form(r)
		if err == nil && (len(raw) > 1024 || value == nil || len(value) > 10) {
			t.Fatal("oversized form accepted")
		}
		if err != nil && err.Error() != "identity.http.invalid_request" {
			t.Fatal("unexpected diagnostic")
		}
	})
}
