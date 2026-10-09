package identityhttp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func metadataConfig(t *testing.T) identityhttp.MetadataConfig {
	t.Helper()
	rate, _, _ := safeLimiter(t)
	return identityhttp.MetadataConfig{Public: true, Network: networkConfig(), Rate: rate, MaximumDuration: time.Second}
}

func TestMetadataRequestBoundariesAndRateAreEnforced(t *testing.T) {
	config := metadataConfig(t)
	h, doc, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, config, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"post", func(r *http.Request) { r.Method = "POST" }, 405},
		{"head", func(r *http.Request) { r.Method = "HEAD" }, 405},
		{"case", func(r *http.Request) { r.URL.Path = "/Openapi.json"; r.RequestURI = r.URL.Path }, 404},
		{"slash", func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.Path }, 404},
		{"escaped", func(r *http.Request) { r.URL.RawPath = "/%6fpenapi.json"; r.RequestURI = r.URL.EscapedPath() }, 404},
		{"query", func(r *http.Request) { r.URL.RawQuery = "private=sentinel"; r.RequestURI += "?private=sentinel" }, 400},
		{"bare query", func(r *http.Request) { r.URL.ForceQuery = true; r.RequestURI += "?" }, 400},
		{"body", func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, 400},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"Secret": []string{"sentinel"}} }, 400},
		{"retry key case", func(r *http.Request) { r.Header["idempotency-key"] = []string{"sentinel"} }, 400},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sentinel") }, 400},
		{"proxy auth", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer sentinel") }, 400},
		{"unknown host", func(r *http.Request) { r.Host = "private.invalid" }, 421},
		{"http", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }, 400},
		{"oversize headers", func(r *http.Request) { r.Header.Set("X-Extra", strings.Repeat("a", 65537)) }, 400},
		{"canceled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := metadataRequest()
			test.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || bytes.Contains(w.Body.Bytes(), []byte("sentinel")) || bytes.Contains(w.Body.Bytes(), []byte("private.invalid")) {
				t.Fatalf("unsafe denial: %d", w.Code)
			}
			if r.Method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD error body")
			}
			if test.status == 405 && w.Header().Get("Allow") != "GET" {
				t.Fatal("wrong allowed methods")
			}
		})
	}
	// Malformed requests above must not consume any of the actual primitive's
	// 100-token shared IP budget. Ambient cookies never select another document.
	for i := 0; i < 100; i++ {
		r := metadataRequest()
		r.Header.Set("Cookie", "unrelated=sentinel")
		r.Header.Set("Forwarded", "for=192.0.2.1;host=private.invalid;proto=http")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), doc.JSON()) {
			t.Fatalf("premature debit or request-derived snapshot at%d: %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, metadataRequest())
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || bytes.Contains(w.Body.Bytes(), []byte("openapi")) {
		t.Fatal("rate budget bypass", w.Code)
	}
	config.Rate.Close()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, metadataRequest())
	if w.Code != 503 {
		t.Fatal("closed owner admitted", w.Code)
	}
}

func TestMetadataConstructionAndDirectExportFailClosed(t *testing.T) {
	for _, change := range []func(*identityhttp.MetadataConfig){
		func(c *identityhttp.MetadataConfig) { c.Public = false },
		func(c *identityhttp.MetadataConfig) { c.Rate = nil },
		func(c *identityhttp.MetadataConfig) { c.MaximumDuration = 0 },
		func(c *identityhttp.MetadataConfig) { c.Network.PublicHosts = []string{"*.invalid"} },
	} {
		c := metadataConfig(t)
		change(&c)
		h, d, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, c, identityhttp.FeatureServices{})
		if err == nil || h != nil || len(d.JSON()) != 0 {
			t.Fatal("partial invalid construction")
		}
	}
	op := extensionDescriptor(t, "metadata", "collision")
	op.Record.Path = "/openapi.json"
	op.Route.Path = op.Record.Path
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OperationID + `","responses":{"200":{"description":"collision"}}}`)}
	f := feature(t, "metadata", nil, op)
	h, d, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, metadataConfig(t), identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err == nil || h != nil || len(d.JSON()) != 0 {
		t.Fatal("export route collision admitted")
	}
	var zero identityhttp.OpenAPIDocument
	if result, err := zero.OpenapiDocument(context.Background(), identityhttp.OpenapiDocumentRequest{}); err == nil || len(result.Document.JSON()) != 0 || result.Digest != [32]byte{} {
		t.Fatal("zero exported")
	}
	_, d, err = identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := d.OpenapiDocument(ctx, identityhttp.OpenapiDocumentRequest{}); !errors.Is(err, context.Canceled) || len(result.Document.JSON()) != 0 {
		t.Fatal("canceled direct export")
	}
	if _, err := d.OpenapiDocument(nil, identityhttp.OpenapiDocumentRequest{}); err == nil {
		t.Fatal("nil context exported")
	}
}

func TestMetadataSelectedSnapshotAndCoverageAreDeterministicAndConcurrent(t *testing.T) {
	checks := 0
	probes, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{State: func() identityhttp.ServerState { return identityhttp.ServerRunning }, Timeout: time.Second, Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
		checks++
		return identityhttp.ReadinessSnapshot{Ready: true}, nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	op := extensionDescriptor(t, "metadata", "read")
	op.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + op.Record.OperationID + `","responses":{"204":{"description":"no content"}}}`)}
	extension := feature(t, "metadata", nil, op)
	selection := identityhttp.FeatureServices{Features: []identityhttp.Feature{probes, extension}}
	config := metadataConfig(t)
	h, d, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, config, selection)
	if err != nil {
		t.Fatal(err)
	}
	selection.Features[0], selection.Features[1] = selection.Features[1], selection.Features[0]
	_, repeat, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, config, selection)
	if err != nil || !bytes.Equal(d.JSON(), repeat.JSON()) || !bytes.Equal(d.CoverageJSON(), repeat.CoverageJSON()) || checks != 0 {
		t.Fatal("export reordered input or invoked feature")
	}
	selected := 0
	for _, row := range d.Coverage() {
		if row.Status == identityhttp.CoverageSelectedRouted {
			selected++
			if row.RegisteredOperationID != row.OperationID {
				t.Fatal("bad selected attribution")
			}
			if row.OperationID == op.Record.OperationID && !row.Extension {
				t.Fatal("extension unattributed")
			}
		}
	}
	if selected != 4 || len(d.Coverage()) != 330 {
		t.Fatal("selection report mismatched", selected)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(op.Route.Method, op.Route.Path, nil))
	if w.Code != 204 {
		t.Fatal("actual extension not dispatched")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("actual probe not dispatched")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			rows := d.Coverage()
			rows[0].OperationID = "mutated"
			raw := d.JSON()
			raw[0] = '!'
			report := d.CoverageJSON()
			report[0] = '!'
			w := httptest.NewRecorder()
			h.ServeHTTP(w, metadataRequest())
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), repeat.JSON()) || !bytes.Equal(d.CoverageJSON(), repeat.CoverageJSON()) {
				t.Error("mutable concurrent snapshot")
			}
		})
	}
	wg.Wait()
}

func metadataRequest() *http.Request {
	r := httptest.NewRequest("GET", "https://login.example/openapi.json", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	r.RequestURI = "/openapi.json"
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestMetadataExportIsExplicitAndDescribesItself(t *testing.T) {
	config := identityhttp.DocumentConfig{Title: "Identity", Version: "1"}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), config, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	off.ServeHTTP(w, metadataRequest())
	if w.Code != 404 || bytes.Contains(offDoc.JSON(), []byte("/openapi.json")) {
		t.Fatal("implicit metadata exposure")
	}
	h, doc, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), config, metadataConfig(t), identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, metadataRequest())
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), doc.JSON()) || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("not exact safe snapshot", w.Code)
	}
	if sha256.Sum256(w.Body.Bytes()) != doc.Digest() {
		t.Fatal("wrong snapshot digest")
	}
	var raw struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Paths) != 1 || raw.Paths["/openapi.json"]["get"].OperationID != "identity.openapi.document" || len(doc.Operations()) != 1 {
		t.Fatal("export not in own selection")
	}
	result, err := doc.OpenapiDocument(context.Background(), identityhttp.OpenapiDocumentRequest{})
	if err != nil || result.Digest != doc.Digest() || !bytes.Equal(result.Document.JSON(), doc.JSON()) {
		t.Fatal("direct export differs")
	}
}

func TestDocumentCoverageRetainsCanonicalObligationsWithoutAdvertisingThem(t *testing.T) {
	_, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Operations []struct{ ID, Exposure string }
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	rows := doc.Coverage()
	if len(rows) != len(inventory.Operations) {
		t.Fatal("canonical rows lost")
	}
	want := map[string]string{}
	for _, row := range inventory.Operations {
		want[row.ID] = row.Exposure
	}
	for i, row := range rows {
		if i > 0 && rows[i-1].OperationID >= row.OperationID {
			t.Fatal("not unique sorted coverage")
		}
		if _, ok := want[row.OperationID]; !ok || row.RegisteredOperationID != "" || row.Extension {
			t.Fatal("invented selected coverage")
		}
		wantExposure := map[string]identityhttp.Exposure{"both": identityhttp.ExposureBoth, "protocol": identityhttp.ExposureProtocol, "direct": identityhttp.ExposureDirect, "middleware": identityhttp.ExposureMiddleware}[want[row.OperationID]]
		if row.Exposure != wantExposure {
			t.Fatal("canonical transport disposition lost")
		}
		delete(want, row.OperationID)
		switch row.OperationID {
		case "identity.platform.bootstrap-administrator":
			if row.Status != identityhttp.CoverageDirectOnly {
				t.Fatal("bootstrap routed")
			}
		case "identity.oauth-server.device-token":
			if row.Status != identityhttp.CoverageSharedVariantUnavailable {
				t.Fatal("unproven shared variant")
			}
		case "identity.openapi.document":
			if row.Status != identityhttp.CoverageUnselectedRouted {
				t.Fatal("disabled export advertised")
			}
		}
	}
	if len(want) != 0 {
		t.Fatal("missing canonical operations")
	}
	before := doc.CoverageJSON()
	rows[0].OperationID = "mutated"
	if !bytes.Equal(before, doc.CoverageJSON()) || !json.Valid(before) {
		t.Fatal("report alias")
	}
	if bytes.Contains(doc.JSON(), []byte("bootstrap-administrator")) {
		t.Fatal("baseline obligations advertised as routes")
	}
}

func TestMetadataUnknownRateDeniesAndKnownOutageUsesBoundedEmergencyPolicy(t *testing.T) {
	events := 0
	rate, backend, _ := safeLimiterSize(t, 1024, func(c *identityhttp.SafeRateConfig) {
		c.Degraded = func(ctx context.Context, e identityhttp.SafeRateEvent) error {
			if _, ok := ctx.Deadline(); !ok || e.OperationID != "identity.openapi.document" {
				t.Error("unbounded or misattributed fallback")
			}
			events++
			return nil
		}
	})
	c := metadataConfig(t)
	c.Rate = rate
	h, _, err := identityhttp.NewDocumentedMetadataHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, c, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	backend.mode.Store(2)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, metadataRequest())
	if w.Code != 503 || events != 0 {
		t.Fatal("unknown rate outcome became fallback authority")
	}
	backend.mode.Store(1)
	for i := 0; i < 25; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, metadataRequest())
		want := 200
		if i >= 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("emergency budget at%d: %d", i, w.Code)
		}
	}
	if events != 25 {
		t.Fatal("fallback decisions not attributed")
	}
}
