//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionvalkey "github.com/faustbrian/go-identity/session/valkey"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type referenceSessionCacheProof struct {
	configuration reference.SessionCacheConfiguration
	fixture       string
	reads         atomic.Int64
}

func TestReferenceSessionValkey(t *testing.T) {
	fixture := os.Getenv("IDENTITY_REFERENCE_SESSION_CACHE_FIXTURE")
	if !filepath.IsAbs(fixture) {
		t.Fatal("explicit owned session cache fixture required")
	}
	read := func(name string, maximum int64) []byte {
		t.Helper()
		file, err := os.Open(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal("owned cache fixture input unavailable")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if err != nil || len(data) == 0 || int64(len(data)) > maximum {
			t.Fatal("invalid bounded cache fixture input")
		}
		return data
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(read("port", 5))))
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("owned loopback cache port required")
	}
	password, err := sessionvalkey.NewSecret(read("password", 4096))
	if err != nil {
		t.Fatal("invalid owned cache credential")
	}
	namespace, err := sessionvalkey.NewSecret(bytes.Repeat([]byte{193}, 32))
	if err != nil {
		t.Fatal(err)
	}
	proof := &referenceSessionCacheProof{fixture: fixture, configuration: reference.SessionCacheConfiguration{
		Codec:  session.EncryptedCacheConfig{Issuer: "deployment", Environment: "reference-test", DeploymentEpoch: 1, KeyReference: "issue-envelope", MaximumAge: 20 * time.Second, MaximumBytes: 32768},
		Valkey: sessionvalkey.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: "rediss://127.0.0.1:" + strconv.Itoa(port), Username: "default", Password: password, NamespaceKey: namespace, Namespace: "reference-session", TrustPEM: read("server.crt", 65536), DeploymentEpoch: 1, MaximumDuration: 3 * time.Second, CacheTimeout: 100 * time.Millisecond, MaximumConcurrent: 4, MaximumScopes: 128, MaximumPayloadBytes: 32768},
	}}
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, sessionCache: proof})
}

func (p *referenceSessionCacheProof) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	// Observe the unchanged native primary lookup, not SQL parameters or secrets.
	if strings.HasPrefix(data.SQL, "SELECT ") && strings.Contains(data.SQL, ".sessions s JOIN ") {
		p.reads.Add(1)
	}
	return ctx
}

func (*referenceSessionCacheProof) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (p *referenceSessionCacheProof) tracePrimary(t *testing.T, ctx context.Context, pool *database.Pool) *database.Pool {
	t.Helper()
	traced, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Tracer = p
		return nil
	}})
	if err != nil {
		t.Fatal("owned primary tracing connection unavailable")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := traced.Close(ctx); err != nil {
			t.Error("owned primary tracing connection cleanup failed")
		}
	})
	return traced
}

func (p *referenceSessionCacheProof) configure(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	if c.Session == nil {
		t.Fatal("cache proof requires genuine session composition")
	}
	c.Session.Cache = &p.configuration
}

func (p *referenceSessionCacheProof) prove(t *testing.T, ctx context.Context, c reference.StoreConfiguration, dependencies reference.ReferenceDependencies, stores reference.StoreSet, features reference.FeatureSet, client *http.Client, base, origin string, user identity.UserID, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	owner, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := c.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	var token session.Token
	for _, cookie := range cookies {
		if cookie.Name == attributes.Name {
			token, err = session.ParseToken(cookie.Value)
		}
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal("genuine signin did not deliver usable credential custody")
	}
	request := session.GetRequest{TenantID: otpTenant, Credential: credential}
	before := p.reads.Load()
	first, err := owner.Get(ctx, request)
	if err != nil || !first.Authenticated || first.ValidateAt(time.Now()) != nil || p.reads.Load() <= before {
		t.Fatal("first cache read did not obtain genuine primary admission", err)
	}
	readHTTP := func(cookies []*http.Cookie) bool {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, "GET", base+"/v1/session/get", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("actual cache-selected HTTP read failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		var result sessionhttp.GetResponse
		if err != nil || closed != nil || response.StatusCode != 200 || len(body) > 16384 || json.Unmarshal(body, &result) != nil {
			t.Fatal("actual cache-selected HTTP response unavailable or malformed")
		}
		if result.Authenticated && (result.Principal == nil || result.Principal.UserID != user || string(result.Principal.TenantID) != otpTenant) || !result.Authenticated && (result.Principal != nil || result.Session != nil) {
			t.Fatal("cached response changed tenant/subject or disclosed denied identity")
		}
		return result.Authenticated
	}
	before = p.reads.Load()
	if !readHTTP(cookies) || p.reads.Load() != before {
		t.Fatal("warm HTTP read did not use the configured cache projection")
	}
	logout := func(csrf string) int {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, "POST", base+"/v1/session/signout", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("actual primary logout failed")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		var result sessionhttp.SignOutResponse
		if err != nil || closed != nil || len(body) > 16384 || json.Unmarshal(body, &result) != nil {
			t.Fatal("actual logout response cleanup/shape")
		}
		if response.StatusCode == 200 && (!result.SignedOut || result.CommitOutcome != "committed") {
			t.Fatal("logout did not commit the actual native revocation")
		}
		return response.StatusCode
	}
	wrong, _ := session.NewCSRFToken()
	wrongWire, _ := wrong.Reveal()
	if logout(wrongWire) != 403 || !readHTTP(cookies) {
		t.Fatal("cache selection weakened protected logout CSRF")
	}
	if logout(csrf) != 200 {
		t.Fatal("selected cache did not retain genuine primary logout")
	}
	// Deliberately omit invalidation delivery: the committed primary is revoked,
	// but ordinary cached metadata may live only until its ORIGINAL deadline.
	before = p.reads.Load()
	if !readHTTP(cookies) || p.reads.Load() != before {
		t.Fatal("lost-invalidation fixture did not retain its warm cache entry")
	}
	again, err := owner.Get(ctx, request)
	if err != nil || !again.Authenticated || !again.ValidUntil().Equal(first.ValidUntil()) {
		t.Fatal("cache promotion renewed original validity", err)
	}
	timer := time.NewTimer(time.Until(first.ValidUntil()) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("original cache deadline was not observed before journey budget")
	case <-timer.C:
	}
	before = p.reads.Load()
	if readHTTP(cookies) || p.reads.Load() <= before {
		t.Fatal("expired cache did not deny actual revoked primary authority")
	}
	freshCookies, _ := fresh()
	if err := os.WriteFile(filepath.Join(p.fixture, "pause"), []byte("pause"), 0600); err != nil {
		t.Fatal("owned outage request failed")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(p.fixture, "paused")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("cache outage fixture canceled")
		case <-deadline.C:
			t.Fatal("owned cache outage not established")
		case <-tick.C:
		}
	}
	before = p.reads.Load()
	if !readHTTP(freshCookies) || p.reads.Load() <= before {
		t.Fatal("cache outage did not use actual healthy primary admission")
	}
	closeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := stores.Close(closeContext); err != nil {
		t.Fatal("selected cache graph did not close", err)
	}
	if _, err := owner.Get(ctx, request); err == nil {
		t.Fatal("retained cached handle survived graph shutdown")
	}
	if err := dependencies.PostgreSQL.Raw().Ping(ctx); err != nil {
		t.Fatal("graph closed the borrowed primary pool")
	}
}
