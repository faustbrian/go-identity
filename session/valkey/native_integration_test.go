//go:build integration

package sessionvalkey_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	native "github.com/faustbrian/go-identity/session/postgres"
	cache "github.com/faustbrian/go-identity/session/valkey"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	valkey "github.com/valkey-io/valkey-go"
)

type trustedClock struct{ nanos atomic.Int64 }

func (c *trustedClock) Now() time.Time    { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *trustedClock) set(now time.Time) { c.nanos.Store(now.UnixNano()) }

type history []migrations.Migration

func (h history) Load(context.Context) ([]migrations.Migration, error) {
	return append(history(nil), h...), nil
}

// This fixture installs official immutable migrations with the owned Runner,
// seeds primary projections, then gets private custody only through the real
// native primary reader. It is not a SessionReader double or issuance proof.
func primaryFixture(t *testing.T, ctx context.Context) (*database.Pool, *session.SessionService, *session.EncryptedCacheCodec, session.GetRequest, *trustedClock, session.DigestKey, session.Credential) {
	t.Helper()
	dsn := os.Getenv("SESSION_VALKEY_POSTGRES_DSN")
	parsed, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || parsed.Host != "127.0.0.1" || parsed.Database != "session_valkey_test" {
		t.Fatal("explicit isolated loopback session_valkey_test required")
	}
	db := stdlib.OpenDB(*parsed)
	t.Cleanup(func() { _ = db.Close() })
	source := kernel.DirectoryAuthorityMigrationSource{Base: kernel.IdentifierNormalizationMigrationSource{Base: kernel.IdentifierMutationMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "cache-deployment", TenantIDs: []identity.TenantID{"tenant-a"}}
	all, err := source.Load(ctx)
	if err != nil {
		t.Fatal("kernel migration source", err)
	}
	child, err := (native.MigrationSource{Schema: "session_store", Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, child...)
	policy, err := authority.AuthoritySchemaMigration(16)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := migrations.NewMigration(16, policy.Name, migrations.TransactionModeDefault, policy.Up, policy.Down)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, pm)
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(history(all), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("official migration runner", err)
	}
	pool, err := database.New(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("isolated primary unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if e := pool.Close(cleanup); e != nil {
			t.Error("primary cleanup failed")
		}
	})
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1); INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','user-a','password',1,'identity/password',1,true)`); err != nil {
		t.Fatal(err)
	}
	policyScope := authority.AuthorityScope{TenantID: "tenant-a", PolicyNamespace: "users", SubjectID: "user-a"}
	if _, err = authority.InitializeAuthority(ctx, pool.Raw(), policyScope, time.Second); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := &trustedClock{}
	clock.set(now)
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := credential.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	kk, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "cache-deployment", TenantID: "tenant-a"}, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := native.SessionAuthorityKeys("tenant-a", "user-a", "family-a", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	pk, err := policyScope.Key()
	if err != nil {
		t.Fatal(err)
	}
	b := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
	auth, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(kk.Global), Tenant: b(kk.Tenant), User: b(kk.User), Identifier: b(kk.Identifier), Credential: b(kk.Credential), SessionFamily: b(sk.Family), Session: b(sk.Session), Authorization: b(pk)})
	if err != nil {
		t.Fatal(err)
	}
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "service-a", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
	spec := session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "service-a", Version: 1, FamilyVersion: 1, Remember: remember, Authority: auth, Lookup: lookup, Authentication: metadata, IssuedAt: now, LastActivityAt: now}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	lifetime, err := record.Lifetime(now)
	if err != nil {
		t.Fatal(err)
	}
	rp, _ := remember.Bindings()
	ap, _ := auth.Bindings()
	// Schema-1 native record fixture: no private admission, ciphertext or bearer.
	payload, err := json.Marshal(struct {
		Schema                   uint32
		SessionID, FamilyID      string
		TenantID                 identity.TenantID
		UserID                   identity.UserID
		Audience                 string
		Version, FamilyVersion   uint64
		Remember                 session.RememberPolicySpec
		Authority                session.AuthoritySnapshotSpec
		Lookup                   session.TokenDigest
		Authentication           session.AuthenticationMetadata
		IssuedAt, LastActivityAt time.Time
	}{1, spec.SessionID, spec.FamilyID, spec.TenantID, spec.UserID, spec.Audience, 1, 1, rp, ap, lookup, metadata, now, now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES('tenant-a','family-a','user-a',1,'active',$1)`, now.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('tenant-a','session-a','user-a','family-a',1,1,'active',$1,$2,$3,$4)`, int64(lookup.KeyVersion), lookup.Sum[:], lifetime.ExpiresAt.Format("2006-01-02T15:04:05.000000000Z"), payload); err != nil {
		t.Fatal(err)
	}
	service, err := native.NewSessionService(pool, native.SessionServiceConfig{Repository: native.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: native.IdentifierAdmissionConfig{GlobalAuthorityID: "cache-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"cache-v1": bytes.Repeat([]byte{13}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewEncryptedCacheCodec(service, crypto, session.EncryptedCacheConfig{Issuer: "issuer", Environment: "integration", DeploymentEpoch: 1, KeyReference: "cache-v1", MaximumAge: 20 * time.Second, MaximumBytes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return pool, service, codec, session.GetRequest{TenantID: "tenant-a", Credential: credential}, clock, key, cookie
}

func TestNativeTLSValkey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pool, primary, codec, request, clock, key, cookie := primaryFixture(t, ctx)
	ca, err := os.ReadFile(os.Getenv("SESSION_VALKEY_CA_FILE"))
	if err != nil {
		t.Fatal("explicit TLS CA required")
	}
	password, err := os.ReadFile(os.Getenv("SESSION_VALKEY_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("explicit TLS password required")
	}
	secret, err := cache.NewSecret(password)
	if err != nil {
		t.Fatal(err)
	}
	namespaceKey, err := cache.NewSecret(bytes.Repeat([]byte{99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := cache.Config{Profile: "positive-cache", Topology: "standalone", Endpoint: os.Getenv("SESSION_VALKEY_ENDPOINT"), Username: "default", Password: secret, Namespace: "native-integration", NamespaceKey: namespaceKey, TrustPEM: ca, DeploymentEpoch: 1, LookupKeys: []session.DigestKey{key}, MaximumDuration: 2 * time.Second, CacheTimeout: 300 * time.Millisecond, MaximumConcurrent: 4, MaximumScopes: 2, MaximumPayloadBytes: 32768}
	if got, e := cache.New(ctx, config, nil, clock); got != nil || e == nil {
		t.Fatal("nil codec accepted")
	}
	if got, e := cache.New(ctx, config, codec, nil); got != nil || e == nil {
		t.Fatal("nil clock accepted")
	}
	var absentClock *trustedClock
	if got, e := cache.New(ctx, config, codec, absentClock); got != nil || e == nil {
		t.Fatal("typed nil clock accepted")
	}
	if got, e := cache.New(nil, config, codec, clock); got != nil || e == nil {
		t.Fatal("nil constructor context accepted")
	}
	for _, change := range []func(*cache.Config){
		func(c *cache.Config) { c.Profile = "authoritative" }, func(c *cache.Config) { c.Topology = "cluster" }, func(c *cache.Config) { c.Endpoint = "redis://localhost:6379" }, func(c *cache.Config) { c.Endpoint = "rediss://user:password@localhost:6379" }, func(c *cache.Config) { c.TrustPEM = []byte("not a certificate") }, func(c *cache.Config) { c.LookupKeys = []session.DigestKey{{}} }, func(c *cache.Config) { c.LookupKeys = []session.DigestKey{key, key} }, func(c *cache.Config) { c.MaximumPayloadBytes = 32769 }, func(c *cache.Config) { c.MaximumScopes = 4097 }, func(c *cache.Config) { c.CacheTimeout = c.MaximumDuration },
	} {
		bad := config
		change(&bad)
		if got, e := cache.New(ctx, bad, codec, clock); got != nil || e == nil {
			t.Fatal("malformed profile accepted")
		}
	}
	wrongHost := config
	wrongHost.Endpoint = strings.Replace(config.Endpoint, "localhost", "127.0.0.1", 1)
	if got, e := cache.New(ctx, wrongHost, codec, clock); e == nil || got != nil {
		t.Fatal("TLS hostname verification bypassed")
	}
	wrongPassword := config
	wrongPassword.Password, _ = cache.NewSecret(bytes.Repeat([]byte{7}, 32))
	if got, e := cache.New(ctx, wrongPassword, codec, clock); got != nil || e == nil {
		t.Fatal("wrong TLS server credential accepted")
	}
	c, err := cache.New(ctx, config, codec, clock)
	if err != nil {
		t.Fatal("real TLS construction", err)
	}
	defer c.Close()
	positive, err := c.Get(ctx, request)
	if err != nil || !positive.Authenticated || positive.ValidateAt(clock.Now()) != nil {
		t.Fatal("native admission/fill", err)
	}
	original := positive.ValidUntil()
	if original.Sub(clock.Now()) > 20*time.Second {
		t.Fatal("freshness exceeded original twenty seconds")
	}
	setActive := func(active bool) {
		t.Helper()
		state := "revoked"
		if active {
			state = "active"
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.families SET state=$1`, state); e != nil {
			t.Fatal(e)
		}
	}
	denied := func(c *cache.Cache, request session.GetRequest) {
		t.Helper()
		got, e := c.Get(ctx, request)
		if e == nil && got.Authenticated {
			t.Fatal("cache granted withdrawn/foreign authority")
		}
	}
	checkpoint, err := c.Checkpoint(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	setActive(false)
	if got, e := primary.Get(ctx, request); e != nil || got.Authenticated {
		t.Fatal("fixture did not withdraw actual primary", e)
	}
	clock.set(clock.Now().Add(2 * time.Second))
	hit, err := c.Get(ctx, request)
	if err != nil || !hit.Authenticated || !hit.ValidUntil().Equal(original) {
		t.Fatal("cache hit renewed/lost original admission", err)
	}
	restarted, err := cache.New(ctx, config, codec, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	hit, err = restarted.Get(ctx, request)
	if err != nil || !hit.Authenticated || !hit.ValidUntil().Equal(original) {
		t.Fatal("adapter restart renewed evidence", err)
	}
	foreign := request
	foreign.TenantID = "tenant-b"
	denied(c, foreign)
	otherToken, _ := session.NewToken(32)
	foreign = request
	foreign.Credential, _ = session.NewCredential(session.CredentialBearer, otherToken)
	denied(c, foreign)
	foreign = request
	foreign.Credential = cookie
	denied(c, foreign)
	for _, change := range []func(*cache.Config){func(c *cache.Config) { c.Namespace = "other" }, func(c *cache.Config) { c.DeploymentEpoch++ }, func(c *cache.Config) { c.NamespaceKey, _ = cache.NewSecret(bytes.Repeat([]byte{101}, 32)) }} {
		isolated := config
		change(&isolated)
		foreignCache, e := cache.New(ctx, isolated, codec, clock)
		if e != nil {
			t.Fatal(e)
		}
		denied(foreignCache, request)
		if filled, e := foreignCache.Fill(ctx, checkpoint, positive); e == nil || filled {
			t.Fatal("foreign cache accepted checkpoint custody")
		}
		foreignCache.Close()
	}
	if err = c.Invalidate(ctx, "tenant-a", "session-a"); err != nil {
		t.Fatal(err)
	}
	if filled, e := c.Fill(ctx, checkpoint, positive); e != nil || filled {
		t.Fatal("stale first-fill won exact invalidation", e)
	}
	denied(c, request)
	setActive(true)
	positive, err = c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal("primary miss fallback", err)
	}
	checkpoint, err = c.Checkpoint(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	setActive(false)
	var wg sync.WaitGroup
	var fillErr, invalidateErr error
	wg.Add(2)
	go func() { defer wg.Done(); _, fillErr = c.Fill(ctx, checkpoint, positive) }()
	go func() { defer wg.Done(); invalidateErr = c.InvalidateFamily(ctx, "tenant-a", "family-a") }()
	wg.Wait()
	if fillErr != nil || invalidateErr != nil {
		t.Fatal("bounded concurrent fill/invalidation", fillErr, invalidateErr)
	}
	denied(c, request)
	// Capacity reset is conservative; it must not resurrect earlier generations.
	if err = c.Invalidate(ctx, "tenant-a", "other-session"); err != nil {
		t.Fatal(err)
	}
	if err = c.InvalidateFamily(ctx, "tenant-a", "other-family"); err != nil {
		t.Fatal(err)
	}
	if filled, e := c.Fill(ctx, checkpoint, positive); e != nil || filled {
		t.Fatal("capacity reset resurrected checkpoint", e)
	}
	setActive(true)
	positive, err = c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal(err)
	}
	// A real server flush loses markers; an old checkpoint cannot recreate them.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	control, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("SESSION_VALKEY_ADDRESS")}, Username: "default", Password: string(password), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots}, ForceSingleClient: true, DisableCache: true, DisableRetry: true})
	if err != nil {
		t.Fatal("fixture control unavailable")
	}
	defer control.Close()
	storedKeys, e := control.Do(ctx, control.B().Keys().Pattern("session-positive-v1:*").Build()).AsStrSlice()
	if e != nil || len(storedKeys) > 32 {
		t.Fatal("fixture cache namespace inspection failed")
	}
	seenEnvelope := false
	for _, key := range storedKeys {
		if strings.Contains(key, "tenant-a") || strings.Contains(key, "session-a") || strings.Contains(key, "family-a") {
			t.Fatal("plaintext scope entered keyspace")
		}
		fields, e := control.Do(ctx, control.B().Hgetall().Key(key).Build()).AsStrMap()
		if e != nil {
			t.Fatal("fixture entry inspection failed")
		}
		if blob, ok := fields["blob"]; ok {
			seenEnvelope = true
			if len(blob) == 0 || len(blob) > 32768 {
				t.Fatal("payload bound changed")
			}
			if _, e = envelope.ParseEnvelope([]byte(blob)); e != nil {
				t.Fatal("entry was not an owned encrypted envelope")
			}
			ttl, e := control.Do(ctx, control.B().Pttl().Key(key).Build()).ToInt64()
			if e != nil || ttl <= 0 || ttl > positive.ValidUntil().Sub(clock.Now()).Milliseconds() {
				t.Fatal("physical TTL exceeded original remaining evidence")
			}
		}
	}
	if !seenEnvelope {
		t.Fatal("no genuine encrypted fill persisted")
	}
	if err = control.Do(ctx, control.B().Arbitrary("ACL").Args("SETUSER", "default", "-info").Build()).Error(); err != nil {
		t.Fatal("fixture ACL change", err)
	}
	if _, e := c.Checkpoint(ctx, request); e == nil {
		t.Fatal("missing script INFO permission accepted")
	}
	if got, e := c.Get(ctx, request); e != nil || !got.Authenticated {
		t.Fatal("ACL denial did not use healthy primary", e)
	}
	if err = control.Do(ctx, control.B().Arbitrary("ACL").Args("SETUSER", "default", "+info").Build()).Error(); err != nil {
		t.Fatal("fixture ACL restoration", err)
	}
	checkpoint, err = c.Checkpoint(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err = control.Do(ctx, control.B().Flushdb().Build()).Error(); err != nil {
		t.Fatal("real flush", err)
	}
	if filled, e := c.Fill(ctx, checkpoint, positive); e != nil || filled {
		t.Fatal("flush recreated old marker", e)
	}
	positive, err = c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal("flush did not use healthy primary", err)
	}
	// The harness restarts the exact isolated server after SAVE. Persisted
	// ciphertext/markers are deliberately restored; server run_id must invalidate
	// them atomically rather than trusting a restored process-generation marker.
	checkpoint, err = c.Checkpoint(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	setActive(false)
	if err = control.Do(ctx, control.B().Save().Build()).Error(); err != nil {
		t.Fatal("fixture SAVE", err)
	}
	restartDir := os.Getenv("SESSION_VALKEY_RESTART_DIR")
	if restartDir == "" {
		t.Fatal("explicit owned restart handshake directory required")
	}
	if err = os.WriteFile(filepath.Join(restartDir, "ready"), []byte("restart persisted fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, e := os.Stat(filepath.Join(restartDir, "restarted")); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture restart handshake timed out")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if filled, e := c.Fill(ctx, checkpoint, positive); e != nil || filled {
		t.Fatal("server restart restored old checkpoint", e)
	}
	denied(c, request)
	setActive(true)
	positive, err = c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal("restart miss did not use primary", err)
	}
	control.Close()
	control, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{os.Getenv("SESSION_VALKEY_ADDRESS")}, Username: "default", Password: string(password), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots}, ForceSingleClient: true, DisableCache: true, DisableRetry: true})
	if err != nil {
		t.Fatal("restarted fixture control unavailable")
	}
	defer control.Close()
	// A real server pause exceeds the cache budget; the request still uses the
	// existing healthy primary and cannot turn timeout into a stale allow.
	if err = control.Do(ctx, control.B().Arbitrary("CLIENT").Args("PAUSE", "800", "ALL").Build()).Error(); err != nil {
		t.Fatal("fixture pause", err)
	}
	if got, e := c.Get(ctx, request); e != nil || !got.Authenticated {
		t.Fatal("cache timeout did not use healthy primary", e)
	}
	setActive(false)
	clock.set(positive.ValidUntil())
	denied(c, request)
	// The original <=20s ceiling denies even when every invalidation is lost.
	if clock.Now().Sub(original) > 30*time.Second {
		t.Fatal("fixture exceeded denial budget")
	}
	setActive(true)
	positive, err = c.Get(ctx, request)
	if err != nil || !positive.Authenticated {
		t.Fatal(err)
	}
	if err = pool.Close(ctx); err != nil {
		t.Fatal("primary outage setup failed")
	}
	hit, err = c.Get(ctx, request)
	if err != nil || !hit.Authenticated || !hit.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("primary outage lost still-valid encrypted hit", err)
	}
	clock.set(positive.ValidUntil())
	denied(c, request)
}
