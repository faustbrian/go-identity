//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

type oauthProxyProductionPreviewAuthentication struct {
	authenticated authentication.Result
}

func (a oauthProxyProductionPreviewAuthentication) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Result{}, err
	}
	bearer, ok := credential.(authentication.BearerCredential)
	if !ok || bearer.Token() != "synthetic-production-preview-invocation" {
		return authentication.Result{}, authentication.ErrCredentialsRejected
	}
	return a.authenticated, nil
}

func TestReferencePostgresOAuthProxyProductionDenial(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, true, true)
	_, c := oauthProxyProductionConfiguration(t)
	installOAuthProxyProductionFixture(t, ctx, f, c)

	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{
		Subject: string(c.Start.Preview.ActorID), Method: "bearer", Issuer: c.Start.Preview.Issuer,
		Audiences: []string{c.Start.Preview.Audience}, Scopes: []string{"identity.oauth.proxy-start"}, AuthenticatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal("construct authenticated preview principal", err)
	}
	authenticated, err := authentication.NewAuthenticatedResult(principal)
	if err != nil {
		t.Fatal("construct authenticated preview result", err)
	}
	c.Start.Preview.Authentication = oauthProxyProductionPreviewAuthentication{authenticated: authenticated}
	profile := c.Start.Provider.Profile()
	var providerDials atomic.Int32
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: profile.ID, Version: profile.Version, Issuer: profile.Issuer, AuthorizationEndpoint: profile.AuthorizationEndpoint,
		TokenEndpoint: profile.TokenEndpoint, RedirectURI: profile.RedirectURI, ClientID: profile.ClientID,
		ClientAuthentication: oauth.PublicClient, Scopes: profile.Scopes, Algorithms: profile.Algorithms,
		KeySet: oauthProxyProductionRejectKeySet{}, Clock: clock.System{}, Timeout: time.Second,
		HTTPClient: &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			providerDials.Add(1)
			return nil, errors.New("provider denial must not contact the token endpoint")
		}}},
	})
	if err != nil {
		t.Fatal("construct controlled external provider boundary", err)
	}
	t.Cleanup(provider.Close)
	c.Start.Provider = provider
	c.HTTP = oauthProxyProductionHTTPConfiguration(t, f.pool)
	owner, err := reference.NewOAuthProxyProduction(f.pool, c)
	if err != nil {
		t.Fatal("construct public production owner", err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.PersistentSession, AbsoluteTTL: 37 * time.Hour, IdleTTL: 71 * time.Minute,
		RefreshAfter: 13 * time.Minute, FreshFor: 29 * time.Minute,
	})
	if err != nil {
		t.Fatal("resolve original remember policy", err)
	}
	request := oauthproxy.InitiationRequest{
		Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"), CommandID: command,
		TransactionID: transaction, RequestFingerprint: sha256.Sum256([]byte("synthetic-production-preview-request")), Remember: remember,
	}
	result, err := owner.Start(ctx, request)
	if err != nil {
		t.Fatal("commit fresh public production initiation", err)
	}
	authorization, ok := result.Authorization()
	if !ok {
		t.Fatal("fresh committed initiation withheld provider authorization")
	}
	bound, ok := result.Binding()
	if !ok {
		t.Fatal("fresh committed initiation withheld preview binding")
	}
	parsed, err := url.Parse(authorization.URL())
	if err != nil {
		t.Fatal("parse committed provider authorization", err)
	}
	query := parsed.Query()
	parsed.RawQuery = ""
	if parsed.String() != profile.AuthorizationEndpoint || query.Get("redirect_uri") != profile.RedirectURI ||
		query.Get("client_id") != profile.ClientID || query.Get("response_type") != "code" || query.Get("response_mode") != "query" ||
		query.Get("code_challenge_method") != "S256" || query.Get("scope") != strings.Join(profile.Scopes, " ") || len(query) != 9 {
		t.Fatal("public initiation changed configured provider authorization")
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(query.Get(name))
		if err != nil || len(decoded) != 32 || len(query[name]) != 1 {
			t.Fatalf("authorization %s is not one canonical 32-byte value", name)
		}
		clear(decoded)
	}
	target := c.Start.Preview.Target
	if bound.TenantID != c.Start.Preview.TenantID || bound.CommandID != command || bound.TransactionID != transaction ||
		bound.RequestFingerprint != request.RequestFingerprint || bound.Remember != remember ||
		bound.ProductionDeployment != c.Native.ProductionDeployment || bound.PreviewDeployment != target.Deployment ||
		bound.PreviewOrigin != target.Origin || bound.PreviewRedirect != target.Redirect || bound.Recipient != target.Recipient ||
		bound.ProviderID != profile.ID || bound.ProviderVersion != profile.Version || bound.Issuer != profile.Issuer || bound.ClientID != profile.ClientID ||
		bound.ClaimsProfile != c.Start.ClaimsProfile || bound.ClaimsVersion != c.Start.ClaimsVersion || bound.ExpiresAt.Sub(bound.IssuedAt) != c.Start.StateLifetime ||
		bound.StateDigest != sha256.Sum256([]byte(query.Get("state"))) || bound.PKCEChallengeDigest != sha256.Sum256([]byte(query.Get("code_challenge"))) {
		t.Fatal("public initiation lost original preview, provider, command or browser bindings")
	}
	var callbackID []byte
	if err := f.pool.Raw().QueryRow(ctx, `SELECT callback_command_id FROM synthetic_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2 AND version=1 AND outcome IS NULL`, string(bound.TenantID), string(transaction)).Scan(&callbackID); err != nil {
		t.Fatal("native initiation did not persist original callback custody", err)
	}
	callbackCommand := base64.RawURLEncoding.EncodeToString(callbackID)
	if callbackCommand == string(command) {
		t.Fatal("native initiation reused the origin command for callback settlement")
	}
	server := httptest.NewTLSServer(owner.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	denial := url.Values{"error": {"access_denied"}, "state": {query.Get("state")}, "iss": {profile.Issuer}}.Encode()
	var firstSettlement time.Time
	for attempt := range 2 {
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/oauth2/callback/proxy?"+denial, nil)
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Host = "production.example"
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatal("invoke actual production TLS handler", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
		closeErr := response.Body.Close()
		var denied struct {
			Error string `json:"error"`
		}
		if readErr != nil || closeErr != nil || len(body) > 1024 || json.Unmarshal(body, &denied) != nil ||
			response.StatusCode != http.StatusForbidden || denied.Error != "denied" ||
			len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Location") != "" {
			t.Fatalf("callback attempt %d did not return only a closed provider denial: status %d", attempt, response.StatusCode)
		}
		var settled, conserved bool
		var settledAt time.Time
		err = f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT version=2 AND outcome=2 AND handoff_ciphertext IS NULL AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL FROM synthetic_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT settled_at FROM synthetic_oauth.proxy_transactions WHERE tenant_id=$1 AND transaction_id=$2),
 (SELECT count(*)=1 AND bool_and(state='finalized' AND uses=1 AND command_id=$4 AND origin_command_id=$5 AND purpose='identity.oauth.proxy-forward') FROM public.capability_identity_one_use) AND
 (SELECT count(*)=2 AND bool_and(state='committed' AND preparation_ciphertext IS NULL) FROM identity.commands) AND
 (SELECT count(*)=1 FROM audit.identity_command_bindings WHERE command_id=$3) AND
 (SELECT count(*)=1 FROM audit.records WHERE action='identity.oauth.use_proxy') AND
 (SELECT count(*)=1 FROM public.identity_outbox_bindings WHERE command_id=$3) AND
 (SELECT count(*)=0 FROM identity.users) AND
 to_regclass('identity.accounts') IS NULL AND to_regclass('session_store.sessions') IS NULL`,
			string(bound.TenantID), string(transaction), callbackID, callbackCommand, string(command)).Scan(&settled, &settledAt, &conserved)
		if err != nil || !settled || !conserved || settledAt.IsZero() || attempt == 1 && !settledAt.Equal(firstSettlement) {
			t.Fatalf("callback attempt %d lost once-only committed denial, spent capability or original settlement: %v", attempt, err)
		}
		firstSettlement = settledAt
	}
	if providerDials.Load() != 0 {
		t.Fatal("provider denial contacted the external token endpoint")
	}
}

func installOAuthProxyProductionFixture(t *testing.T, ctx context.Context, f liveStores, c reference.OAuthProxyProductionConfiguration, reuseAudit ...bool) {
	t.Helper()
	var source migrations.Source = kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 10,
		GlobalAuthorityID: c.Native.GlobalAuthorityID, TenantIDs: []identity.TenantID{c.Start.Preview.TenantID}}
	source = kernel.RequestKeyMigrationSource{Base: source, Version: 11}
	source = kernel.RequestKeyPreparationMigrationSource{Base: source, Version: 12}
	source = kernel.RequestKeyExpiryMigrationSource{Base: source, Version: 13}
	source = kernel.PreparationMigrationSource{Base: source, Version: 14}
	source = kernel.AdmissionPreparationMigrationSource{Base: source, Version: 15}
	source = kernel.CounterPreparationMigrationSource{Base: source, Version: 16}
	source = kernel.OAuthProxyForwardPreparationErasureMigrationSource{Base: source, Version: 17}
	source = kernel.OAuthProxyStartPreparationErasureMigrationSource{Base: source, Version: 18}
	history, err := source.Load(ctx)
	if err != nil {
		t.Fatal("load native production kernel histories", err)
	}
	additional := make([]migrations.Migration, 0, len(history))
	for _, migration := range history {
		if migration.Version() > 9 {
			additional = append(additional, migration)
		}
	}
	history = additional
	for _, owner := range []migrations.Source{
		oauthpg.MigrationSource{Schema: c.Native.Schema, Version: 40},
		oauthpg.ProxyTransactionMigrationSource{Schema: c.Native.Schema, Version: 41},
		riskpg.DurableCounterMigrationSource{Schema: "risk_store", Version: 42},
	} {
		owned, err := owner.Load(ctx)
		if err != nil {
			t.Fatal("load native production owner history", err)
		}
		history = append(history, owned...)
	}
	for _, files := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations(), capabilitypg.Migrations()} {
		owner, err := migrations.NewFSSource(fixtureMigrationFiles{files}, ".")
		if err != nil {
			t.Fatal(err)
		}
		owned, err := owner.Load(ctx)
		if err != nil {
			t.Fatal("load immutable native participant history", err)
		}
		history = append(history, owned...)
	}
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("begin production fixture owner installation", err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = tx.Rollback(bounded)
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=public,pg_catalog; SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s'`); err != nil {
		t.Fatal(err)
	}
	// Distinct disposable databases in the same test can use the roles the
	// preview fixture already owns. This never changes the product preflight.
	sharedAudit := len(reuseAudit) == 1 && reuseAudit[0]
	if sharedAudit {
		var roles int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&roles); err != nil || roles != 3 {
			t.Fatal("preview fixture did not provision its three audit roles", err)
		}
	} else if _, err := tx.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal("reserve fixture-owned fresh audit roles", err)
	}
	for _, migration := range history {
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("install native production fixture history", migration.Name(), err)
		}
	}
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := tx.Exec(ctx, migration.Up); err != nil {
			t.Fatal("install native HTTP rate history", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit production fixture owner histories", err)
	}
	if sharedAudit {
		return
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, "DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
			t.Error("release fixture-owned production audit roles", err)
		}
	})
}
