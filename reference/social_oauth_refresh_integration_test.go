//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

func TestReferenceNativeStoredProviderRefresh(t *testing.T) {
	for _, mode := range []string{"rotation", "rejection", "ambiguous", "concurrent", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
				postgresBaseline: true, socialProviderRefresh: mode,
			}, true)
		})
	}
}

type referenceProviderRefreshFixture struct {
	provider  *oauth.OAuth2UserInfoProvider
	challenge atomic.Pointer[string]
	sends     atomic.Int32
	mode      string
	entered   chan struct{}
	release   chan struct{}
	unblock   sync.Once
}

func configureReferenceProviderRefresh(t *testing.T, c *reference.StoreConfiguration, origin, mode string) *referenceProviderRefreshFixture {
	t.Helper()
	f := &referenceProviderRefreshFixture{mode: mode}
	if mode == "concurrent" {
		f.entered, f.release = make(chan struct{}), make(chan struct{})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	if f.release != nil {
		t.Cleanup(f.releaseFirstExchange)
	}
	provider, err := oauth.NewOAuth2UserInfoProvider(oauth.OAuth2UserInfoConfig{
		ID: "refresh-fixture", Version: 1, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize",
		TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/userinfo",
		RedirectURI: origin + "/v1/oauth/callback", ClientID: "refresh-fixture-client",
		ClientAuthentication: oauth.ClientSecretPost, ClientSecret: []byte("synthetic-refresh-fixture"),
		Scopes: []string{"read", "write"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject,
		HTTPClient: server.Client(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal("construct controlled TLS provider", err)
	}
	t.Cleanup(provider.Close)
	f.provider = provider
	configureReferenceSocialLink(t, c, origin, provider)
	return f
}

func (f *referenceProviderRefreshFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/userinfo" && r.Method == http.MethodGet && r.Header.Get("Authorization") == "Bearer fixture-initial-access":
		_, _ = io.WriteString(w, `{"id":42}`)
	case r.URL.Path == "/token" && r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != "refresh-fixture-client" ||
			r.PostForm.Get("client_secret") != "synthetic-refresh-fixture" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			proof := f.challenge.Swap(nil)
			digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if proof != nil && *proof == base64.RawURLEncoding.EncodeToString(digest[:]) &&
				r.PostForm.Get("code") == "fixture-public-code" && r.PostForm.Get("redirect_uri") == f.provider.Profile().RedirectURI {
				_, _ = io.WriteString(w, `{"access_token":"fixture-initial-access","refresh_token":"fixture-first-refresh","token_type":"Bearer","expires_in":600,"scope":"read write"}`)
				return
			}
		case "refresh_token":
			n := f.sends.Add(1)
			want := "fixture-first-refresh"
			if n > 1 {
				want = "fixture-next-refresh"
			}
			if r.PostForm.Get("refresh_token") != want || r.PostForm.Has("scope") {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if f.entered != nil && n == 1 {
				close(f.entered)
				select {
				case <-f.release:
				case <-r.Context().Done():
					return
				}
			}
			switch f.mode {
			case "ambiguous":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "rejection":
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			default:
				_, _ = io.WriteString(w, `{"access_token":"fixture-successor-access","refresh_token":"fixture-next-refresh","token_type":"Bearer","expires_in":120,"scope":"read"}`)
			}
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *referenceProviderRefreshFixture) releaseFirstExchange() {
	f.unblock.Do(func() { close(f.release) })
}

func runReferenceProviderRefreshRace(t *testing.T, ctx context.Context, f *referenceProviderRefreshFixture, refresh *oauthpg.ProviderRefreshService, request oauthpg.ProviderRefreshRequest) (oauthpg.ProviderRefreshResult, error) {
	t.Helper()
	type attempt struct {
		result oauthpg.ProviderRefreshResult
		err    error
	}
	done := make(chan attempt, 1)
	go func() {
		result, err := refresh.Refresh(ctx, request)
		done <- attempt{result, err}
	}()
	defer f.releaseFirstExchange()
	select {
	case <-f.entered:
	case early := <-done:
		t.Fatalf("first attempt ended before entering the provider: %T %v", early.err, early.err)
	case <-ctx.Done():
		t.Fatal("first attempt did not reach the provider within the test deadline")
	}
	var pending identity.UnknownCommitError
	if duplicate, err := refresh.Refresh(ctx, request); !errors.As(err, &pending) || pending.CommandID == "" || duplicate != (oauthpg.ProviderRefreshResult{}) || f.sends.Load() != 1 {
		t.Fatalf("a simultaneous original retry was not fenced: %T %v", err, err)
	}
	f.releaseFirstExchange()
	select {
	case first := <-done:
		if first.result.CommandID != pending.CommandID {
			t.Fatal("concurrent attempts did not share the same original command")
		}
		return first.result, first.err
	case <-ctx.Done():
		t.Fatal("first attempt did not return after releasing the provider")
		return oauthpg.ProviderRefreshResult{}, ctx.Err()
	}
}

func installReferenceProviderRefreshHistory(t *testing.T, ctx context.Context, d reference.ReferenceDependencies, schema string) {
	t.Helper()
	unlink := kernel.AccountUnlinkPreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 2405}
	validation := kernel.AccountUnlinkPreparationValidationMigrationSource{Base: unlink, Version: 2406}
	sources := []struct {
		src migrations.Source
		min migrations.Version
	}{
		{kernel.OAuthProviderRefreshErasureMigrationSource{Base: validation, Version: 2407}, 2405},
		{oauthpg.TokenVaultOptionalExpiryMigrationSource{Schema: schema, Version: 3}, 3},
		{oauthpg.ProviderRefreshReceiptMigrationSource{Schema: schema, Version: 5}, 5},
	}
	for _, selected := range sources {
		history, err := selected.src.Load(ctx)
		if err != nil {
			t.Fatal("load exact refresh consumer history", err)
		}
		for _, step := range history {
			if step.Version() >= selected.min {
				tx, err := d.PostgreSQL.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, step.UpSQL()); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatalf("install refresh history %d: %v", step.Version(), err)
				}
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func proveReferenceProviderRefresh(t *testing.T, ctx context.Context, c reference.StoreConfiguration, d reference.ReferenceDependencies, f *referenceProviderRefreshFixture, user identity.UserID, cookies []*http.Cookie, wireCSRF string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	n := *c.SocialOAuth
	installReferenceProviderRefreshHistory(t, ctx, d, n.Schema)
	validation := c.Session.Native.Validation
	validation.Clock = c.Session.Native.Execution.Clock
	link, err := oauthpg.NewLinkService(d.PostgreSQL, oauthpg.LinkServiceConfig{
		Schema: n.Schema, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Origin: n.Origin,
		Providers: n.Providers, CallbackAllowlist: n.CallbackAllowlist,
		Session:  sessionpg.SessionServiceConfig{Repository: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, Validation: validation},
		CSRFKeys: c.Session.CSRFKeys, Coordinator: n.Coordinator, Counters: n.Counters,
		Capability: n.Issuer, CapabilityPreparation: c.PasswordSignup.Preparation,
		MaximumDuration: n.MaximumDuration, StateLifetime: n.StateLifetime,
		AuditRetentionPolicyVersion: c.Session.Native.Execution.AuditRetentionVersion,
		IntentKey:                   n.IntentKey, CurrentStateKeyVersion: n.CurrentStateKeyVersion, StateKeys: n.StateKeys,
		CurrentPKCEKeyVersion: n.CurrentPKCEKeyVersion, PKCECommitmentKeys: n.PKCECommitmentKeys,
		CurrentEnvelopeKey: n.CurrentEnvelopeKey, EnvelopeKeys: n.EnvelopeKeys,
	})
	if err != nil {
		t.Fatal("construct native link", err)
	}
	refresh, err := oauthpg.NewProviderRefreshService(link, []string{f.provider.ID()})
	if err != nil {
		t.Fatal("compose explicit refresh", err)
	}
	if len(cookies) != 1 {
		t.Fatal("missing real password-authenticated cookie")
	}
	csrf, err := session.ParseCSRFToken(wireCSRF)
	if err != nil {
		t.Fatal("missing real password-authenticated synchronizer", err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)},
		Action: "identity.account.link-start", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)},
		Environment: authorization.Environment{Time: time.Now().UTC()},
	}}
	app, _ := oauth.NewValidatedCallbackURL(n.CallbackAllowlist[0], n.CallbackAllowlist)
	failure, _ := oauth.NewValidatedCallbackURL(n.CallbackAllowlist[1], n.CallbackAllowlist)
	scopes, _ := oauth.NewScopeSet([]string{"read", "write"})
	key, _ := identity.NewIdempotencyKey([]byte("fixture-provider-refresh-link"))
	bearer := auth.NewBearerCredential(cookies[0].Value)
	start, err := link.LinkStart(ctx, oauth.LinkStartRequest{TenantID: otpTenant, Provider: oauth.ProviderID(f.provider.ID()),
		Callback: app, ErrorCallback: failure, Scopes: scopes, SignupDisabled: true, IdempotencyKey: key,
		Session: bearer, CSRFToken: csrf, Caller: caller, Origin: n.Origin, Network: "127.0.0.1"})
	if err != nil {
		t.Fatalf("real native link start: %T %v", err, err)
	}
	redirect := start.RedirectURI.Query()
	challenge := redirect.Get("code_challenge")
	if len(challenge) != 43 || redirect.Get("code_challenge_method") != "S256" {
		t.Fatal("native link did not supply the configured S256 challenge")
	}
	f.challenge.Store(&challenge)
	query := url.Values{"code": {"fixture-public-code"}, "state": {redirect.Get("state")}}
	profile := f.provider.OAuth2Profile()
	callback, err := oauth.ParseOAuth2QueryCallback(ctx, query.Encode(), profile.Profile.RedirectURI, profile)
	if err != nil {
		t.Fatal("parse controlled provider callback", err)
	}
	defer callback.Destroy()
	linked, err := link.Callback(ctx, oauth.CallbackRequest{Callback: callback, TenantID: otpTenant, Session: bearer,
		Origin: n.Origin, Network: "127.0.0.1"})
	account, ok := linked.Outcome.Identity()
	if err != nil || !ok || account.UserID != user || account.AccountID == "" {
		t.Fatalf("real OAuth exchange/link failed: %T %v", err, err)
	}
	caller.Request.Action = "identity.account.refresh-token"
	caller.Request.Resource = authorization.Resource{Type: "identity.account", ID: authorization.ResourceID(account.AccountID)}
	request := oauthpg.ProviderRefreshRequest{TenantID: otpTenant, Account: account.AccountID, ExpectedVersion: 1, Session: bearer,
		CSRFToken: csrf, Caller: caller, Origin: n.Origin, Network: "127.0.0.1"}
	// Linking installs a credential and advances the user's credential epoch.
	// The original cookie still proves link replay, not current refresh authority.
	if got, err := refresh.Refresh(ctx, request); err == nil || got != (oauthpg.ProviderRefreshResult{}) || f.sends.Load() != 0 {
		t.Fatal("the pre-link session remained current after installing a credential")
	}
	freshRequest := func() {
		t.Helper()
		cookies, wire := fresh()
		if len(cookies) != 1 {
			t.Fatal("missing fresh session for stored provider refresh")
		}
		request.Session = auth.NewBearerCredential(cookies[0].Value)
		csrf, err := session.ParseCSRFToken(wire)
		if err != nil {
			t.Fatal(err)
		}
		request.CSRFToken = csrf
	}
	freshRequest()
	invalid := request
	invalid.CSRFToken = session.CSRFToken{}
	if got, err := refresh.Refresh(ctx, invalid); err == nil || got != (oauthpg.ProviderRefreshResult{}) || f.sends.Load() != 0 {
		t.Fatal("unauthorized call reached the provider")
	}
	table := pgx.Identifier{n.Schema, "token_sets"}.Sanitize()
	const readAccountVersions = `SELECT a.version::bigint,a.social_link_version::bigint
FROM identity.accounts a WHERE a.tenant_id=$1 AND a.account_id=$2`
	var originalAccountVersion, originalLinkVersion int64
	if err := d.PostgreSQL.Raw().QueryRow(ctx, readAccountVersions, otpTenant, string(account.AccountID)).
		Scan(&originalAccountVersion, &originalLinkVersion); err != nil {
		t.Fatal("missing original authoritative link", err)
	}
	if f.mode == "rollback" {
		if _, err := d.PostgreSQL.Raw().Exec(ctx, `CREATE FUNCTION public.reject_refresh_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.action='identity.oauth.refresh_grant' THEN RAISE EXCEPTION 'test: reject required refresh audit'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reject_refresh_audit_test BEFORE INSERT ON audit.records
FOR EACH ROW EXECUTE FUNCTION public.reject_refresh_audit_test()`); err != nil {
			t.Fatal("install isolated required-audit failure", err)
		}
	}
	var got oauthpg.ProviderRefreshResult
	if f.mode == "concurrent" {
		got, err = runReferenceProviderRefreshRace(t, ctx, f, refresh, request)
	} else {
		got, err = refresh.Refresh(ctx, request)
	}
	var version string
	if f.mode == "ambiguous" || f.mode == "rollback" {
		var unknown identity.UnknownCommitError
		if got != (oauthpg.ProviderRefreshResult{}) || !errors.As(err, &unknown) || unknown.CommandID == "" {
			t.Fatalf("upstream ambiguity did not return its original command: %T %v", err, err)
		}
		var retry identity.UnknownCommitError
		if _, err := refresh.Refresh(ctx, request); !errors.As(err, &retry) || retry.CommandID != unknown.CommandID || f.sends.Load() != 1 {
			t.Fatalf("ambiguous attempt reexecuted or lost its correlation: %T %v", err, err)
		}
		if err := d.PostgreSQL.Raw().QueryRow(ctx, "SELECT version::text FROM "+table+" WHERE tenant_id=$1 AND account_id=$2", otpTenant, string(account.AccountID)).Scan(&version); err != nil || version != "1" {
			t.Fatal("ambiguous exchange changed local grant custody", err)
		}
		var accountVersion, linkVersion int64
		if err := d.PostgreSQL.Raw().QueryRow(ctx, readAccountVersions, otpTenant, string(account.AccountID)).
			Scan(&accountVersion, &linkVersion); err != nil || accountVersion != originalAccountVersion || linkVersion != originalLinkVersion {
			t.Fatal("failed refresh advanced account-link authority", err)
		}
		command, _ := base64.RawURLEncoding.DecodeString(string(unknown.CommandID))
		var events int
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2`, otpTenant, command).
			Scan(&events); err != nil || events != 0 {
			t.Fatal("failed refresh left a lifecycle effect", err)
		}
		return
	}
	rejected := f.mode == "rejection"
	if err != nil || got.CommandID == "" || got.BeforeVersion != 1 || got.AfterVersion != 2 ||
		got.Rejected != rejected || got.AccessExpiresAt.IsZero() != rejected || f.sends.Load() != 1 {
		t.Fatalf("unexpected first refresh: version %d rejected=%t sends=%d error=%T %v", got.AfterVersion, got.Rejected, f.sends.Load(), err, err)
	}
	freshRequest()
	again, err := refresh.Refresh(ctx, request)
	if err != nil || again != got || f.sends.Load() != 1 {
		t.Fatalf("original receipt did not survive a different current session: %T %v", err, err)
	}
	var linkVersion, accountVersion int64
	var hasExpiry, erased bool
	if err := d.PostgreSQL.Raw().QueryRow(ctx, "SELECT v.version::text,a.social_link_version::bigint,a.version::bigint,v.access_expires_at_seconds IS NOT NULL "+
		"FROM "+table+" v JOIN identity.accounts a ON (v.tenant_id,v.user_id,v.account_id)=(a.tenant_id,a.user_id,a.account_id) "+
		"WHERE v.tenant_id=$1 AND v.account_id=$2", otpTenant, string(account.AccountID)).Scan(&version, &linkVersion, &accountVersion, &hasExpiry); err != nil || version != "2" ||
		linkVersion != originalLinkVersion+1 || accountVersion != originalAccountVersion || hasExpiry == rejected {
		t.Fatal("committed vault and current account-link authority diverged", err)
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(got.CommandID))
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL
FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.account.refresh-token' AND command_id=$2 AND state='committed'`, otpTenant, command).Scan(&erased); err != nil || !erased {
		t.Fatal("committed refresh retained duplicate provider ciphertext", err)
	}
	request.ExpectedVersion = 2
	next, err := refresh.Refresh(ctx, request)
	if rejected {
		if err == nil || next != (oauthpg.ProviderRefreshResult{}) || f.sends.Load() != 1 {
			t.Fatal("a definitively rejected local grant remained usable")
		}
	} else if err != nil || next.BeforeVersion != 2 || next.AfterVersion != 3 || next.Rejected || f.sends.Load() != 2 {
		t.Fatalf("a succeeding refresh did not use the rotated grant: %T %v", err, err)
	}
}
