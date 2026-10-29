//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresOrganizationAPIKeyHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organizationKey: true, organizationKeyUpgrade: upgrade, postgresBaseline: true})
		})
	}
}

type referenceOrganizationKeyPolicy struct{}

func (referenceOrganizationKeyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if string(r.Tenant) == otpTenant && c.PolicyRevision == 9 && (r.Subject.Kind == authorization.SubjectUser || r.Subject.Kind == authorization.SubjectAPIKey) {
		if r.Resource.Type == "organization-api-key" {
			switch r.Action {
			case "identity.apikey.create", "identity.apikey.import", "identity.apikey.rotate", "identity.apikey.delete", "invoice.read":
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
		if r.Action == "identity.apikey.verify" && r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "identity.anonymous-flow" {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	out, err := (referenceAPIKeyPolicy{}).Decide(ctx, c)
	if err != nil || out.Outcome == authorization.Allow {
		return out, err
	}
	return (referenceOrganizationPolicy{}).Decide(ctx, c)
}

func configureReferenceOrganizationKey(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configureReferenceAPIKey(t, c, origin)
	configureReferenceOrganization(t, c, origin)
	c.Organization.Invitations = nil
	c.HTTPOrganization = nil
	c.APIKey.OrganizationOwned = true
	c.HTTPAPIKey.OrganizationOwned = true
}

// The existing genuine baseline supplies registered/verified humans. Only
// deployment policy and sender/provider seams are configured; all domain
// stores, migration plans, session issuance and handlers remain public owners.
func proveReferenceOrganizationKey(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, baseline reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, config reference.ReferenceConfig, client *http.Client, base, origin string, messages <-chan string, user identity.UserID, upgrade bool) {
	t.Helper()
	recipient := registerReferenceOrganizationHuman(t, ctx, client, base, origin, baseline, workers, messages)
	var retainedSelf apikey.Record
	var retainedSecret apikey.Secret
	var retainedBytes []byte
	if upgrade {
		prior := c
		bearer := *c.PasswordSignin
		bearer.Native.Transport, bearer.Native.CSRFKey, bearer.Native.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
		prior.PasswordSignin, prior.HTTPPasswordSignin = &bearer, nil
		_, priorFeatures := composeReferenceAPIKeyGraph(t, prior, deps, workerConfigs)
		if err := priorFeatures.Initialize(ctx); err != nil {
			t.Fatal("existing self-key graph startup", err)
		}
		priorOwner, err := priorFeatures.APIKeys()
		if err != nil {
			t.Fatal(err)
		}
		priorCaller := referenceAPIKeyBearer(t, ctx, priorFeatures, prior, origin, user)
		priorKey, _ := identity.NewIdempotencyKey([]byte("existing-self-key-before-organization-upgrade"))
		issued, err := priorOwner.Create(ctx, apikey.CreateRequest{Authentication: priorCaller, IdempotencyKey: priorKey, Name: "retained self key", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "127.0.0.1"})
		if err != nil {
			t.Fatal("genuine existing self key", err)
		}
		retainedSelf, _ = issued.Record()
		wire, err := issued.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		retainedSecret, _ = apikey.ParseSecret(wire)
		if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, otpTenant, string(retainedSelf.ID)).Scan(&retainedBytes); err != nil {
			t.Fatal(err)
		}
		configureReferenceOrganizationKey(t, &c, origin)
	}
	signin := *c.PasswordSignin
	signin.Native.Transport, signin.Native.CSRFKey, signin.Native.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
	c.PasswordSignin, c.HTTPPasswordSignin = &signin, nil
	stores, features := composeReferenceAPIKeyGraph(t, c, deps, workerConfigs)
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity", "organization/postgres", "identity/apikey/postgres"}
	apply := applyRequest(t, ctx, stores, modules)
	apply.CommandID = "migration_org_api_key_selected_0001"
	apply.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("apply-org-key-selected"))
	if out, err := stores.ReferenceMigrationApply(ctx, apply); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("selected organization-key migration", err)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("selected organization-key initialization", err)
	}
	keyOwner, err := features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if upgrade {
		var after []byte
		if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, otpTenant, string(retainedSelf.ID)).Scan(&after); err != nil || !bytes.Equal(after, retainedBytes) {
			t.Fatal("organization upgrade rewrote an existing self key", err)
		}
		out, err := keyOwner.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandIDForReference(t)), TenantID: otpTenant, ConfigurationID: c.APIKey.Configuration.Spec().ID, ConfigurationRevision: 1, Secret: retainedSecret, RequiredPermissions: []string{"invoice.read"}})
		if err != nil || out.Result == nil || out.Result.Record.ID != retainedSelf.ID || out.Result.Owner != retainedSelf.Owner {
			t.Fatal("organization upgrade changed existing self-key authentication", err)
		}
	}
	organizationKeys, ok := any(keyOwner).(interface {
		CreateOrganization(context.Context, apikey.OrganizationCreateRequest) (apikey.IssuanceResult, error)
		RecoverOrganization(context.Context, apikey.OrganizationID, apikey.RecoveryRequest) (identity.CommandResult, error)
	})
	if !ok {
		t.Fatal("Reference API-key owner has no organization workflow")
	}
	creator := referenceAPIKeyBearer(t, ctx, features, c, origin, user)
	second := referenceAPIKeyBearer(t, ctx, features, c, origin, recipient.user, "organization-recipient@example.invalid")
	orgs, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	key := func(text string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	orgAuth := func(a apikey.Authentication) organization.Authentication {
		return organization.Authentication{TenantID: a.TenantID, Bearer: a.Bearer}
	}
	created, err := orgs.Create(ctx, organization.CreateOperationRequest{Authentication: orgAuth(creator), IdempotencyKey: key("org-key-owner-create"), Name: "Independent key owner", Slug: "org-key-owner", CorrelationID: "org-key-owner-create"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine key-owner creation", err)
	}
	orgID := created.OrganizationID
	added, err := orgs.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: orgAuth(creator), IdempotencyKey: key("org-key-second-owner"), OrganizationID: orgID, UserID: recipient.user, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "org-key-second-owner"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine second-owner admission", err)
	}
	selected, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("organization-key HTTP composition", err)
	}
	api := httptest.NewTLSServer(selected.Handler())
	t.Cleanup(api.Close)
	apiClient := api.Client()
	apiClient.Timeout = 5 * time.Second
	type reply struct {
		Committed bool   `json:"committed"`
		Secret    string `json:"secret"`
		Key       struct {
			ID      apikey.KeyID `json:"id"`
			Version uint64       `json:"version"`
		} `json:"key"`
		Recovery identity.RecoveryQuery `json:"recovery"`
	}
	callAt := func(selectedClient *http.Client, selectedBase, action, id string, body any, caller apikey.Authentication) (int, reply) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, selectedBase+"/v1/apikey/"+action, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+caller.Bearer.Token())
		r.Header.Set("Idempotency-Key", id)
		response, err := selectedClient.Do(r)
		if err != nil {
			t.Fatal("organization-key HTTPS", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 131073))
		closeErr := response.Body.Close()
		var out reply
		if readErr != nil || closeErr != nil || len(payload) > 131072 || json.Unmarshal(payload, &out) != nil || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(payload, []byte(caller.Bearer.Token())) {
			t.Fatal("organization-key response custody")
		}
		return response.StatusCode, out
	}
	call := func(action, id string, body any, caller apikey.Authentication) (int, reply) {
		return callAt(apiClient, api.URL, action, id, body, caller)
	}
	body := map[string]any{"organizationID": string(orgID), "name": "independent key", "permissions": []string{"invoice.read"}, "expiresAt": time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)}
	code, issued := call("create", "reference-org-key-original", body, creator)
	if code != 200 || !issued.Committed || issued.Secret == "" || issued.Key.ID == "" || issued.Recovery.UserID != user {
		t.Fatal("organization-key original HTTPS issuance", code)
	}
	if code, replayed := call("create", "reference-org-key-original", body, creator); code != 200 || !replayed.Committed || replayed.Secret != "" || replayed.Key.ID != issued.Key.ID {
		t.Fatal("organization issuance retry replaced identity or disclosure", code)
	}
	secret, err := apikey.ParseSecret(issued.Secret)
	if err != nil {
		t.Fatal("original modern secret")
	}
	removed, err := orgs.RemoveMember(ctx, organization.RemoveMemberOperationRequest{Authentication: orgAuth(second), OrganizationID: orgID, UserID: user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "org-key-remove-creator"}, "127.0.0.1")
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine creator removal", err)
	}
	verify := func(presented apikey.Secret, allow bool) {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		out, err := keyOwner.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: otpTenant, ConfigurationID: c.APIKey.Configuration.Spec().ID, ConfigurationRevision: 1, Secret: presented, RequiredPermissions: []string{"invoice.read"}})
		if allow {
			if err != nil || out.Result == nil || out.Result.Owner.Spec().OrganizationID != apikey.OrganizationID(orgID) || out.Result.Owner.Spec().UserID != "" || out.Original.UserID != "" {
				t.Fatal("creator removal revoked independent key authority", err)
			}
		} else if !errors.Is(err, apikey.ErrDenied) || out.Result != nil {
			t.Fatal("terminal organization key authenticated", err)
		}
	}
	verify(secret, true)
	userOnlyConfig := c
	userOnlyHTTP := *c.HTTPAPIKey
	userOnlyHTTP.OrganizationOwned = false
	userOnlyConfig.HTTPAPIKey = &userOnlyHTTP
	_, userOnlyFeatures := composeReferenceAPIKeyGraph(t, userOnlyConfig, deps, workerConfigs)
	if err := userOnlyFeatures.Initialize(ctx); err != nil {
		t.Fatal("user-only HTTP reconstruction", err)
	}
	userOnlyServer, err := reference.NewServer(config, deps, userOnlyFeatures)
	if err != nil {
		t.Fatal(err)
	}
	userOnlyAPI := httptest.NewTLSServer(userOnlyServer.Handler())
	t.Cleanup(userOnlyAPI.Close)
	userOnlyClient := userOnlyAPI.Client()
	userOnlyClient.Timeout = 5 * time.Second
	userOnlyCode, userOnlyOut := callAt(userOnlyClient, userOnlyAPI.URL, "delete", "unselected-organization-revoke", map[string]any{"keyID": issued.Key.ID, "expectedVersion": issued.Key.Version}, second)
	var userOnlyRecord []byte
	if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, otpTenant, string(issued.Key.ID)).Scan(&userOnlyRecord); err != nil {
		t.Fatal(err)
	}
	var userOnlyState struct {
		Status  apikey.KeyStatus
		Version uint64
	}
	if json.Unmarshal(userOnlyRecord, &userOnlyState) != nil || userOnlyState.Status != apikey.KeyActive || userOnlyState.Version != issued.Key.Version {
		t.Fatalf("user-only HTTP changed actual organization authority: http_status=%d still_active=%t same_version=%t", userOnlyCode, userOnlyState.Status == apikey.KeyActive, userOnlyState.Version == issued.Key.Version)
	}
	if code, out := userOnlyCode, userOnlyOut; code != 403 || out.Committed || out.Secret != "" || out.Recovery.CommandID != "" {
		t.Fatal("user-only HTTP acquired organization mutation authority", code)
	}
	verify(secret, true)
	if code, out := callAt(userOnlyClient, userOnlyAPI.URL, "create", "unselected-organization-create", body, second); code != 400 || out.Committed || out.Secret != "" {
		t.Fatal("user-only HTTP accepted organization input", code)
	}
	func() {
		var before int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2`, otpTenant, string(orgID)).Scan(&before); err != nil {
			t.Fatal(err)
		}
		// Fail at the real required audit persistence boundary after native
		// domain writes; do not replace the transaction or authority owner.
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_reference_org_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.api_key.create' THEN RAISE EXCEPTION 'injected required audit outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_reference_org_key_audit BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_reference_org_key_audit()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := f.pool.Raw().Exec(cleanup, `DROP TRIGGER reject_reference_org_key_audit ON audit.records; DROP FUNCTION public.reject_reference_org_key_audit()`); err != nil {
				t.Error("audit fault cleanup", err)
			}
		}()
		if code, out := call("create", "reference-org-key-required-effect-rollback", body, second); code != 503 || out.Committed || out.Secret != "" {
			t.Fatal("failed required organization-key effect leaked commitment", code)
		}
		var after int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2`, otpTenant, string(orgID)).Scan(&after); err != nil || after != before {
			t.Fatal("failed required effect left organization authority", err)
		}
	}()
	if code, out := call("create", "reference-org-key-original", body, creator); code != 403 || out.Secret != "" || out.Committed {
		t.Fatal("removed creator retained HTTP management", code)
	}
	if out, err := organizationKeys.RecoverOrganization(ctx, apikey.OrganizationID(orgID), apikey.RecoveryRequest{Authentication: creator, Query: issued.Recovery}); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("removed creator retained original recovery")
	}
	code, rotated := call("rotate", "reference-org-key-other-owner-rotate", map[string]any{"keyID": issued.Key.ID, "expectedVersion": issued.Key.Version}, second)
	if code != 200 || !rotated.Committed || rotated.Secret == "" || rotated.Key.ID == issued.Key.ID {
		t.Fatal("other owner organization rotation", code)
	}
	verify(secret, false)
	successor, err := apikey.ParseSecret(rotated.Secret)
	if err != nil {
		t.Fatal("successor secret")
	}
	verify(successor, true)
	if code, out := call("delete", "reference-org-key-other-owner-revoke", map[string]any{"keyID": rotated.Key.ID, "expectedVersion": rotated.Key.Version}, second); code != 200 || !out.Committed || out.Secret != "" {
		t.Fatal("other owner organization revoke", code)
	}
	verify(successor, false)
}
