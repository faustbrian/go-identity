//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
)

// This is the existing explicit external policy seam, not identity/key storage.
// Every user, session, owner, membership and key in these tests is native.
type metadataConsumerPolicy struct {
	base interface {
		Evaluate(context.Context, authorization.Request) (authorization.Decision, error)
	}
	deny bool
	fail bool
}

func (p metadataConsumerPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	d, err := p.base.Evaluate(ctx, r)
	if err == nil && r.Tenant == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Action == "identity.session.revoke-one" && r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID) {
		d.Outcome = authorization.Allow
	}
	if err == nil && r.Tenant == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (r.Action == "identity.apikey.get" || r.Action == "identity.apikey.list") {
		if p.fail {
			return authorization.Decision{}, errors.New("external metadata policy unavailable")
		}
		if r.Resource.Type == "api-key" && (r.Resource.ID == "automation" || r.Resource.ID == "legacy") || r.Resource.Type == "organization-api-key" {
			d.Outcome = authorization.Allow
			if p.deny {
				d.Outcome = authorization.Deny
			}
		}
	}
	return d, err
}

func metadataPolicy(t *testing.T, config apikeypg.ServiceConfig, policy metadataConsumerPolicy) apikeypg.ServiceConfig {
	t.Helper()
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "metadata-consumer", Revision: 9, Evaluator: policy})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	config.Authorization, err = authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func metadataReader(t *testing.T, service *apikeypg.Service) apikey.MetadataService {
	t.Helper()
	reader, ok := any(service).(apikey.MetadataService)
	if !ok {
		t.Fatal("genuine configured native key service lacks safe metadata Get/List")
	}
	return reader
}

func metadataIssue(t *testing.T, f nativeConsumerFixture, service *apikeypg.Service, authentication apikey.Authentication, name string) apikey.Record {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("metadata-original-" + name))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Create(f.ctx, apikey.CreateRequest{Authentication: authentication, IdempotencyKey: key, Name: name, Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.44"})
	if err != nil {
		t.Fatal("genuine metadata fixture key issuance", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("genuine issued key record absent")
	}
	return record
}

func TestGenuineMetadataReadsIssuedSelfKey(t *testing.T) {
	f := setupNativeConsumer(t)
	config := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}})
	service, err := apikeypg.NewService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	record := metadataIssue(t, f, service, f.caller, "metadata-runtime-presence")
	reader := metadataReader(t, service)
	got, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID})
	if err != nil || got.Record.ID != record.ID || got.Record.Name != record.Name || got.Record.Owner.Spec().UserID != f.user {
		t.Fatal("actual self-key metadata read", err)
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Limit: 1}); !errors.Is(err, identity.UnavailableError{}) || len(out.Records) != 0 {
		t.Fatal("uninstalled selected metadata index silently fell back to a tenant scan", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE TABLE identity_api_keys.metadata_other(id integer); CREATE INDEX identity_api_keys_metadata_user_page ON identity_api_keys.metadata_other(id)`); err != nil {
		t.Fatal(err)
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Limit: 1}); !errors.Is(err, identity.UnavailableError{}) || len(out.Records) != 0 {
		t.Fatal("same-name ready index on another relation satisfied metadata readiness", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP INDEX identity_api_keys.identity_api_keys_metadata_user_page; DROP TABLE identity_api_keys.metadata_other`); err != nil {
		t.Fatal(err)
	}
	installMetadataPages(t, f, false)
	second := metadataIssue(t, f, service, f.caller, "second-self-metadata")
	third := metadataIssue(t, f, service, f.caller, "terminal-self-metadata")
	revokeKey, _ := identity.NewIdempotencyKey([]byte("terminal-self-metadata-revoke"))
	if out, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: revokeKey, KeyID: third.ID, ExpectedVersion: third.Version, Network: "192.0.2.44"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine terminal metadata specimen", err)
	}
	other, _ := f.register()
	foreign := metadataIssue(t, f, service, other, "other-owner-metadata")
	before := metadataState(t, f)
	terminal, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: third.ID})
	if err != nil || terminal.Record.Status != apikey.KeyRevoked {
		t.Fatal("authorized terminal record metadata was hidden", err)
	}
	terminal.Record.Grant = append(terminal.Record.Grant, "invented.permission")
	terminal.Record.Name = "caller mutation"
	again, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: third.ID})
	if err != nil || again.Record.Name == terminal.Record.Name || slices.Contains(again.Record.Grant, "invented.permission") {
		t.Fatal("caller-owned metadata aliased native state", err)
	}
	expected := []apikey.KeyID{record.ID, second.ID, third.ID}
	slices.Sort(expected)
	request := apikey.ListRequest{Authentication: f.caller, Limit: 1}
	var seen []apikey.KeyID
	var firstCursor string
	for page := 0; page < 4; page++ {
		// Reconstruct all native service composition between pages. A cursor is
		// only a query position, not an in-memory session/transaction handle.
		restarted, err := apikeypg.NewService(f.pool, config)
		if err != nil {
			t.Fatal(err)
		}
		result, err := metadataReader(t, restarted).List(f.ctx, request)
		if err != nil || len(result.Records) != 1 {
			t.Fatal("stable owner page after native reconstruction", err)
		}
		seen = append(seen, result.Records[0].ID)
		if page == 0 {
			firstCursor = result.NextCursor
		}
		if result.NextCursor == "" {
			break
		}
		request.Cursor = result.NextCursor
	}
	if !slices.Equal(seen, expected) || firstCursor == "" {
		t.Fatal("metadata pagination duplicated, omitted or reordered existing self keys")
	}
	metadataConcurrentReads(t, f, reader, record.ID)
	for _, request := range []apikey.GetRequest{
		{Authentication: f.caller, KeyID: foreign.ID},
		{Authentication: other, KeyID: record.ID},
		{Authentication: f.caller, KeyID: "absent-key"},
		{Authentication: f.caller, OrganizationID: "unselected-organization", KeyID: record.ID},
	} {
		if out, err := reader.Get(f.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Record.ID != "" {
			t.Fatal("foreign, missing or unselected owner metadata was disclosed", err)
		}
	}
	foreignTenant := f.caller
	foreignTenant.TenantID = "other-tenant"
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: foreignTenant, KeyID: record.ID}); err == nil || out.Record.ID != "" {
		t.Fatal("cross-tenant bearer acquired key metadata")
	}
	for _, request := range []apikey.ListRequest{
		{Authentication: f.caller, ConfigurationIDs: []string{"unselected"}, Limit: 1},
		{Authentication: f.caller, Cursor: "malformed", Limit: 1},
		{Authentication: other, Cursor: firstCursor, Limit: 1},
		{Authentication: f.caller, Cursor: strings.Repeat("x", 513), Limit: 1},
		{Authentication: f.caller, Limit: 201},
	} {
		if out, err := reader.List(f.ctx, request); err == nil || len(out.Records) != 0 || out.NextCursor != "" {
			t.Fatal("invalid/foreign paging scope acquired metadata")
		}
	}
	deniedConfig := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}, deny: true})
	denied, err := apikeypg.NewService(f.pool, deniedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := metadataReader(t, denied).Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID}); !errors.Is(err, apikey.ErrDenied) || out.Record.ID != "" {
		t.Fatal("current policy denial disclosed key metadata", err)
	}
	if out, err := metadataReader(t, denied).List(f.ctx, apikey.ListRequest{Authentication: f.caller, Cursor: firstCursor, Limit: 1}); !errors.Is(err, apikey.ErrDenied) || len(out.Records) != 0 {
		t.Fatal("retained cursor bypassed current policy denial", err)
	}
	unavailableConfig := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}, fail: true})
	unavailable, err := apikeypg.NewService(f.pool, unavailableConfig)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := metadataReader(t, unavailable).Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID}); !errors.Is(err, identity.UnavailableError{}) || out.Record.ID != "" {
		t.Fatal("unavailable current policy disclosed metadata or a weaker fallback", err)
	}
	revisionConfig := config
	revision := config.Configuration.Spec()
	revision.Revision++
	revisionConfig.Configuration, err = apikey.NewConfiguration(revision)
	if err != nil {
		t.Fatal(err)
	}
	revised, err := apikeypg.NewService(f.pool, revisionConfig)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := metadataReader(t, revised).List(f.ctx, apikey.ListRequest{Authentication: f.caller, Cursor: firstCursor, Limit: 1}); !errors.Is(err, apikey.ErrDenied) || len(out.Records) != 0 {
		t.Fatal("different effective configuration revision acquired old metadata", err)
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	if out, err := reader.List(canceled, apikey.ListRequest{Authentication: f.caller, Limit: 1}); !errors.Is(err, context.Canceled) || len(out.Records) != 0 {
		t.Fatal("canceled page produced metadata", err)
	}
	if after := metadataState(t, f); after != before {
		t.Fatal("metadata reads changed key/configuration/verification-attempt state")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=false WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, config.Configuration.Spec().ID); err != nil {
		t.Fatal(err)
	}
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID}); !errors.Is(err, apikey.ErrDenied) || out.Record.ID != "" {
		t.Fatal("disabled authoritative profile disclosed metadata", err)
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Cursor: firstCursor, Limit: 1}); !errors.Is(err, apikey.ErrDenied) || len(out.Records) != 0 {
		t.Fatal("cursor bypassed disabled current configuration", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=true WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, config.Configuration.Spec().ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id=$1`, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Cursor: firstCursor, Limit: 1}); err == nil || len(out.Records) != 0 {
		t.Fatal("disabled actual tenant retained metadata disclosure")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.tenant_authorities SET enabled=true WHERE tenant_id=$1`, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, baselineTenant, string(f.user)); err != nil {
		t.Fatal(err)
	}
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID}); err == nil || out.Record.ID != "" {
		t.Fatal("current suspended human retained metadata disclosure")
	}
	if out, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Cursor: firstCursor, Limit: 1}); err == nil || len(out.Records) != 0 {
		t.Fatal("cursor bypassed current human/session authority")
	}
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: other, KeyID: foreign.ID}); err != nil || out.Record.ID != foreign.ID {
		t.Fatal("independent current owner was affected by another user's suspension", err)
	}
	metadataSignOut(t, f, config, other)
	if out, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: other, KeyID: foreign.ID}); err == nil || out.Record.ID != "" {
		t.Fatal("actually logged-out bearer retained metadata disclosure")
	}
}

func metadataConcurrentReads(t *testing.T, f nativeConsumerFixture, reader apikey.MetadataService, key apikey.KeyID) {
	t.Helper()
	var workers sync.WaitGroup
	failures := make(chan error, 6)
	for range 6 {
		workers.Go(func() {
			for range 3 {
				got, err := reader.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: key})
				if err != nil || got.Record.ID != key {
					failures <- errors.New("concurrent native metadata Get failed")
					return
				}
				page, err := reader.List(f.ctx, apikey.ListRequest{Authentication: f.caller, Limit: 1})
				if err != nil || len(page.Records) != 1 || page.Records[0].Owner.Spec().UserID != f.user {
					failures <- errors.New("concurrent native metadata List failed")
					return
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
}

func metadataState(t *testing.T, f nativeConsumerFixture) [3]string {
	t.Helper()
	var state [3]string
	err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT coalesce(md5(string_agg(row_to_json(k)::text,'' ORDER BY tenant_id,configuration_id,key_id)),'') FROM identity_api_keys.keys k),
 (SELECT coalesce(md5(string_agg(row_to_json(c)::text,'' ORDER BY tenant_id,configuration_id)),'') FROM identity_api_keys.configurations c),
 (SELECT coalesce(md5(string_agg(row_to_json(e)::text,'' ORDER BY command_id)),'') FROM identity_api_keys.command_effects e)`).Scan(&state[0], &state[1], &state[2])
	if err != nil {
		t.Fatal("read-only key/configuration/verification-attempt observation", err)
	}
	return state
}

func installMetadataPages(t *testing.T, f nativeConsumerFixture, organization bool) {
	t.Helper()
	var source migrations.Source = apikeypg.MetadataMigrationSource{Version: 1}
	namespace := "identity_api_keys_metadata_user"
	if organization {
		source = apikeypg.OrganizationMetadataMigrationSource{Version: 1}
		namespace = "identity_api_keys_metadata_org"
	}
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace(namespace)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(source, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("selected additive metadata paging migration", err)
	}
}

func metadataSignOut(t *testing.T, f nativeConsumerFixture, config apikeypg.ServiceConfig, authentication apikey.Authentication) {
	t.Helper()
	query, admission := *config.Coordinator.QueryPolicy, *config.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = config.Authorization, config.Authorization
	coordinator := config.Coordinator
	coordinator.QueryPolicy, coordinator.AdmissionPolicy = &query, &admission
	lookup := make([]session.DigestKey, 0, len(config.LookupKeys))
	for _, key := range config.LookupKeys {
		lookup = append(lookup, key)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-metadata", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sessionpg.NewSignOutService(f.pool, sessionpg.SignOutServiceConfig{
		Execution:  sessionpg.IssueExecutorConfig{Repository: config.Session, Profile: sessionpg.IssueAdmissionConfig(config.Profile), Coordinator: coordinator, Authorization: config.Authorization, Clock: clock.System{}, PolicyID: config.PolicyID, PolicyVersion: config.PolicyVersion, AuditRetentionVersion: 1},
		Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: lookup},
		Cookie:     cookie, MaximumDuration: 4 * time.Second,
	})
	if err != nil {
		t.Fatal("actual native bearer signout composition", err)
	}
	token, err := session.ParseToken(authentication.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.SignOut(f.ctx, session.SignOutRequest{TenantID: authentication.TenantID, CommandID: commandID(t), CorrelationID: "metadata-current-session-logout", Transport: session.CredentialBearer, Credential: credential})
	if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual native metadata bearer logout", err)
	}
}
