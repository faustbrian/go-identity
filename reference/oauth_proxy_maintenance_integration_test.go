//go:build integration

package reference_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresOAuthProxyMaintenanceDrainsBothActualOrigins(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true,
		oauthProxyPreview: true, oauthProxyProviderAuthority: true, oauthProxyMaintenance: true,
	}, true)
}

func (p *referenceOAuthProxyPreviewProof) installMaintenance(t *testing.T, ctx context.Context, c reference.StoreConfiguration, production liveStores, runtime *database.Pool) {
	t.Helper()
	productionSchema := p.production.Native.Schema
	for _, source := range []migrations.Source{
		oauthpg.ProxyRetirementMigrationSource{Schema: productionSchema, Version: 44, Kind: kernel.OAuthProxyRetireProduction},
		oauthpg.ProviderDisableCascadeMigrationSource{Schema: productionSchema, Version: 46},
		oauthpg.ProxyDisablePairMigrationSource{Schema: productionSchema, Version: 47},
		oauthpg.ProxyCustodyWriteFenceMigrationSource{Schema: productionSchema, Version: 48, Kind: kernel.OAuthProxyRetireProduction},
		oauthpg.ProxyRetirementDrainMigrationSource{Schema: productionSchema, Version: 49},
		oauthpg.ProxyCustodyWriteFenceActivationSource{Schema: productionSchema, Version: 50, Kind: kernel.OAuthProxyRetireProduction},
	} {
		applyReferenceProxyMaintenanceSource(t, ctx, production.pool, source)
	}
	applyReferenceProxyMaintenanceSource(t, ctx, p.previewPool, oauthpg.ProxyCustodyWriteFenceActivationSource{
		Schema: c.SocialOAuth.Schema, Version: 100, Kind: kernel.OAuthProxyRetirePreview,
	})
	reader := pgx.Identifier{p.readerRole}.Sanitize()
	cascadeTable := pgx.Identifier{productionSchema, "provider_disable_cascades"}.Sanitize()
	if _, err := production.pool.Raw().Exec(ctx, "GRANT SELECT ON "+cascadeTable+" TO "+reader); err != nil {
		t.Fatal("grant the designated primary reader only retained disable admission reads", err)
	}
	role := pgx.Identifier{runtime.Raw().Config().ConnConfig.User}.Sanitize()
	fenceTable := pgx.Identifier{productionSchema, "proxy_production_write_fences"}.Sanitize()
	drainTable := pgx.Identifier{productionSchema, "proxy_retirement_drains"}.Sanitize()
	for _, grant := range []string{
		"GRANT SELECT ON " + fenceTable + " TO " + role,
		"GRANT SELECT, INSERT, UPDATE ON " + drainTable + " TO " + role,
	} {
		if _, err := production.pool.Raw().Exec(ctx, grant); err != nil {
			t.Fatal("grant the callback owner only local fence reads and bounded drain checkpoints", err)
		}
	}
	var restricted bool
	if err := runtime.Raw().QueryRow(ctx, `SELECT
 has_table_privilege(current_user,$1,'SELECT') AND
 NOT has_table_privilege(current_user,$1,'INSERT,UPDATE,DELETE,TRUNCATE') AND
 has_table_privilege(current_user,$2,'SELECT,INSERT,UPDATE') AND
 NOT has_table_privilege(current_user,$2,'DELETE,TRUNCATE') AND
 NOT has_table_privilege(current_user,$3,'INSERT,UPDATE,DELETE,TRUNCATE')`, fenceTable, drainTable, cascadeTable).Scan(&restricted); err != nil || !restricted {
		t.Fatal("maintenance widened the production runtime into a fence or provider operator", err)
	}
}

func applyReferenceProxyMaintenanceSource(t *testing.T, ctx context.Context, pool *database.Pool, source migrations.Source) {
	t.Helper()
	history, err := source.Load(ctx)
	if err != nil || len(history) == 0 {
		t.Fatal("load the separately selected native maintenance migration", err)
	}
	for _, migration := range history {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal("begin actual custody maintenance migration", err)
		}
		if _, err := tx.Exec(ctx, migration.UpSQL()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("apply actual custody maintenance migration", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal("commit actual custody maintenance migration", err)
		}
	}
}

func (p *referenceOAuthProxyPreviewProof) proveMaintenance(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet,
	production *reference.OAuthProxyProduction, app *http.Client, base, origin string, first reference.OAuthProxyPreviewStartRequest, authorizationURL string) {
	t.Helper()
	if authorizationURL == "" {
		t.Fatal("the first genuine production Start and preview Bind withheld authorization")
	}
	second := p.startMaintenanceOriginal(t, ctx, c, features, production, app, base, origin)
	productionSchema, previewSchema := p.production.Native.Schema, c.SocialOAuth.Schema
	type localOrigin struct {
		pool                        *database.Pool
		schema, custody, fence, key string
	}
	origins := []localOrigin{
		{p.productionFixture.pool, productionSchema, "proxy_transactions", "proxy_production_write_fences", "transaction_id"},
		{p.previewPool, previewSchema, "proxy_preview_bindings", "proxy_preview_write_fences", "flow_id"},
	}
	for _, local := range origins {
		table := pgx.Identifier{local.schema, local.custody}.Sanitize()
		var genuine bool
		if err := local.pool.Raw().QueryRow(ctx, `SELECT count(*)=2 AND bool_and(version=1 AND settled_at IS NULL AND
 fence_provider_id=$4 AND fence_provider_epoch=$5::numeric) FROM `+table+` WHERE tenant_id=$1 AND `+local.key+` IN ($2,$3)`,
			string(otpTenant), string(first.Initiation.TransactionID), string(second.Initiation.TransactionID), p.production.Start.Provider.Profile().ID, p.epoch).Scan(&genuine); err != nil || !genuine {
			t.Fatal("maintenance did not begin with both genuine public Start/Bind originals", local.custody, err)
		}
	}
	configuration := reference.OAuthProxyMaintenanceConfiguration{
		Operator: p.operator, ActorID: p.production.Native.Actor,
		ProductionFencePool: p.productionFixture.pool, PreviewFencePool: p.previewPool, MaximumDuration: time.Second,
	}
	maintenance, err := features.NewOAuthProxyMaintenance(production, configuration)
	if err != nil {
		t.Fatal("compose public maintenance from the actual Reference production and preview owners", err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	disable := oauthpg.ProviderAuthorityChange{
		Key:             oauthpg.ProviderAuthorityKey{TenantID: otpTenant, ProviderID: p.production.Start.Provider.Profile().ID},
		ExpectedVersion: p.epoch, Next: oauthpg.ProviderAuthorityState{Version: p.epoch + 1, ProfileVersion: p.production.Start.Provider.Profile().Version}, CommandID: command,
	}
	beforeExchanges, beforeRevocations := p.provider.exchanges.Load(), p.provider.proxyRevocations.Load()
	admission, err := maintenance.ApplyDisableCascade(ctx, disable, time.Hour)
	if err != nil || admission.Disable != disable || admission.Status != identity.RevocationPending || admission.Generation != 1 || admission.CascadeID == "" {
		t.Fatal("public maintenance did not freeze the exact pending provider-disable pair", err)
	}
	if replay, err := maintenance.ApplyDisableCascade(ctx, disable, time.Hour); err != nil || !reflect.DeepEqual(replay, admission) {
		t.Fatal("the paired disable retry did not recover its exact durable admission", err)
	}
	var paired bool
	if err := p.productionFixture.pool.Raw().QueryRow(ctx, `SELECT count(*)=1 AND bool_and(cascade_id=$3 AND generation=$4
 AND production_schema=$5 AND preview_schema=$6 AND production_deployment=$7 AND preview_deployment=$8 AND acknowledged_at IS NULL)
 FROM `+pgx.Identifier{productionSchema, "provider_disable_proxy_pairs"}.Sanitize()+` WHERE tenant_id=$1 AND source_command_id=$2`,
		string(otpTenant), string(command), string(admission.CascadeID), admission.Generation, productionSchema, previewSchema,
		p.production.Native.ProductionDeployment, c.OAuthProxyPreview.Native.Target.Deployment).Scan(&paired); err != nil || !paired {
		t.Fatal("provider admission did not freeze exactly these two actual custody owners", err)
	}
	source := oauthpg.ProxyCustodyFenceSealRequest{TenantID: otpTenant, SourceCommandID: command, CascadeID: admission.CascadeID, Generation: admission.Generation}
	snapshot := func() string {
		t.Helper()
		var state strings.Builder
		for _, local := range origins {
			for _, name := range []string{local.custody, "proxy_retirement_drains", local.fence} {
				var rows string
				if err := local.pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+pgx.Identifier{local.schema, name}.Sanitize()+` r`).Scan(&rows); err != nil {
					t.Fatal("snapshot actual local custody and maintenance progress", err)
				}
				state.WriteString(rows)
			}
		}
		for _, name := range []string{"provider_disable_cascades", "provider_disable_proxy_pairs"} {
			var rows string
			if err := p.productionFixture.pool.Raw().QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+pgx.Identifier{productionSchema, name}.Sanitize()+` r`).Scan(&rows); err != nil {
				t.Fatal("snapshot the retained admission and pair acknowledgement", err)
			}
			state.WriteString(rows)
		}
		return state.String()
	}
	assertAckDenied := func(selected oauthpg.ProxyCustodyFenceSealRequest) {
		t.Helper()
		before := snapshot()
		if ack, err := maintenance.Acknowledge(ctx, selected); err == nil || ack != (oauthpg.ProxyDisablePairAcknowledgement{}) {
			t.Fatal("incomplete or substituted pair disclosed an acknowledgement", err)
		}
		if snapshot() != before {
			t.Fatal("rejected acknowledgement changed either actual origin or the provider admission")
		}
	}
	assertAckDenied(source)
	if err := maintenance.Seal(ctx, source); err != nil {
		t.Fatal("seal both separately activated actual custody databases", err)
	}
	for _, local := range origins {
		var sealed bool
		if err := local.pool.Raw().QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=to_regclass($1) AND tgname='proxy_custody_write_fence'
 AND NOT tgisinternal AND tgenabled IN ('O','A') AND tgdeferrable AND tginitdeferred) AND
 (SELECT denied_through=$4::numeric FROM `+pgx.Identifier{local.schema, local.fence}.Sanitize()+` WHERE tenant_id=$2 AND provider_id=$3)`,
			pgx.Identifier{local.schema, local.custody}.Sanitize(), string(otpTenant), disable.Key.ProviderID, disable.ExpectedVersion).Scan(&sealed); err != nil || !sealed {
			t.Fatal("each actual origin must retain its own active writer gate and exact cutoff", local.custody, err)
		}
	}
	assertAckDenied(source)
	for index, step := range []func(context.Context, oauthpg.ProxyCustodyFenceSealRequest, uint16) (oauthpg.ProxyRetirementDrainProgress, error){maintenance.StepProduction, maintenance.StepPreview} {
		progress, err := step(ctx, source, 1)
		if err != nil || progress.Exhausted || progress.Retired != 1 {
			t.Fatal("one-row drain did not preserve a genuinely incomplete two-original traversal", progress, err)
		}
		assertAckDenied(source)
		for range 4 {
			progress, err = step(ctx, source, 1)
			if err != nil {
				t.Fatal("advance the bounded public Reference drain", err)
			}
			if progress.Exhausted {
				break
			}
		}
		if !progress.Exhausted || progress.Retired != 2 || progress.Remaining != 0 {
			t.Fatal("the two-original drain did not reach its durable local checkpoint", progress)
		}
		if replay, err := step(ctx, source, 1); err != nil || replay != progress {
			t.Fatal("exhausted local drain did not retain its exact bounded progress", err)
		}
		if index == 0 {
			assertAckDenied(source)
		}
	}
	for _, local := range origins {
		proofErased := "state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL AND handoff_ciphertext IS NULL"
		if local.custody == "proxy_preview_bindings" {
			proofErased = "proof_ciphertext IS NULL"
		}
		var retired bool
		commandBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(command))
		if err != nil {
			t.Fatal(err)
		}
		if err := local.pool.Raw().QueryRow(ctx, `SELECT count(*)=2 AND bool_and(version=3 AND `+proofErased+`
 AND settled_at IS NULL AND retirement_source_command_id=$4 AND retirement_source_version=$5::numeric AND retired_at IS NOT NULL)
 FROM `+pgx.Identifier{local.schema, local.custody}.Sanitize()+` WHERE tenant_id=$1 AND `+local.key+` IN ($2,$3)`,
			string(otpTenant), string(first.Initiation.TransactionID), string(second.Initiation.TransactionID), commandBytes, disable.Next.Version).Scan(&retired); err != nil || !retired {
			t.Fatal("drain lost bearer erasure, exact disable provenance or original unsettled state", local.custody, err)
		}
	}
	wrong := source
	wrong.Generation++
	assertAckDenied(wrong)
	acknowledgement, err := maintenance.Acknowledge(ctx, source)
	if err != nil || acknowledgement.TenantID != source.TenantID || acknowledgement.SourceCommandID != source.SourceCommandID ||
		acknowledgement.CascadeID != source.CascadeID || acknowledgement.Generation != source.Generation || acknowledgement.AcknowledgedAt.IsZero() ||
		acknowledgement.ProductionDeployment != p.production.Native.ProductionDeployment || acknowledgement.PreviewDeployment != c.OAuthProxyPreview.Native.Target.Deployment ||
		acknowledgement.Consumer != (oauthpg.ProviderDisableConsumer{ID: "identity/oauth/proxy", ContractVersion: 1}) {
		t.Fatal("both actual drains did not produce the exact selected-pair acknowledgement", err)
	}
	beforeReplay := snapshot()
	restarted, err := features.NewOAuthProxyMaintenance(production, configuration)
	if err != nil {
		t.Fatal("reconstruct maintenance only from the existing public singleton owners", err)
	}
	if replay, err := restarted.Acknowledge(ctx, source); err != nil || replay != acknowledgement || snapshot() != beforeReplay {
		t.Fatal("restarted maintenance did not return the same sticky acknowledgement without new effects", err)
	}
	reenableCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	reenable := oauthpg.ProviderAuthorityChange{
		Key: disable.Key, ExpectedVersion: disable.Next.Version,
		Next:      oauthpg.ProviderAuthorityState{Version: disable.Next.Version + 1, ProfileVersion: disable.Next.ProfileVersion, Enabled: true},
		CommandID: reenableCommand,
	}
	if state, err := p.operator.Apply(ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("re-enable through the separately authorized native provider operator", err)
	}
	unpairedCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	unpairedDisable := oauthpg.ProviderAuthorityChange{
		Key: disable.Key, ExpectedVersion: reenable.Next.Version,
		Next:      oauthpg.ProviderAuthorityState{Version: reenable.Next.Version + 1, ProfileVersion: reenable.Next.ProfileVersion},
		CommandID: unpairedCommand,
	}
	unpairedAdmission, err := p.operator.ApplyDisableCascade(ctx, unpairedDisable, time.Hour)
	if err != nil || unpairedAdmission.Disable != unpairedDisable || unpairedAdmission.CascadeID == admission.CascadeID {
		t.Fatal("admit a genuinely new native disable without freezing a Reference pair", err)
	}
	unpairedSource := oauthpg.ProxyCustodyFenceSealRequest{
		TenantID: otpTenant, SourceCommandID: unpairedCommand,
		CascadeID: unpairedAdmission.CascadeID, Generation: unpairedAdmission.Generation,
	}
	beforeUnpaired := snapshot()
	if err := maintenance.Seal(ctx, unpairedSource); err == nil || snapshot() != beforeUnpaired {
		t.Fatal("Reference maintenance accepted an unpaired native source or advanced an actual cutoff", err)
	}
	for _, step := range []func(context.Context, oauthpg.ProxyCustodyFenceSealRequest, uint16) (oauthpg.ProxyRetirementDrainProgress, error){maintenance.StepProduction, maintenance.StepPreview} {
		if progress, err := step(ctx, unpairedSource, 1); err == nil || progress != (oauthpg.ProxyRetirementDrainProgress{}) || snapshot() != beforeUnpaired {
			t.Fatal("Reference maintenance traversed unpaired custody or changed either actual cutoff", err)
		}
	}
	var pending bool
	if err := p.productionFixture.pool.Raw().QueryRow(ctx, `SELECT status=$3 FROM `+pgx.Identifier{productionSchema, "provider_disable_cascades"}.Sanitize()+` WHERE tenant_id=$1 AND source_command_id=$2`, string(otpTenant), string(command), int16(identity.RevocationPending)).Scan(&pending); err != nil || !pending {
		t.Fatal("selected-pair acknowledgement incorrectly completed the whole provider cascade", err)
	}
	if p.provider.exchanges.Load() != beforeExchanges || p.provider.proxyRevocations.Load() != beforeRevocations {
		t.Fatal("local maintenance performed an external provider exchange or revocation")
	}
}

func (p *referenceOAuthProxyPreviewProof) startMaintenanceOriginal(t *testing.T, ctx context.Context, c reference.StoreConfiguration, features reference.FeatureSet,
	production *reference.OAuthProxyProduction, app *http.Client, base, origin string) reference.OAuthProxyPreviewStartRequest {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := *app
	browser.Jar = jar
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/session/preauth-issue", strings.NewReader(`{"method":"oauth-proxy","remember":false}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal("issue the second actual preview browser flow", err)
	}
	wire, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	var issued struct {
		Issued bool   `json:"issued"`
		FlowID string `json:"flowID"`
	}
	if readErr != nil || closeErr != nil || len(wire) > 4096 || response.StatusCode != http.StatusOK || json.Unmarshal(wire, &issued) != nil || !issued.Issued {
		t.Fatal("second public preauth issuance did not establish a real browser original")
	}
	flow, err := identity.ParsePreAuthTransactionID(issued.FlowID)
	if err != nil {
		t.Fatal(err)
	}
	flowCookie, err := c.SocialOAuth.Signin.FlowCookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := c.HTTPPreAuth.Device.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewBrowserDeviceCodec(*c.HTTPPreAuth.Device)
	if err != nil {
		t.Fatal(err)
	}
	start := reference.OAuthProxyPreviewStartRequest{Network: "127.0.0.1"}
	for _, cookie := range response.Cookies() {
		if cookie.Name == flowCookie.Name {
			start.FlowCookie = authentication.NewBearerCredential(cookie.Value)
		}
		if cookie.Name == deviceCookie.Name {
			device, err := codec.Resolve(ctx, time.Now(), otpTenant, origin, cookie.Value)
			if err != nil {
				t.Fatal(err)
			}
			start.Device = device.DeviceID()
		}
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, c.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	start.Initiation = oauthproxy.InitiationRequest{
		Credential: authentication.NewBearerCredential("synthetic-production-preview-invocation"), CommandID: command,
		TransactionID: flow, RequestFingerprint: sha256.Sum256([]byte("reference-maintenance-second-original")), Remember: remember,
	}
	if authorization, err := features.StartOAuthProxyPreview(ctx, production, start); err != nil || authorization.URL() == "" {
		t.Fatal("second genuine Start and Bind did not acknowledge both actual owners", err)
	}
	return start
}
