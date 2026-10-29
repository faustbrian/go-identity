//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Only consumer policy is supplied here. Native organization/session/key stores,
// scoped authority, transactions, protected counters and effects remain real.
type organizationKeyConsumerPolicy struct {
	base         *baselineEvaluator
	org          organization.ID
	beforeCreate func(context.Context) error
}

func (p organizationKeyConsumerPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	decision, err := p.base.Evaluate(ctx, r)
	if err != nil || string(r.Tenant) != baselineTenant || r.Subject.ID == "" {
		return decision, err
	}
	if r.Subject.Kind == authorization.SubjectUser && strings.HasPrefix(string(r.Action), "identity.organization.") && (r.Resource.Type == "organization" && r.Resource.ID == authorization.ResourceID(p.org) || r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID)) {
		decision.Outcome = authorization.Allow
	}
	if (r.Subject.Kind == authorization.SubjectUser || r.Subject.Kind == authorization.SubjectAPIKey) && r.Resource.Type == "organization-api-key" && r.Resource.ID == authorization.ResourceID(p.org) {
		switch r.Action {
		case "identity.apikey.create", "identity.apikey.rotate", "identity.apikey.delete", "identity.apikey.import", "invoice.read", "invoice.write":
			if r.Action == "identity.apikey.create" && p.beforeCreate != nil {
				if err := p.beforeCreate(ctx); err != nil {
					return authorization.Decision{}, err
				}
			}
			decision.Outcome = authorization.Allow
			if r.Action == "invoice.write" && p.base.deniedGrant != nil && p.base.deniedGrant.Load() {
				decision.Outcome = authorization.Deny
			}
		}
	}
	if r.Subject.Kind == authorization.SubjectAPIKey && r.Action == "identity.apikey.verify" && r.Resource.Type == "identity.anonymous-flow" {
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

func organizationKeyOwners(t *testing.T, f nativeConsumerFixture, id organization.ID) (*organizationpg.Service, *organizationpg.Repository, apikeypg.ServiceConfig) {
	t.Helper()
	config := f.config
	legacy := config.Configuration.Spec()
	legacy.ID, legacy.Algorithm, legacy.State = "legacy", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	var err error
	config.LegacyConfiguration, err = apikey.NewConfiguration(legacy)
	if err != nil {
		t.Fatal(err)
	}
	config.ValidateCanonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id != "01ARZ3NDEKTSV4RRFFQ69G5FAZ" && id != "01ARZ3NDEKTSV4RRFFQ69G5FAY" {
			return apikey.ErrInvalid
		}
		return nil
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-key-consumer", Revision: 9, Evaluator: organizationKeyConsumerPolicy{base: &baselineEvaluator{deniedGrant: f.deniedGrant, deniedManagement: f.deniedManagement}, org: id}})
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
	query, admission := *config.Coordinator.QueryPolicy, *config.Coordinator.AdmissionPolicy
	query.Authorization, admission.Authorization = config.Authorization, config.Authorization
	config.Coordinator.QueryPolicy, config.Coordinator.AdmissionPolicy = &query, &admission
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	participant, err := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: config.Session, Profile: config.Profile, LookupKeys: config.LookupKeys, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{directory, audits, outbox, config.Counters, participant})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(f.pool, registry, config.Coordinator)
	if err != nil {
		t.Fatal(err)
	}
	service, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}}, Sessions: config.Sessions, Authorization: config.Authorization, Risk: config.Counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, config
}

func installOrganizationKeyOwners(t *testing.T, f nativeConsumerFixture) {
	t.Helper()
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_owned_keys")
	if err != nil {
		t.Fatal(err)
	}
	var steps []migrations.Migration
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 1}, organizationpg.CredentialAuthorityMigrationSource{Version: 2}, apikeypg.OrganizationMigrationSource{Version: 3}} {
		loaded, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, loaded...)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated independent organization key migrations", err)
	}
	legacyBackend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	legacyBackend, err = legacyBackend.ForNamespace("identity_api_keys")
	if err != nil {
		t.Fatal(err)
	}
	legacyRunner, err := migrations.NewRunner(apikeypg.LegacyMigrationSource{Base: apikeypg.MigrationSource{Version: 7100}, Version: 7101}, legacyBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyRunner.Up(f.ctx); err != nil {
		t.Fatal("selected legacy key migration over retained base history", err)
	}
}

func TestGenuineOrganizationKeySurvivesCreatorRemoval(t *testing.T) {
	proveGenuineOrganizationKeySurvivesCreatorRemoval(t, false)
}

func TestGenuineOrganizationNoExpiryKeySurvivesCreatorRemoval(t *testing.T) {
	proveGenuineOrganizationKeySurvivesCreatorRemoval(t, true)
}

func proveGenuineOrganizationKeySurvivesCreatorRemoval(t *testing.T, noExpiry bool) {
	t.Helper()
	f := setupNativeConsumer(t)
	self, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := self.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	selfID, _ := identity.NewIdempotencyKey([]byte("self-key-before-organization-migration"))
	selfIssued, err := self.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: selfID, Name: "retained self key", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"})
	if err != nil {
		t.Fatal("preexisting user-owned key", err)
	}
	selfRecord, _ := selfIssued.Record()
	selfWire, err := selfIssued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	installOrganizationKeyOwners(t, f)
	selfSecret, _ := apikey.ParseSecret(selfWire)
	selfResult, err := self.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: f.config.Configuration.Spec().ID, ConfigurationRevision: f.config.Configuration.Spec().Revision, Secret: selfSecret, RequiredPermissions: []string{"invoice.read"}})
	if err != nil || selfResult.Result == nil || selfResult.Result.Record.ID != selfRecord.ID || selfResult.Result.Owner != selfRecord.Owner {
		t.Fatal("organization migration changed existing user-key authority", err)
	}
	orgID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(orgID))
	legacySpec := config.LegacyConfiguration.Spec()
	legacySpec.AllowLegacyNoExpiry = noExpiry
	config.LegacyConfiguration, err = apikey.NewConfiguration(legacySpec)
	if err != nil {
		t.Fatal(err)
	}
	authentication := func(a apikey.Authentication) organization.Authentication {
		return organization.Authentication{TenantID: a.TenantID, Bearer: a.Bearer}
	}
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: authentication(f.caller), CommandID: commandID(t), ID: organization.ID(orgID), Slug: "independent-key", Name: "Independent key owner", CorrelationID: "organization-key-create-owner"}, "192.0.2.20")
	if err != nil {
		t.Fatal("prepare actual organization creation", err)
	}
	if result, err := org.Execute(f.ctx, create); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine organization creation", err)
	}
	second, secondID := f.register()
	add, err := org.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: authentication(f.caller), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: secondID, Role: organization.RoleOwner, OrganizationVersion: 1, CorrelationID: "organization-key-add-owner"}, "192.0.2.20")
	if err != nil {
		t.Fatal("prepare actual owner admission", err)
	}
	if result, err := org.Execute(f.ctx, add); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine second owner admission", err)
	}
	service, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CheckConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeLegacyConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("organization-key-original-create"))
	request := apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "independent automation", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"}, OrganizationID: apikey.OrganizationID(orgID)}
	issued, err := service.CreateOrganization(f.ctx, request)
	if err != nil {
		t.Fatal("actual organization-owned key issuance", err)
	}
	record, ok := issued.Record()
	if !ok || record.Owner.Spec().Kind != apikey.OwnerOrganization || record.Owner.Spec().OrganizationID != apikey.OrganizationID(orgID) || record.Owner.Spec().UserID != "" {
		t.Fatal("organization issuance fabricated a creator owner")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := service.CreateOrganization(f.ctx, request)
	if err != nil {
		t.Fatal("original organization issuance retry", err)
	}
	if recovered, ok := duplicate.Record(); !ok || recovered.ID != record.ID {
		t.Fatal("organization retry changed chosen key")
	}
	if _, err := duplicate.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("organization retry revealed original secret again")
	}
	original, err := issued.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	foreign := request
	foreign.Authentication.TenantID = "unrelated-tenant"
	if out, err := service.CreateOrganization(f.ctx, foreign); err == nil || out.DeliveryOutcome() == apikey.IssuanceCommittedAndRevealed {
		t.Fatal("foreign tenant acquired organization-key management")
	}
	wrongID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	wrong := request
	wrong.OrganizationID = apikey.OrganizationID(wrongID)
	if out, err := service.CreateOrganization(f.ctx, wrong); err == nil || out.DeliveryOutcome() == apikey.IssuanceCommittedAndRevealed {
		t.Fatal("original key request selected an unrelated organization")
	}
	if out, err := service.RecoverOrganization(f.ctx, apikey.OrganizationID(wrongID), apikey.RecoveryRequest{Authentication: f.caller, Query: original}); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("wrong organization disclosed original management outcome")
	}
	foreignRecovery := apikey.RecoveryRequest{Authentication: foreign.Authentication, Query: original}
	if out, err := service.RecoverOrganization(f.ctx, request.OrganizationID, foreignRecovery); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant disclosed organization command outcome")
	}
	legacyRecord := record
	legacyRecord.ID, legacyRecord.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ", "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	legacyRecord.Version, legacyRecord.AuthorityVersion, legacyRecord.RootVersion = 3, 2, 2
	legacyRecord.ConfigurationID = config.LegacyConfiguration.Spec().ID
	legacyRecord.CreatedAt = time.Now().UTC().Add(-500 * 24 * time.Hour).Truncate(time.Microsecond)
	legacyRecord.ExpiresAt = time.Now().UTC().Add(500 * 24 * time.Hour).Truncate(time.Microsecond)
	if noExpiry {
		legacyRecord.ExpiresAt = time.Time{}
	}
	bare := "organization-bare-" + string(commandID(t))
	legacyDigest, _ := apikey.NewLegacyDigest(sha256.Sum256([]byte(bare)))
	importKey, _ := identity.NewIdempotencyKey([]byte("organization-key-original-legacy-import"))
	importRequest := apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: importKey, Record: legacyRecord, Digest: legacyDigest, SourceID: "authenticated-source", SourceVersion: 7, Network: "192.0.2.21"}
	imported, err := service.Import(f.ctx, importRequest)
	if err != nil || imported.Outcome != identity.CommitOutcomeCommitted || imported.Binding.RecordID != string(legacyRecord.ID) {
		t.Fatal("organization digest-only import lost source identity/versions", err)
	}
	importRequest.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("organization-key-same-source-new-key"))
	if repeated, err := service.Import(f.ctx, importRequest); err != nil || repeated.Binding != imported.Binding || repeated.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization source retry did not retain the original human command", err)
	}
	var directRevocation apikey.ImportRequest
	var directSecret apikey.LegacySecret
	if noExpiry {
		directRevocation = importRequest
		directRevocation.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("organization-no-expiry-direct-revoke-import"))
		directRevocation.Record.ID, directRevocation.Record.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAY", "01ARZ3NDEKTSV4RRFFQ69G5FAY"
		directRevocation.Digest, _ = apikey.NewLegacyDigest(sha256.Sum256([]byte(bare + "-direct-revoke")))
		directSecret, _ = apikey.ParseLegacySecret(bare + "-direct-revoke")
		if out, err := service.Import(f.ctx, directRevocation); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual no-expiry organization revocation specimen import failed", err)
		}
	}
	if result, err := service.RecoverOrganization(f.ctx, apikey.OrganizationID(orgID), apikey.RecoveryRequest{Authentication: f.caller, Query: original}); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("explicit organization status recovery lost original owner", err)
	}
	rollback := request
	rollback.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("organization-key-required-effect-rollback"))
	var rollbackReceipt identity.CommandResult
	rejectMutationAudit(t, f.ctx, f.pool, "identity.api_key.create", func() {
		out, err := service.CreateOrganization(f.ctx, rollback)
		if err == nil || out.DeliveryOutcome() == apikey.IssuanceCommittedAndRevealed {
			t.Fatal("organization key survived unavailable required audit")
		}
		rollbackReceipt, _ = out.Receipt()
		if _, err := out.Reveal(); err == nil {
			t.Fatal("rolled-back organization key exposed invocation material")
		}
	})
	if rollbackReceipt.Binding.CommandID == "" || rollbackReceipt.Binding.RecordID == "" {
		t.Fatal("required-effect failure lost original recovery binding")
	}
	var rollbackRows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, baselineTenant, rollbackReceipt.Binding.RecordID).Scan(&rollbackRows); err != nil || rollbackRows != 0 {
		t.Fatal("required-effect failure retained organization credential authority", err)
	}
	unknownRequest := request
	unknownRequest.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("organization-key-lost-commit-acknowledgement"))
	fault := &legacyCommitFault{marker: []byte("INSERT INTO identity_api_keys.keys")}
	faultPool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := faultPool.Close(ctx); err != nil {
			t.Error("organization fault pool cleanup", err)
		}
	})
	faultService, err := apikeypg.NewOrganizationService(faultPool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := faultService.CreateOrganization(f.ctx, unknownRequest)
	unknownReceipt, receiptErr := unknown.Receipt()
	if err == nil || receiptErr != nil || !fault.hit.Load() || unknown.DeliveryOutcome() != apikey.IssuanceCommitUnknown || unknownReceipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost organization COMMIT acknowledgement was not preserved as unknown")
	}
	if _, err := unknown.Reveal(); err == nil {
		t.Fatal("organization unknown commit revealed plaintext")
	}
	recoveredUnknown, err := service.CreateOrganization(f.ctx, unknownRequest)
	recoveredUnknownReceipt, receiptErr := recoveredUnknown.Receipt()
	if err != nil || receiptErr != nil || recoveredUnknownReceipt.Binding != unknownReceipt.Binding || recoveredUnknownReceipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization unknown commit could not reconcile its exact original", err)
	}
	if _, err := recoveredUnknown.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("organization unknown recovery reconstructed original plaintext")
	}
	remove, err := org.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: authentication(second), CommandID: commandID(t), OrganizationID: organization.ID(orgID), UserID: f.user, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "organization-key-remove-creator"}, "192.0.2.22")
	if err != nil {
		t.Fatal(err)
	}
	// Change actual membership after the key service observes it, from the
	// external policy callback before Work acquires its native authority fences.
	var removed atomic.Bool
	staleConfig := config
	staleSnapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-key-consumer", Revision: 9, Evaluator: organizationKeyConsumerPolicy{base: &baselineEvaluator{deniedGrant: f.deniedGrant, deniedManagement: f.deniedManagement}, org: organization.ID(orgID), beforeCreate: func(ctx context.Context) error {
		if removed.CompareAndSwap(false, true) {
			result, err := org.Execute(ctx, remove)
			if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
				return errors.Join(errors.New("actual creator membership removal during policy evaluation failed"), err)
			}
		}
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	staleEngine, err := authorization.NewEngine(staleSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	staleConfig.Authorization, err = authorization.NewDecisionService(staleEngine)
	if err != nil {
		t.Fatal(err)
	}
	staleQuery, staleAdmission := *config.Coordinator.QueryPolicy, *config.Coordinator.AdmissionPolicy
	staleQuery.Authorization, staleAdmission.Authorization = staleConfig.Authorization, staleConfig.Authorization
	staleConfig.Coordinator.QueryPolicy, staleConfig.Coordinator.AdmissionPolicy = &staleQuery, &staleAdmission
	staleService, err := apikeypg.NewOrganizationService(f.pool, staleConfig, repository)
	if err != nil {
		t.Fatal(err)
	}
	staleRequest := request
	staleRequest.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("organization-membership-removed-after-observation"))
	var beforeStale int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2`, baselineTenant, string(orgID)).Scan(&beforeStale); err != nil {
		t.Fatal(err)
	}
	staleResult, staleErr := staleService.CreateOrganization(f.ctx, staleRequest)
	if staleErr == nil || !removed.Load() || staleResult.DeliveryOutcome() == apikey.IssuanceCommittedAndRevealed {
		t.Fatal("stale observed membership admitted organization-key issuance")
	}
	if _, err := staleResult.Reveal(); err == nil {
		t.Fatal("stale authority revealed a credential")
	}
	var staleRows int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2`, baselineTenant, string(orgID)).Scan(&staleRows); err != nil || staleRows != beforeStale {
		t.Fatal("stale membership escaped protected Work fence", err)
	}
	secret, _ := apikey.ParseSecret(wire)
	verify := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: config.Configuration.Spec().ID, ConfigurationRevision: config.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{"invoice.read"}}
	verified, err := service.VerifyAndConsume(f.ctx, verify)
	if err != nil || verified.Validate() != nil || verified.Result == nil || verified.Result.Owner != record.Owner || verified.Original.UserID != "" || verified.Original.ActorID != identity.ActorID(record.ID) {
		t.Fatal("creator removal revoked independent organization key", err)
	}
	legacySecret, _ := apikey.ParseLegacySecret(bare)
	legacyVerified, err := service.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: config.LegacyConfiguration.Spec().ID, ConfigurationRevision: config.LegacyConfiguration.Spec().Revision, LegacySecret: legacySecret, RequiredPermissions: []string{"invoice.read"}})
	if err != nil || legacyVerified.Result == nil || legacyVerified.Result.Record.ID != legacyRecord.ID || legacyVerified.Result.Record.Version != 3 || legacyVerified.Result.Owner != record.Owner || legacyVerified.Original.UserID != "" || !legacyVerified.Result.Record.ExpiresAt.Equal(legacyRecord.ExpiresAt) || legacyVerified.Result.ValidUntil.After(legacyVerified.Result.ReadStartedAt.Add(20*time.Second)) {
		t.Fatal("creator removal changed bare organization-key verification or source versions", err)
	}
	query := apikey.VerificationReconcileQuery{AttemptID: verify.AttemptID, TenantID: verify.TenantID, Fingerprint: verified.Fingerprint, Original: verified.Original}
	replay, err := service.ReconcileVerifyAndConsume(f.ctx, query)
	if err != nil || replay.Result == nil || !replay.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) || !replay.Result.ValidUntil.Equal(verified.Result.ValidUntil) {
		t.Fatal("organization reconciliation repeated authentication or renewed freshness", err)
	}
	unselected, err := apikeypg.NewService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []apikey.AtomicVerificationRequest{verify, {AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: verify.TenantID, ConfigurationID: verify.ConfigurationID, ConfigurationRevision: verify.ConfigurationRevision, Secret: secret, RequiredPermissions: []string{"invoice.read"}}} {
		if out, err := unselected.VerifyAndConsume(f.ctx, attempt); err == nil || out.Result != nil {
			t.Fatal("unselected service acquired organization authentication from fresh use or replay")
		}
	}
	if out, err := unselected.ReconcileVerifyAndConsume(f.ctx, query); err == nil || out.Result != nil {
		t.Fatal("unselected service acquired organization principal from recorded history")
	}
	if _, err := service.CreateOrganization(f.ctx, request); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("removed creator retained management or original recovery", err)
	}
	if result, err := service.RecoverOrganization(f.ctx, apikey.OrganizationID(orgID), apikey.RecoveryRequest{Authentication: f.caller, Query: original}); !errors.Is(err, apikey.ErrDenied) || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("removed creator retained explicit outcome disclosure", err)
	}
	rotationKey, _ := identity.NewIdempotencyKey([]byte("organization-key-other-owner-rotate"))
	rotationTarget := record
	if noExpiry {
		rotationTarget = legacyVerified.Result.Record
	}
	rotated, err := service.Rotate(f.ctx, apikey.Rotation{Authentication: second, IdempotencyKey: rotationKey, KeyID: rotationTarget.ID, ExpectedVersion: rotationTarget.Version, Network: "192.0.2.22"})
	if err != nil {
		t.Fatal("remaining actual owner cannot rotate", err)
	}
	successor, ok := rotated.Record()
	if !ok || successor.Owner != rotationTarget.Owner || successor.PreviousID != rotationTarget.ID || successor.ID == rotationTarget.ID || !slices.Equal(successor.Grant, rotationTarget.Grant) || successor.ConfigurationID != config.Configuration.Spec().ID || successor.ExpiresAt.IsZero() || !successor.ExpiresAt.After(successor.CreatedAt) || successor.ExpiresAt.Sub(successor.CreatedAt) > config.Configuration.Spec().MaximumLifetime {
		t.Fatal("organization rotation changed immutable owner or lineage")
	}
	if _, err := rotated.Reveal(); err != nil {
		t.Fatal(err)
	}
	revokeKey, _ := identity.NewIdempotencyKey([]byte("organization-key-other-owner-revoke"))
	if result, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: second, IdempotencyKey: revokeKey, KeyID: successor.ID, ExpectedVersion: successor.Version, Network: "192.0.2.22"}); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("remaining owner cannot revoke organization key", err)
	}
	if noExpiry {
		verifyLegacy := func(secret apikey.LegacySecret) (apikey.AtomicVerificationResult, error) {
			return service.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: config.LegacyConfiguration.Spec().ID, ConfigurationRevision: config.LegacyConfiguration.Spec().Revision, LegacySecret: secret, RequiredPermissions: []string{"invoice.read"}})
		}
		if out, err := verifyLegacy(legacySecret); err == nil || out.Result != nil {
			t.Fatal("no-expiry organization predecessor remained usable after rotation")
		}
		current, err := verifyLegacy(directSecret)
		if err != nil || current.Result == nil || current.Result.Record.ID != directRevocation.Record.ID || !current.Result.Record.ExpiresAt.IsZero() {
			t.Fatal("surviving owner lost the genuine no-expiry direct-revoke specimen", err)
		}
		directKey, _ := identity.NewIdempotencyKey([]byte("organization-no-expiry-direct-revoke"))
		if out, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: second, IdempotencyKey: directKey, KeyID: directRevocation.Record.ID, ExpectedVersion: current.Result.Record.Version, Network: "192.0.2.22"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("surviving owner cannot directly revoke absent-expiry organization key", err)
		}
		if out, err := verifyLegacy(directSecret); err == nil || out.Result != nil {
			t.Fatal("directly revoked no-expiry organization key retained authority")
		}
	}
	newKey, _ := identity.NewIdempotencyKey([]byte("organization-key-before-owner-archive"))
	request.Authentication, request.IdempotencyKey = second, newKey
	archiveKey, err := service.CreateOrganization(f.ctx, request)
	if err != nil {
		t.Fatal("current owner cannot issue independent archive specimen", err)
	}
	archiveWire, err := archiveKey.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	archiveSecret, _ := apikey.ParseSecret(archiveWire)
	// Exercise a mixed older state-only writer at the authoritative owner seam.
	// The organization's own optional trigger owns terminal epoch advancement.
	for _, state := range []string{"archived", "active"} {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state=$3,version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, baselineTenant, string(orgID), state); err != nil {
			t.Fatal("mixed-writer owner transition", err)
		}
		attempt := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: verify.TenantID, ConfigurationID: verify.ConfigurationID, ConfigurationRevision: verify.ConfigurationRevision, Secret: archiveSecret, RequiredPermissions: []string{"invoice.read"}}
		if out, err := service.VerifyAndConsume(f.ctx, attempt); err == nil || out.Result != nil {
			t.Fatal("archive or restore resurrected previous organization credential authority", state)
		}
	}
}

func TestOrganizationKeyNarrowIsAtomicAndCannotExpand(t *testing.T) {
	f := setupNativeConsumer(t)
	installOrganizationKeyOwners(t, f)
	orgID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	org, repository, config := organizationKeyOwners(t, f, organization.ID(orgID))
	create, err := org.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: organization.Authentication{TenantID: f.caller.TenantID, Bearer: f.caller.Bearer}, CommandID: commandID(t), ID: organization.ID(orgID), Slug: "narrow-key", Name: "Narrow key owner", CorrelationID: "organization-narrow-owner"}, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := org.Execute(f.ctx, create); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine organization creation", err)
	}
	service, err := apikeypg.NewOrganizationService(f.pool, config, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("organization-policy-reduction"))
	request := apikey.OrganizationCreateRequest{CreateRequest: apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "policy reduction", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.21"}, OrganizationID: apikey.OrganizationID(orgID)}
	issued, err := service.CreateOrganization(f.ctx, request)
	if err != nil {
		t.Fatal("organization policy-reduction specimen issuance", err)
	}
	record, _ := issued.Record()
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := apikey.ParseSecret(wire)
	attempt := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: config.Configuration.Spec().ID, ConfigurationRevision: config.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{"invoice.write"}}
	f.deniedGrant.Store(true)
	rejectMutationAudit(t, f.ctx, f.pool, "identity.api_key.update", func() {
		out, err := service.VerifyAndConsume(f.ctx, attempt)
		if err == nil || out.Result != nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("organization policy reduction survived unavailable required effect")
		}
	})
	assertStoredKeyState(t, f.ctx, f.pool, baselineTenant, record.ID, apikey.KeyActive, 1, 1)
	attempt.AttemptID = apikey.VerificationAttemptID(commandID(t))
	if out, err := service.VerifyAndConsume(f.ctx, attempt); !errors.Is(err, apikey.ErrDenied) || out.Result != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization policy denial did not commit durable Narrow", err)
	}
	assertStoredKeyState(t, f.ctx, f.pool, baselineTenant, record.ID, apikey.KeyActive, 2, 2)
	f.deniedGrant.Store(false)
	attempt.AttemptID = apikey.VerificationAttemptID(commandID(t))
	if out, err := service.VerifyAndConsume(f.ctx, attempt); !errors.Is(err, apikey.ErrDenied) || out.Result != nil {
		t.Fatal("restored organization policy re-expanded the key ceiling", err)
	}
	attempt.AttemptID, attempt.RequiredPermissions = apikey.VerificationAttemptID(commandID(t)), []string{"invoice.read"}
	if out, err := service.VerifyAndConsume(f.ctx, attempt); err != nil || out.Result == nil || len(out.Result.Record.Grant) != 1 || out.Result.Record.Grant[0] != "invoice.read" {
		t.Fatal("organization retained permission was not independently usable", err)
	}
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("independent-key-after-organization-policy-reduction"))
	if _, err := service.CreateOrganization(f.ctx, request); err != nil {
		t.Fatal("one key's narrowing denied independent current-authorized creation", err)
	}
}
