//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
)

func TestNativeLegacySourceAuthorityUsesActualImportedUSERKey(t *testing.T) {
	f := setupNativeConsumer(t)
	c := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}})
	spec := c.Configuration.Spec()
	spec.ID, spec.Algorithm, spec.State = "legacy", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	spec.AllowLegacyNoExpiry = true
	var err error
	c.LegacyConfiguration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	const keyID apikey.KeyID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	c.ValidateCanonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id != keyID {
			return apikey.ErrInvalid
		}
		return nil
	}
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("identity_api_keys")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(apikeypg.LegacyMigrationSource{Base: apikeypg.MigrationSource{Version: 7100}, Version: 7101}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
	service, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeLegacyConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	requestID := func(text string) identity.IdempotencyKey {
		key, err := identity.NewIdempotencyKey([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	modern, err := service.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: requestID("legacy-source-modern-create"), Name: "still modern", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.11"})
	if err != nil {
		t.Fatal("legacy selection changed modern issuance", err)
	}
	modernRecord, ok := modern.Record()
	modernWire, revealErr := modern.Reveal()
	_, parseErr := apikey.ParseSecret(modernWire)
	modernWire = ""
	if !ok || revealErr != nil || parseErr != nil || modernRecord.ConfigurationID != c.Configuration.Spec().ID || modernRecord.ExpiresAt.IsZero() {
		t.Fatal("new issuance did not retain its modern finite profile")
	}
	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := directory.GetStatus(f.ctx, identity.UserStatusQuery{TenantID: baselineTenant, UserID: f.user})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: baselineTenant, Kind: apikey.OwnerUser, UserID: f.user, Version: status.AuthorityVersion})
	if err != nil {
		t.Fatal(err)
	}
	bare := "unchanged-existing-bare-" + string(commandID(t))
	digest, err := apikey.NewLegacyDigest(sha256.Sum256([]byte(bare)))
	if err != nil {
		t.Fatal(err)
	}
	request := apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: requestID("legacy-source-original-import"), Record: apikey.Record{ID: keyID, Owner: owner, Version: 3, AuthorityVersion: 2, ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: time.Now().UTC().Add(-500 * 24 * time.Hour).Truncate(time.Microsecond), RootID: keyID, RootVersion: 2, Issuer: spec.Issuer, Environment: spec.Environment, Audience: spec.Audience}, Digest: digest, SourceID: "authenticated-source", SourceVersion: 7, Network: "192.0.2.11"}
	imported, err := service.Import(f.ctx, request)
	if err != nil || imported.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine digest-only source import", err)
	}
	secret, err := apikey.ParseLegacySecret(bare)
	bare = ""
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: spec.ID, ConfigurationRevision: spec.Revision, LegacySecret: secret, RequiredPermissions: []string{"invoice.read"}})
	secret = apikey.LegacySecret{}
	if err != nil || verified.Result == nil || verified.State != apikey.VerificationAttemptNotApplicable || verified.Result.Record.ID != keyID || !verified.Result.Record.ExpiresAt.IsZero() {
		t.Fatal("unchanged bare credential failed its real existing verifier", err)
	}
	binding, err := apikey.NewSourceAuthorityBinding(*verified.Result, c.LegacyConfiguration, time.Now().UTC())
	if err != nil {
		t.Fatal("genuinely verified legacy USER key cannot supply source binding", err)
	}
	observed, err := service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || observed.Validate(binding, c.LegacyConfiguration, time.Now().UTC()) != nil || !observed.Record.ExpiresAt.IsZero() || !slices.Equal(observed.Grant, binding.Grant) || observed.ValidUntil.After(observed.ReadStartedAt.Add(20*time.Second)) {
		t.Fatal("selected legacy source observation lost original restrictions or bounded freshness", err)
	}
	f.config = c
	coordinator, work, command := prepareSourceFence(t, f, service, observed, false)
	result, err := coordinator.ApplyFeature(f.ctx, work, command)
	if err != nil {
		t.Fatal("actual API-key actor could not use legacy source in real Work", err)
	}
	committed, err := coordinator.Commit(work, result)
	if err != nil || committed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy source failed its final real Work fence", err)
	}
	current, err := service.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: keyID})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: requestID("legacy-source-revoke"), KeyID: keyID, ExpectedVersion: current.Record.Version, Network: "192.0.2.11"})
	if err != nil || revoked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(err)
	}
	if out, err := service.ObserveSourceAuthority(f.ctx, binding); err == nil || out.Record.ID != "" {
		t.Fatal("revoked imported root retained current source authority")
	}
	if replay, err := service.Import(f.ctx, request); err != nil || replay.Binding != imported.Binding {
		t.Fatal("original digest-only import lost status-only recovery", err)
	}
	current, err = service.Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: keyID})
	if err != nil || current.Record.Status != apikey.KeyRevoked || !current.Record.ExpiresAt.IsZero() {
		t.Fatal("identical import resurrected or rewrote revoked legacy material", err)
	}
}
