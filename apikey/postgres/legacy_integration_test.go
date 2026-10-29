//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestGenuineLegacyDigestImportVerificationAndModernRotation(t *testing.T) {
	f := setupNativeConsumer(t)
	ctx, c := f.ctx, f.config
	key := func(text string) identity.IdempotencyKey {
		out, err := identity.NewIdempotencyKey([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	modern, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := modern.InitializeConfiguration(ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	create := apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key("modern-before-legacy-migration"), Name: "existing modern", Permissions: []string{"invoice.read"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.11"}
	issued, err := modern.Create(ctx, create)
	if err != nil {
		t.Fatal("populated modern baseline failed", err)
	}
	modernWire, err := issued.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	before, ok := issued.Record()
	if !ok {
		t.Fatal("populated modern key missing")
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
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("populated legacy migration failed", err)
	}
	legacySpec := c.Configuration.Spec()
	legacySpec.ID, legacySpec.Algorithm, legacySpec.State = "legacy", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	c.LegacyConfiguration, err = apikey.NewConfiguration(legacySpec)
	if err != nil {
		t.Fatal(err)
	}
	unsupported := c
	unsupportedSpec := legacySpec
	unsupportedSpec.PermissionReduction = apikey.PermissionReductionRevoke
	unsupported.LegacyConfiguration, err = apikey.NewConfiguration(unsupportedSpec)
	if err != nil {
		t.Fatal(err)
	}
	unsupported.ValidateCanonicalKeyID = func(context.Context, apikey.KeyID) error { return nil }
	if _, err := apikeypg.NewService(f.pool, unsupported); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("native constructor admitted unsupported legacy Revoke lifecycle", err)
	}
	c.ValidateCanonicalKeyID = func(ctx context.Context, id apikey.KeyID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(id) != 26 || !strings.HasPrefix(string(id), "01ARZ3NDEKTSV4RRFFQ69G5F") {
			return apikey.ErrInvalid
		}
		return nil
	}
	s, err := apikeypg.NewService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeLegacyConfiguration(ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckLegacyConfiguration(ctx, baselineTenant); err != nil {
		t.Fatal("exact installed legacy profile was not observed", err)
	}
	// Reconstructing after additive migration must keep the exact old prepared
	// configuration/request bytes; retry never generates another modern key.
	retry, err := s.Create(ctx, create)
	if err != nil {
		t.Fatal("modern original retry changed after legacy enablement", err)
	}
	retained, ok := retry.Record()
	if !ok || retained.ID != before.ID {
		t.Fatal("modern original correlation changed")
	}
	if _, err := retry.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("modern original retry re-revealed")
	}
	modernSecret, _ := apikey.ParseSecret(modernWire)
	modernVerified, err := s.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Secret: modernSecret, RequiredPermissions: []string{"invoice.read"}})
	if err != nil || modernVerified.Result == nil || modernVerified.Result.Record.ID != before.ID {
		t.Fatal("populated modern key no longer authenticates", err)
	}

	directory, err := kernel.NewRepository(f.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	status, err := directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: baselineTenant, UserID: f.user})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: baselineTenant, Kind: apikey.OwnerUser, UserID: f.user, Version: status.AuthorityVersion})
	created := time.Now().UTC().Add(-500 * 24 * time.Hour).Truncate(time.Microsecond)
	expires := time.Now().UTC().Add(500 * 24 * time.Hour).Truncate(time.Microsecond)
	id := apikey.KeyID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	raw := "historical-bare-" + string(commandID(t))
	digest, _ := apikey.NewLegacyDigest(sha256.Sum256([]byte(raw)))
	r := apikey.ImportRequest{Authentication: f.caller, IdempotencyKey: key("legacy-original-import"), Record: apikey.Record{ID: id, Owner: owner, Version: 3, AuthorityVersion: 2, ConfigurationID: legacySpec.ID, ConfigurationRevision: legacySpec.Revision, Name: "historical integration", Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: created, ExpiresAt: expires, RootID: id, RootVersion: 2, PreviousID: "01ARZ3NDEKTSV4RRFFQ69G5FAT", Issuer: legacySpec.Issuer, Environment: legacySpec.Environment, Audience: legacySpec.Audience}, Digest: digest, SourceID: "authenticated-source", SourceVersion: 7, Network: "192.0.2.11"}
	r.Record.Name = ""
	imported, err := s.Import(ctx, r)
	if err != nil || imported.Outcome != identity.CommitOutcomeCommitted || imported.Binding.RecordID != string(id) {
		t.Fatal("digest-only import did not commit exact ID", err)
	}
	assertAttemptAudit(t, ctx, f.pool, imported.Binding.CommandID, "identity.api_key.import", audit.OutcomeSucceeded)
	commandBytes, err := base64.RawURLEncoding.Strict().DecodeString(string(imported.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var createdEvents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND r.action='identity.api_key.create'`, baselineTenant, commandBytes).Scan(&createdEvents); err != nil || createdEvents != 0 {
		t.Fatal("legacy import emitted a new issuance event")
	}
	repeated, err := s.Import(ctx, r)
	if err != nil || repeated.Binding != imported.Binding {
		t.Fatal("original import repeat changed correlation", err)
	}
	otherRequest := r
	otherRequest.IdempotencyKey = key("legacy-same-source-another-request")
	if repeated, err := s.Import(ctx, otherRequest); err != nil || repeated.Binding != imported.Binding {
		t.Fatal("same-source repeat created another import", err)
	}
	conflict := r
	conflict.IdempotencyKey = key("legacy-conflicting-source")
	conflict.Record.Name = "conflicting snapshot"
	var sourceConflict identity.ConflictError
	if _, err := s.Import(ctx, conflict); !errors.As(err, &sourceConflict) {
		t.Fatal("same-ID conflicting import was accepted", err)
	}
	stale := r
	stale.IdempotencyKey = key("legacy-stale-source")
	stale.SourceVersion--
	var staleImport apikey.StaleImportError
	if _, err := s.Import(ctx, stale); !errors.As(err, &staleImport) {
		t.Fatal("stale source version did not return typed denial", err)
	}
	newerTombstone := r
	newerTombstone.IdempotencyKey, newerTombstone.SourceVersion, newerTombstone.Record.Status = key("legacy-newer-tombstone-explicit-conflict"), r.SourceVersion+1, apikey.KeyRevoked
	if out, err := s.Import(ctx, newerTombstone); !errors.As(err, &sourceConflict) || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("unsupported source update silently reported tombstone import success", err)
	}
	unauthorized := r
	unauthorized.SourceID, unauthorized.IdempotencyKey = "unapproved-source", key("legacy-unapproved-source")
	if _, err := s.Import(ctx, unauthorized); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("unapproved source reached import authority", err)
	}
	foreign := r
	foreign.Record.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: baselineTenant, Kind: apikey.OwnerUser, UserID: "another-user", Version: 1})
	foreign.IdempotencyKey = key("legacy-foreign-owner")
	if _, err := s.Import(ctx, foreign); !errors.Is(err, apikey.ErrDenied) {
		t.Fatal("authenticated actor imported a foreign user key", err)
	}
	exhausted := r
	exhausted.IdempotencyKey, exhausted.Record.ID, exhausted.Record.RootID, exhausted.Record.Version = key("legacy-exhausted-active-version"), "01ARZ3NDEKTSV4RRFFQ69G5FAZ", "01ARZ3NDEKTSV4RRFFQ69G5FAZ", ^uint64(0)
	exhausted.Digest, _ = apikey.NewLegacyDigest(sha256.Sum256([]byte(raw + "-exhausted")))
	if out, err := s.Import(ctx, exhausted); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("active exhausted source version became usable authority")
	}

	legacySecret, _ := apikey.ParseLegacySecret(raw)
	knownRequest := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: legacySpec.ID, ConfigurationRevision: legacySpec.Revision, LegacySecret: legacySecret, RequiredPermissions: []string{"invoice.read"}}
	verify := func(secret apikey.LegacySecret) (apikey.AtomicVerificationResult, error) {
		return s.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: legacySpec.ID, ConfigurationRevision: legacySpec.Revision, LegacySecret: secret, RequiredPermissions: []string{"invoice.read"}})
	}
	verified, err := s.VerifyAndConsume(ctx, knownRequest)
	if err != nil || verified.Result == nil || verified.Result.Record.ID != id || verified.Result.Owner != owner || !verified.Result.Record.CreatedAt.Equal(created) || !verified.Result.Record.ExpiresAt.Equal(expires) || verified.State != apikey.VerificationAttemptNotApplicable {
		t.Fatal("unchanged historical bare token or restrictions changed", err)
	}
	statusQuery := apikey.VerificationReconcileQuery{AttemptID: verified.AttemptID, TenantID: baselineTenant, Fingerprint: verified.Fingerprint, Original: verified.Original}
	if observed, err := s.ReconcileVerifyAndConsume(ctx, statusQuery); err != nil || observed.Result == nil || !observed.Result.ValidUntil.Equal(verified.Result.ValidUntil) || !observed.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) {
		t.Fatal("legacy original inquiry changed configuration or renewed freshness", err)
	}
	wrong, _ := apikey.ParseLegacySecret(raw + "-wrong")
	if denied, err := verify(wrong); err == nil || denied.Result != nil {
		t.Fatal("wrong historical token authenticated")
	}
	var beforeCandidate []byte
	if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, legacySpec.ID, string(id)).Scan(&beforeCandidate); err != nil {
		t.Fatal(err)
	}
	knownWrong := knownRequest
	knownWrong.AttemptID, knownWrong.Candidate, knownWrong.LegacySecret = apikey.VerificationAttemptID(commandID(t)), id, wrong
	if denied, err := s.VerifyAndConsume(ctx, knownWrong); err == nil || denied.Result != nil {
		t.Fatal("wrong secret authenticated an existing explicit legacy candidate")
	}
	var afterKnownWrong []byte
	if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, legacySpec.ID, string(id)).Scan(&afterKnownWrong); err != nil || !bytes.Equal(beforeCandidate, afterKnownWrong) {
		t.Fatal("wrong secret mutated the existing explicit legacy candidate", err)
	}
	for _, presented := range []apikey.LegacySecret{legacySecret, wrong} {
		request := knownRequest
		request.AttemptID, request.Candidate, request.LegacySecret = apikey.VerificationAttemptID(commandID(t)), "01ARZ3NDEKTSV4RRFFQ69G5FAZ", presented
		if denied, err := s.VerifyAndConsume(ctx, request); err == nil || denied.Result != nil {
			t.Fatal("wrong explicit legacy candidate fell back to digest lookup")
		}
		var afterCandidate []byte
		if err := f.pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, legacySpec.ID, string(id)).Scan(&afterCandidate); err != nil || !bytes.Equal(beforeCandidate, afterCandidate) {
			t.Fatal("wrong explicit candidate mutated the actual legacy credential", err)
		}
	}

	rollback := r
	rollback.IdempotencyKey, rollback.Record.ID, rollback.Record.RootID = key("legacy-required-audit-rollback"), "01ARZ3NDEKTSV4RRFFQ69G5FAX", "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	rollback.Digest, _ = apikey.NewLegacyDigest(sha256.Sum256([]byte(raw + "-rollback")))
	var rollbackReceipt identity.CommandResult
	rejectMutationAudit(t, ctx, f.pool, "identity.api_key.import", func() {
		out, err := s.Import(ctx, rollback)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("import survived required audit failure")
		}
		rollbackReceipt = out
	})
	var rolledBack int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, baselineTenant, string(rollback.Record.ID)).Scan(&rolledBack); err != nil || rolledBack != 0 {
		t.Fatal("required import effect failure retained key authority")
	}
	afterRollback := rollback
	afterRollback.IdempotencyKey = key("legacy-after-required-audit-restored")
	if out, err := s.Import(ctx, afterRollback); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("same source snapshot was not admissible after audit recovery", err)
	}
	// The unavailable required audit also rejects its failure record, so the
	// original lease can legitimately remain live. InProgress/Unknown is not
	// rollback proof; reconcile the same original after expiring its exact lease.
	if out, err := s.Import(ctx, rollback); out.Binding != rollbackReceipt.Binding || out.Outcome != identity.CommitOutcomeNotCommitted && out.Outcome != identity.CommitOutcomeUnknown && out.Outcome != identity.CommitOutcomeInProgress {
		t.Fatalf("original rollback status mismatch: initial_outcome=%d later_outcome=%d initial_binding_present=%t later_binding_present=%t same_binding=%t error_present=%t", rollbackReceipt.Outcome, out.Outcome, rollbackReceipt.Binding.CommandID != "", out.Binding.CommandID != "", out.Binding == rollbackReceipt.Binding, err != nil)
	}
	rollbackCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(rollbackReceipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	// The call returned and has no live Work. Expire only its retained lease,
	// then let the genuine coordinator determine the terminal absence of effects.
	expired, err := f.pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND tenant_id=$2 AND purpose='identity.apikey.import'`, rollbackCommand, baselineTenant)
	if err != nil || expired.RowsAffected() != 1 {
		t.Fatal("original retained import lease was not uniquely expired", err)
	}
	if out, err := s.Import(ctx, rollback); out.Outcome != identity.CommitOutcomeNotCommitted || out.Binding != rollbackReceipt.Binding {
		t.Fatal("original rollback did not reconcile its exact terminal noncommit", err)
	}

	ambiguous := r
	ambiguous.IdempotencyKey, ambiguous.Record.ID, ambiguous.Record.RootID = key("legacy-lost-commit-acknowledgement"), "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	// Different records cannot reuse an already imported verifier: preserving
	// that unique lookup binding prevents accidental ambiguous bare-key matches.
	ambiguous.Digest, _ = apikey.NewLegacyDigest(sha256.Sum256([]byte(raw + "-second")))
	ambiguous.Record.Grant = []string{"invoice.read", "invoice.write"}
	fault := &legacyCommitFault{}
	faulted, err := database.Connect(ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
		// ConnString retains the initial cluster DSN, not the fixture's later
		// database selection. Keep the fault pool in the genuine fixture database.
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.DialFunc = fault.dial
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if faulted.Close(cleanup) != nil {
			t.Error("legacy fault pool cleanup failed")
		}
	})
	faultService, err := apikeypg.NewService(faulted, c)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := faultService.Import(ctx, ambiguous)
	if err == nil || !fault.hit.Load() || unknown.Outcome != identity.CommitOutcomeUnknown || unknown.Binding.RecordID != string(ambiguous.Record.ID) {
		t.Fatalf("lost import acknowledgement mismatch: fault_hit=%t outcome=%d binding_present=%t same_record=%t same_database=%t error_present=%t", fault.hit.Load(), unknown.Outcome, unknown.Binding.CommandID != "", unknown.Binding.RecordID == string(ambiguous.Record.ID), faulted.Raw().Config().ConnConfig.Database == f.pool.Raw().Config().ConnConfig.Database, err != nil)
	}
	recovered, err := s.Import(ctx, ambiguous)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != unknown.Binding {
		t.Fatal("import did not recover its exact original committed outcome", err)
	}
	revokeSecret, _ := apikey.ParseLegacySecret(raw + "-rollback")
	current, err := verify(revokeSecret)
	if err != nil || current.Result == nil {
		t.Fatal("unnamed direct-revoke target did not authenticate", err)
	}
	if revoked, err := s.Revoke(ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: key("unnamed-legacy-direct-revoke"), KeyID: afterRollback.Record.ID, ExpectedVersion: current.Result.Record.Version, Network: r.Network}); err != nil || revoked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("unnamed imported credential could not be directly revoked", err)
	}
	if denied, err := verify(revokeSecret); err == nil || denied.Result != nil {
		t.Fatal("unnamed directly revoked credential retained authority")
	}
	tombstone := r
	tombstone.IdempotencyKey, tombstone.Record.ID, tombstone.Record.RootID = key("legacy-preserved-expired-tombstone"), "01ARZ3NDEKTSV4RRFFQ69G5FAY", "01ARZ3NDEKTSV4RRFFQ69G5FAY"
	tombstone.Record.Status, tombstone.Record.ExpiresAt = apikey.KeyRevoked, time.Now().UTC().Add(-24*time.Hour).Truncate(time.Microsecond)
	tombstone.Record.Version, tombstone.Record.AuthorityVersion, tombstone.Record.RootVersion, tombstone.SourceVersion = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	tombstone.Digest, _ = apikey.NewLegacyDigest(sha256.Sum256([]byte(raw + "-tombstone")))
	if out, err := s.Import(ctx, tombstone); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("expired revoked source tombstone was not preserved", err)
	}
	var terminalWire []byte
	var sourceVersion string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT k.record,s.source_version::text FROM identity_api_keys.keys k JOIN identity_api_keys.legacy_imports s USING(tenant_id,configuration_id,key_id) WHERE k.tenant_id=$1 AND k.key_id=$2`, baselineTenant, string(tombstone.Record.ID)).Scan(&terminalWire, &sourceVersion); err != nil {
		t.Fatal(err)
	}
	var terminal struct {
		Version, AuthorityVersion, RootVersion uint64
		Status                                 apikey.KeyStatus
		CreatedAt, ExpiresAt                   time.Time
	}
	if json.Unmarshal(terminalWire, &terminal) != nil || terminal.Version != ^uint64(0) || terminal.AuthorityVersion != ^uint64(0) || terminal.RootVersion != ^uint64(0) || terminal.Status != apikey.KeyRevoked || !terminal.CreatedAt.Equal(tombstone.Record.CreatedAt) || !terminal.ExpiresAt.Equal(tombstone.Record.ExpiresAt) || sourceVersion != "18446744073709551615" {
		t.Fatal("terminal source snapshot lost full-width versions or original absolute times")
	}
	resurrection := tombstone
	resurrection.IdempotencyKey, resurrection.Record.Status, resurrection.Record.ExpiresAt = key("legacy-tombstone-resurrection"), apikey.KeyActive, expires
	resurrection.Record.Version, resurrection.Record.AuthorityVersion, resurrection.Record.RootVersion = 1, 1, 1
	if out, err := s.Import(ctx, resurrection); !errors.As(err, &sourceConflict) || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("conflicting source snapshot resurrected terminal tombstone", err)
	}
	tombstoneSecret, _ := apikey.ParseLegacySecret(raw + "-tombstone")
	if out, err := verify(tombstoneSecret); err == nil || out.Result != nil {
		t.Fatal("imported revoked tombstone authenticated")
	}

	rotationStart := time.Now().UTC()
	rotated, err := s.Rotate(ctx, apikey.Rotation{Authentication: f.caller, IdempotencyKey: key("legacy-modern-successor"), KeyID: id, ExpectedVersion: r.Record.Version, Network: r.Network})
	if err != nil {
		t.Fatal("legacy rotation failed", err)
	}
	successor, ok := rotated.Record()
	if !ok || successor.Name != "" || successor.ID == id || successor.PreviousID != id || successor.ConfigurationID != c.Configuration.Spec().ID || !successor.Owner.SameIdentity(owner) || strings.Join(successor.Grant, ",") != "invoice.read" || successor.ExpiresAt.After(rotationStart.Add(c.Configuration.Spec().MaximumLifetime+time.Second)) || successor.ExpiresAt.After(expires) {
		t.Fatal("rotation did not retain non-expanding modern authority")
	}
	newWire, err := rotated.Reveal()
	if err != nil || !strings.HasPrefix(newWire, "idk_") {
		t.Fatal("rotation did not issue modern reveal-once successor")
	}
	if old, err := verify(legacySecret); err == nil || old.Result != nil {
		t.Fatal("legacy predecessor retained authority after rotation")
	}
	if historical, err := s.VerifyAndConsume(ctx, knownRequest); historical.Outcome != identity.CommitOutcomeCommitted || historical.Fingerprint != verified.Fingerprint || historical.Original != verified.Original || historical.Result != nil && (!historical.Result.ValidUntil.Equal(verified.Result.ValidUntil) || !historical.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt)) {
		t.Fatal("legacy retry after rotation lost original history or renewed freshness", err)
	}
	if _, err := s.Import(ctx, r); err != nil {
		t.Fatal("historical original status recovery failed", err)
	}
	if old, err := verify(legacySecret); err == nil || old.Result != nil {
		t.Fatal("import retry resurrected rotated predecessor")
	}
	newSecret, _ := apikey.ParseSecret(newWire)
	if out, err := s.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Secret: newSecret, RequiredPermissions: []string{"invoice.read"}}); err != nil || out.Result == nil || out.Result.Record.ID != successor.ID {
		t.Fatal("modern successor did not authenticate", err)
	}
	secondSecret, _ := apikey.ParseLegacySecret(raw + "-second")
	if out, err := verify(secondSecret); err != nil || out.Result == nil || out.Result.Record.ID != ambiguous.Record.ID {
		t.Fatal("recovered legacy import did not authenticate", err)
	}
	f.deniedGrant.Store(true)
	advanceUserPolicy(t, ctx, f.pool, c.Profile.PolicyNamespace, f.user)
	removed := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: legacySpec.ID, ConfigurationRevision: legacySpec.Revision, LegacySecret: secondSecret, RequiredPermissions: []string{"invoice.write"}}
	if out, err := s.VerifyAndConsume(ctx, removed); err == nil || out.Result != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("removed current permission survived legacy verification")
	}
	if out, err := verify(secondSecret); err != nil || out.Result == nil || strings.Join(out.Result.Grant, ",") != "invoice.read" || out.Result.Record.Version != ambiguous.Record.Version+1 {
		t.Fatal("legacy current-authority narrowing was not atomic", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, baselineTenant, string(f.user)); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(secondSecret); err == nil || out.Result != nil {
		t.Fatal("suspended owner retained legacy authority")
	}
	if out, err := s.Import(ctx, r); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("suspended owner performed legacy import/status management")
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='suspended'`, baselineTenant, string(f.user)); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(secondSecret); err != nil || out.Result == nil || strings.Join(out.Result.Grant, ",") != "invoice.read" {
		t.Fatal("restored owner did not retain only the still-valid narrowed key", err)
	}
	if out, err := verify(legacySecret); err == nil || out.Result != nil {
		t.Fatal("owner restoration resurrected rotated legacy root")
	}
}
