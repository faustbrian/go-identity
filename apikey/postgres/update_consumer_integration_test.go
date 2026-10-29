//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	database "github.com/faustbrian/go-postgres"
)

func keyUpdater(t *testing.T, service *apikeypg.Service) apikey.Updater {
	t.Helper()
	updater, ok := any(service).(apikey.Updater)
	if !ok {
		t.Fatal("genuine native key service lacks keyed Update")
	}
	return updater
}

func updateKey(t *testing.T, input string) identity.IdempotencyKey {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyCredentialState(t *testing.T, f nativeConsumerFixture, id apikey.KeyID) string {
	t.Helper()
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pepper_version::text || ':' || encode(lookup_digest,'hex') FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, baselineTenant, string(id)).Scan(&state); err != nil {
		t.Fatal("observe unchanged credential custody", err)
	}
	return state
}

func assertUpdateEffects(t *testing.T, f nativeConsumerFixture, out apikey.UpdateResult, topic string) {
	t.Helper()
	assertAttemptAudit(t, f.ctx, f.pool, out.Receipt.Binding.CommandID, "identity.api_key.update", audit.OutcomeSucceeded)
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var events, charges int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$1 AND m.topic=$2),
 (SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1 AND operation='identity.apikey.update' AND allowed)`, command, topic).Scan(&events, &charges); err != nil || events != 1 || charges != 1 {
		t.Fatal("committed Update did not atomically retain its exact lifecycle effect and one protected counter charge", err)
	}
}

func TestGenuineKeyUpdateRenamesNarrowsAndRecovers(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	updater := keyUpdater(t, service)
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	issued, err := service.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "update-original-create"), Name: "automation", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.44"})
	if err != nil {
		t.Fatal("actual Update fixture issuance", err)
	}
	original, ok := issued.Record()
	if !ok {
		t.Fatal("issued metadata absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal("original invocation credential unavailable")
	}
	credential := keyCredentialState(t, f, original.ID)
	request := apikey.UpdateRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "update-name-only"), KeyID: original.ID, ExpectedVersion: original.Version, Name: "renamed automation", Permissions: slices.Clone(original.Grant), Network: "192.0.2.44"}
	renamed, err := updater.Update(f.ctx, request)
	if err != nil || renamed.Validate(f.config.Configuration) != nil || renamed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine keyed name-only Update", err)
	}
	want := original
	want.Name, want.Version = request.Name, original.Version+1
	if !reflect.DeepEqual(*renamed.Record, want) || renamed.ConfigurationAuthority.Version != 1 || keyCredentialState(t, f, original.ID) != credential {
		t.Fatal("name-only Update changed credential, owner, expiry, lineage or security epoch")
	}
	assertUpdateEffects(t, f, renamed, "api_key.updated.v1")
	binding := renamed.Receipt.Binding
	query := identity.RecoveryQuery{CommandID: binding.CommandID, TenantID: binding.TenantID, UserID: binding.UserID, ActorID: binding.ActorID, ActorKind: binding.ActorKind, OperationID: binding.OperationID, RecordID: binding.RecordID}
	if recovered, err := service.Recover(f.ctx, apikey.RecoveryRequest{Authentication: f.caller, Query: query}); err != nil || !reflect.DeepEqual(recovered, renamed.Receipt) {
		t.Fatal("public status-only Update recovery lost its original receipt", err)
	}
	restarted, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := keyUpdater(t, restarted).Update(f.ctx, request)
	if err != nil || !reflect.DeepEqual(replay, renamed) {
		t.Fatal("reconstructed exact Update retry lost original result", err)
	}
	conflicting := request
	conflicting.Name = "different intent"
	if out, err := keyUpdater(t, restarted).Update(f.ctx, conflicting); !errors.Is(err, identity.ConflictError{}) || out.Record != nil {
		t.Fatal("Update idempotency key admitted conflicting intent", err)
	}
	request.IdempotencyKey = updateKey(t, "update-permission-narrow")
	request.ExpectedVersion, request.Permissions = renamed.Record.Version, []string{"invoice.read"}
	narrowed, err := keyUpdater(t, restarted).Update(f.ctx, request)
	if err != nil || narrowed.Validate(f.config.Configuration) != nil || narrowed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine keyed permission narrowing", err)
	}
	want.Version++
	want.AuthorityVersion++
	want.RootVersion++
	want.Grant = []string{"invoice.read"}
	if !reflect.DeepEqual(*narrowed.Record, want) || narrowed.ConfigurationAuthority.Version != 2 || keyCredentialState(t, f, original.ID) != credential {
		t.Fatal("narrowing changed identity/custody or failed to advance existing security dimensions once")
	}
	assertUpdateEffects(t, f, narrowed, "api_key.permissions_changed.v1")
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"invoice.read", "invoice.write"} {
		verified, err := restarted.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: f.config.Configuration.Spec().ID, ConfigurationRevision: f.config.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{permission}})
		if permission == "invoice.read" {
			if err != nil || verified.Result == nil || !slices.Equal(verified.Result.Grant, want.Grant) {
				t.Fatal("unchanged credential lost narrowed access", err)
			}
		} else if !errors.Is(err, apikey.ErrDenied) || verified.Result != nil {
			t.Fatal("unchanged credential retained removed permission", err)
		}
	}
	// A later mutation must not turn the original name-only replay into a read
	// of today's metadata or configuration epoch.
	oldRequest := request
	oldRequest.IdempotencyKey, oldRequest.ExpectedVersion, oldRequest.Permissions = updateKey(t, "update-name-only"), original.Version, slices.Clone(original.Grant)
	replayedName, err := keyUpdater(t, restarted).Update(f.ctx, oldRequest)
	if err != nil || !reflect.DeepEqual(replayedName, renamed) {
		t.Fatal("later narrowing rewrote original name-only recovery snapshot", err)
	}
	request.IdempotencyKey = updateKey(t, "update-deny-all")
	request.ExpectedVersion, request.Permissions = narrowed.Record.Version, []string{}
	empty, err := keyUpdater(t, restarted).Update(f.ctx, request)
	if err != nil || empty.Record == nil || len(empty.Record.Grant) != 0 || empty.Record.Status != apikey.KeyActive || empty.ConfigurationAuthority.Version != 3 {
		t.Fatal("explicit deny-all Update was confused with inheritance or revocation", err)
	}
	if out, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: updateKey(t, "update-terminal-revoke"), KeyID: original.ID, ExpectedVersion: empty.Record.Version, Network: request.Network}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual terminal Update specimen", err)
	}
	before := metadataState(t, f)
	request.IdempotencyKey, request.ExpectedVersion = updateKey(t, "update-revoked-denial"), empty.Record.Version+1
	if out, err := updater.Update(f.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Record != nil || out.ConfigurationAuthority != nil || metadataState(t, f) != before {
		t.Fatal("Update revived or changed a terminal credential", err)
	}
}

func TestGenuineKeyUpdateDenialsRollbackAndLostAcknowledgement(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	record := metadataIssue(t, f, service, f.caller, "update-security")
	request := apikey.UpdateRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "update-security-original"), KeyID: record.ID, ExpectedVersion: record.Version, Name: "updated security", Permissions: slices.Clone(record.Grant), Network: "192.0.2.44"}
	other, _ := f.register()
	before := metadataState(t, f)
	for i, change := range []func(*apikey.UpdateRequest){
		func(r *apikey.UpdateRequest) { r.Authentication = other },
		func(r *apikey.UpdateRequest) { r.Authentication.TenantID = "other-tenant" },
		func(r *apikey.UpdateRequest) { r.OrganizationID = "unselected-organization" },
		func(r *apikey.UpdateRequest) { r.KeyID = "absent-record" },
		func(r *apikey.UpdateRequest) { r.ExpectedVersion++ },
		func(r *apikey.UpdateRequest) { r.Permissions = []string{f.maximumGrants[0], "invoice.read"} },
	} {
		bad := request
		bad.IdempotencyKey = updateKey(t, fmt.Sprintf("update-denied-%d", i))
		change(&bad)
		if out, err := keyUpdater(t, service).Update(f.ctx, bad); err == nil || out.Record != nil || out.ConfigurationAuthority != nil {
			t.Fatal("foreign, stale or expanding Update acquired a committed snapshot")
		}
		if metadataState(t, f) != before {
			t.Fatal("denied Update mutated key/configuration/effect state")
		}
	}
	f.deniedManagement.Store(true)
	if out, err := keyUpdater(t, service).Update(f.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Record != nil {
		t.Fatal("current management denial admitted Update", err)
	}
	f.deniedManagement.Store(false)
	func() {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=false WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, f.config.Configuration.Spec().ID); err != nil {
			t.Fatal("trusted fixture configuration withdrawal", err)
		}
		defer func() {
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_api_keys.configurations SET enabled=true WHERE tenant_id=$1 AND configuration_id=$2`, baselineTenant, f.config.Configuration.Spec().ID); err != nil {
				t.Error("trusted fixture configuration restoration", err)
			}
		}()
		disabled := metadataState(t, f)
		if out, err := keyUpdater(t, service).Update(f.ctx, request); !errors.Is(err, apikey.ErrDenied) || out.Record != nil || out.ConfigurationAuthority != nil || metadataState(t, f) != disabled {
			t.Fatal("Update used a disabled configuration or changed its authority", err)
		}
	}()
	var failed apikey.UpdateResult
	rejectMutationAudit(t, f.ctx, f.pool, "identity.api_key.update", func() {
		out, err := keyUpdater(t, service).Update(f.ctx, request)
		if err == nil || out.Record != nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("required Update audit failure disclosed committed metadata")
		}
		failed = out
	})
	if metadataState(t, f) != before {
		t.Fatal("required Update audit failure persisted key/configuration/effects")
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(failed.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal("failed audit did not retain original recovery identity", err)
	}
	var charges int
	// The retained kernel's protected-preparation contract commits one admitted
	// attempt charge before generation, including when final domain apply fails
	// (postgres@601e478a297c:preparation_counter_integration_test.go, deny-apply).
	// Final audit failure rolls back key/effects, not that earlier abuse charge.
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1`, command).Scan(&charges); err != nil || charges != 1 {
		t.Fatal("failed protected preparation lost or duplicated its original attempt charge", err)
	}
	failedRequest := request
	// SQL observation proves no domain effect here, not the public command's
	// terminal disposition. The audit outage can also prevent outcome recording;
	// keep that original uncertainty rather than asserting a known rollback.
	request.IdempotencyKey = updateKey(t, "update-unknown-commit")
	fault := &legacyCommitFault{marker: []byte("UPDATE identity_api_keys.keys SET record=")}
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
			t.Error("Update fault pool cleanup", err)
		}
	})
	faultService, err := apikeypg.NewService(faultPool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := keyUpdater(t, faultService).Update(f.ctx, request)
	if err == nil || !fault.hit.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Record != nil || unknown.ConfigurationAuthority != nil || unknown.Validate(f.config.Configuration) != nil {
		t.Fatal("lost actual Update COMMIT acknowledgement was not preserved as unknown")
	}
	recovered, err := keyUpdater(t, service).Update(f.ctx, request)
	if err != nil || recovered.Validate(f.config.Configuration) != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Receipt.Binding != unknown.Receipt.Binding || recovered.Record.Version != record.Version+1 || recovered.ConfigurationAuthority.Version != 1 {
		t.Fatal("Update failed to recover its exact original committed transaction", err)
	}
	if replay, _ := keyUpdater(t, service).Update(f.ctx, failedRequest); replay.Validate(f.config.Configuration) != nil || replay.Receipt.Outcome == identity.CommitOutcomeCommitted || replay.Receipt.Binding != failed.Receipt.Binding || replay.Record != nil || replay.ConfigurationAuthority != nil {
		t.Fatal("failed-audit original recovery fabricated commitment or executed another intent")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1`, command).Scan(&charges); err != nil || charges != 1 {
		t.Fatal("original failed Update replay charged another attempt", err)
	}
}
func TestGenuineKeyUpdateContendsWithRotationAndRevocation(t *testing.T) {
	f := setupNativeConsumer(t)
	config := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}})
	service, err := apikeypg.NewService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	record := metadataIssue(t, f, service, f.caller, "update-contention")
	updater := keyUpdater(t, service)
	update := apikey.UpdateRequest{Authentication: f.caller, IdempotencyKey: updateKey(t, "race-update"), KeyID: record.ID, ExpectedVersion: record.Version, Name: "race winner", Permissions: []string{}, Network: "192.0.2.44"}
	rotate := apikey.Rotation{Authentication: f.caller, IdempotencyKey: updateKey(t, "race-rotate"), KeyID: record.ID, ExpectedVersion: record.Version, Network: "192.0.2.44"}
	revoke := apikey.Revocation(rotate)
	revoke.IdempotencyKey = updateKey(t, "race-revoke")
	start := make(chan struct{})
	winners := make(chan bool, 3)
	var workers sync.WaitGroup
	for _, run := range []func() bool{
		func() bool {
			out, err := updater.Update(f.ctx, update)
			return err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
		},
		func() bool {
			out, err := service.Rotate(f.ctx, rotate)
			receipt, receiptErr := out.Receipt()
			return err == nil && receiptErr == nil && receipt.Outcome == identity.CommitOutcomeCommitted
		},
		func() bool {
			out, err := service.Revoke(f.ctx, revoke)
			return err == nil && out.Outcome == identity.CommitOutcomeCommitted
		},
	} {
		workers.Add(1)
		go func() { defer workers.Done(); <-start; winners <- run() }()
	}
	close(start)
	workers.Wait()
	close(winners)
	count := 0
	for winner := range winners {
		if winner {
			count++
		}
	}
	if count != 1 {
		t.Fatal("Update/rotate/revoke did not select exactly one original-version winner")
	}
	got, err := metadataReader(t, service).Get(f.ctx, apikey.GetRequest{Authentication: f.caller, KeyID: record.ID})
	if err != nil || got.Record.Version != record.Version+1 || got.Record.AuthorityVersion != record.AuthorityVersion+1 || got.Record.RootVersion != got.Record.AuthorityVersion {
		t.Fatal("contending mutations double-advanced or lost the original credential version", err)
	}
}
