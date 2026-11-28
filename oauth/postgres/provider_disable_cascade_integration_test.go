//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func providerDisableCascadeFixture(t *testing.T) (context.Context, *database.Pool, *ProviderAuthority, *ProviderAuthorityOperator, ProviderAuthorityKey) {
	t.Helper()
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	history, err := (ProviderDisableCascadeMigrationSource{Schema: "onetap_oauth", Version: 43}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load one additive provider-disable admission migration", len(history), err)
	}
	if _, err := pool.Raw().Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install admission after existing provider authority history", err)
	}
	return ctx, pool, authority, operator, key
}

func providerDisableAssertRows(t *testing.T, ctx context.Context, pool *database.Pool, disable ProviderAuthorityChange, want int) {
	t.Helper()
	var total, matching int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE tenant_id=$1 AND source_command_id=$2)
 FROM onetap_oauth.provider_disable_cascades`, string(disable.Key.TenantID), string(disable.CommandID)).Scan(&total, &matching); err != nil || total != want || matching != want {
		t.Fatal("admission did not conserve exactly one tenant/source row or left a poison row", total, matching, want, err)
	}
}

func providerDisableAssertReceipt(t *testing.T, got ProviderDisableAdmission, disable ProviderAuthorityChange, window time.Duration) {
	t.Helper()
	if _, err := identity.ParseCascadeID(string(got.CascadeID)); err != nil {
		t.Fatal("admission omitted a valid opaque cascade identity", err)
	}
	if got.Generation != 1 || got.Disable != disable || got.EventID != disable.CommandID || got.EventVersion != 1 || got.EventTopic != "social_provider.disabled.v1" || got.ManifestVersion != "identity-lifecycle-consumers-v1" || got.Status != identity.RevocationPending {
		t.Fatal("admission lost exact disable, event correlation or pending disposition", got)
	}
	if got.AdmittedAt.IsZero() || got.Deadline.Sub(got.AdmittedAt) != window {
		t.Fatal("admission deadline was not fixed from its persisted admission time", got.AdmittedAt, got.Deadline, window)
	}
	wantConsumers := []ProviderDisableConsumer{
		{ID: "identity/oauth", ContractVersion: 1},
		{ID: "identity/oauth/onetap", ContractVersion: 1},
		{ID: "identity/oauth/proxy", ContractVersion: 1},
		{ID: "identity", ContractVersion: 1},
		{ID: "identity/session", ContractVersion: 1},
		{ID: "identity/session/valkey", ContractVersion: 1},
		{ID: "identity/delivery", ContractVersion: 1},
		{ID: "audit", ContractVersion: 1},
	}
	if !reflect.DeepEqual(got.Consumers, wantConsumers) {
		t.Fatal("admission did not freeze the complete provider-owned consumer manifest", got.Consumers, wantConsumers)
	}
}

func TestProviderDisableAdmissionPersistsAtomicEffectsAndReplaysAfterReenable(t *testing.T) {
	ctx, pool, authority, operator, key := providerDisableCascadeFixture(t)
	configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure provider before selected disable", err)
	}
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
	first, err := operator.ApplyDisableCascade(ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit selected provider disable", err)
	}
	providerDisableAssertReceipt(t, first, disable, time.Hour)
	providerDisableAssertRows(t, ctx, pool, disable, 1)
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
	configured := providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}
	disabled := providerAuthorityEvent{command: disable.CommandID, key: key, enabled: false}
	providerAuthorityAssertEvents(t, ctx, pool, configured, disabled)
	var payload []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT payload FROM public.outbox_messages WHERE id=$1`, string(disable.CommandID)).Scan(&payload); err != nil {
		t.Fatal("read original provider-disabled event", err)
	}
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal("decode existing provider-disabled payload", err)
	}
	wantEvent := map[string]any{"tenant_id": string(key.TenantID), "provider_id": key.ProviderID, "previous_version": float64(7), "version": float64(8), "profile_version": float64(3), "enabled": false}
	if !reflect.DeepEqual(event, wantEvent) {
		t.Fatal("admission replaced or changed the existing disabled event contract", event, wantEvent)
	}

	reenable := ProviderAuthorityChange{Key: key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 12, ProfileVersion: 4, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(ctx, reenable); err != nil {
		t.Fatal("reenable provider after admitted disable", err)
	}
	restarted, err := NewProviderAuthorityOperator(authority, oneTapStartActor)
	if err != nil {
		t.Fatal("restart selected provider operator", err)
	}
	replay, err := restarted.ApplyDisableCascade(ctx, disable, time.Hour)
	if err != nil || !reflect.DeepEqual(replay, first) {
		t.Fatal("superseded exact replay did not recover the same persisted random identity and deadline", replay, first, err)
	}
	for name, altered := range map[string]ProviderAuthorityChange{
		"changed predecessor": {Key: key, ExpectedVersion: 6, Next: disable.Next, CommandID: disable.CommandID},
		"changed epoch":       {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 9, ProfileVersion: 3}, CommandID: disable.CommandID},
		"changed profile":     {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 4}, CommandID: disable.CommandID},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := restarted.ApplyDisableCascade(ctx, altered, time.Hour)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || !reflect.DeepEqual(got, ProviderDisableAdmission{}) {
				t.Fatal("altered committed command was not an exact conflict with no admission", got, err)
			}
		})
	}
	got, err := restarted.ApplyDisableCascade(ctx, disable, time.Hour+time.Second)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || !reflect.DeepEqual(got, ProviderDisableAdmission{}) {
		t.Fatal("changed admission deadline reused a committed command", got, err)
	}
	providerAuthorityAssertState(t, ctx, authority, key, reenable.Next)
	providerDisableAssertRows(t, ctx, pool, disable, 1)
	providerAuthorityAssertEvents(t, ctx, pool, configured, disabled, providerAuthorityEvent{command: reenable.CommandID, key: key, enabled: true})
}

func TestProviderDisableAdmissionDefaultWindowIsCanonicalAndLegacyDisableCannotBeUpgraded(t *testing.T) {
	t.Run("default window", func(t *testing.T) {
		ctx, pool, authority, operator, key := providerDisableCascadeFixture(t)
		configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
		if _, err := operator.Apply(ctx, configure); err != nil {
			t.Fatal("configure provider", err)
		}
		disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
		first, err := operator.ApplyDisableCascade(ctx, disable, 0)
		if err != nil {
			t.Fatal("admit provider disable with default deadline", err)
		}
		providerDisableAssertReceipt(t, first, disable, 7*24*time.Hour)
		replay, err := operator.ApplyDisableCascade(ctx, disable, 7*24*time.Hour)
		if err != nil || !reflect.DeepEqual(replay, first) {
			t.Fatal("explicit default duration conflicted with its canonical zero form", replay, first, err)
		}
		providerDisableAssertRows(t, ctx, pool, disable, 1)
		providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
		providerAuthorityAssertEvents(t, ctx, pool, providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}, providerAuthorityEvent{command: disable.CommandID, key: key})
	})
	t.Run("legacy disable", func(t *testing.T) {
		ctx, pool, authority, operator, key := providerDisableCascadeFixture(t)
		configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
		disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
		for _, change := range []ProviderAuthorityChange{configure, disable} {
			if _, err := operator.Apply(ctx, change); err != nil {
				t.Fatal("commit legacy provider transition", err)
			}
		}
		got, err := operator.ApplyDisableCascade(ctx, disable, time.Hour)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || !reflect.DeepEqual(got, ProviderDisableAdmission{}) {
			t.Fatal("legacy disable retroactively acquired an admission", got, err)
		}
		providerDisableAssertRows(t, ctx, pool, disable, 0)
		providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
		providerAuthorityAssertEvents(t, ctx, pool, providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}, providerAuthorityEvent{command: disable.CommandID, key: key})
	})
}

func TestProviderDisableAdmissionOutboxFailureRollsBackWithoutPoisoningCommand(t *testing.T) {
	ctx, pool, authority, operator, key := providerDisableCascadeFixture(t)
	configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure provider before outbox fault", err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE onetap_oauth.provider_disable_outbox_failure;
 CREATE FUNCTION onetap_oauth.reject_provider_disable_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 PERFORM nextval('onetap_oauth.provider_disable_outbox_failure');
 RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='fixture provider disable outbox failure'; END $$;
 CREATE TRIGGER provider_disable_outbox_failure BEFORE INSERT ON public.outbox_messages
 FOR EACH ROW WHEN (NEW.topic='social_provider.disabled.v1')
 EXECUTE FUNCTION onetap_oauth.reject_provider_disable_outbox()`); err != nil {
		t.Fatal("install fault on the existing fixture-owned outbox", err)
	}
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
	got, err := operator.ApplyDisableCascade(ctx, disable, time.Hour)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, ProviderDisableAdmission{}) {
		t.Fatal("failed outbox write returned a usable admission or wrong disposition", got, err)
	}
	var fired bool
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called FROM onetap_oauth.provider_disable_outbox_failure`).Scan(&fired); err != nil || !fired {
		t.Fatal("failure did not reach the existing disabled event insertion", fired, err)
	}
	providerDisableAssertRows(t, ctx, pool, disable, 0)
	providerAuthorityAssertState(t, ctx, authority, key, configure.Next)
	configured := providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}
	providerAuthorityAssertEvents(t, ctx, pool, configured)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER provider_disable_outbox_failure ON public.outbox_messages`); err != nil {
		t.Fatal("remove fixture outbox fault", err)
	}
	accepted, err := operator.ApplyDisableCascade(ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("rolled-back admission consumed its command or predecessor", err)
	}
	providerDisableAssertReceipt(t, accepted, disable, time.Hour)
	providerDisableAssertRows(t, ctx, pool, disable, 1)
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
	providerAuthorityAssertEvents(t, ctx, pool, configured, providerAuthorityEvent{command: disable.CommandID, key: key})
}
