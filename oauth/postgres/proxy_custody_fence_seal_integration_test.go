//go:build integration

package postgres

import (
	"context"
	"reflect"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type proxyCustodyFenceSealFixture struct {
	ctx       context.Context
	primary   *database.Pool
	authority *ProviderAuthority
	provider  *ProviderAuthorityOperator
	key       ProviderAuthorityKey
	local     *database.Pool
	db        *pgx.Conn
	lane      proxyCustodyFenceFixture
	admitted  ProviderDisableAdmission
}

func newProxyCustodyFenceSealFixture(t *testing.T, lane proxyCustodyFenceFixture) proxyCustodyFenceSealFixture {
	t.Helper()
	ctx, primary, authority, provider, key := providerDisableCascadeFixture(t)
	_, db := rpMigrationDatabase(t)
	local, err := database.Connect(ctx, database.Config{DSN: db.Config().ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = db.Config().Database
		return nil
	}})
	if err != nil {
		t.Fatal("open independently owned local custody pool", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := local.Close(cleanup); err != nil {
			t.Error("close local custody pool", err)
		}
	})
	var primaryDatabase, localDatabase string
	if err := primary.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&primaryDatabase); err != nil {
		t.Fatal("identify provider-primary database", err)
	}
	if err := local.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&localDatabase); err != nil || localDatabase != db.Config().Database || localDatabase == primaryDatabase {
		t.Fatal("local custody did not use its separate fixture-owned database", err)
	}
	proxyCustodyFenceApply(t, ctx, db, MigrationSource{Schema: "oauth_rp", Version: 100})
	proxyCustodyFenceApply(t, ctx, db, lane.source)
	proxyCustodyFenceApply(t, ctx, db, ProxyCustodyWriteFenceMigrationSource{Schema: "oauth_rp", Version: 102, Kind: lane.kind})
	configure := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	if _, err := provider.Apply(ctx, configure); err != nil {
		t.Fatal("configure provider before admitted disable", err)
	}
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
	admitted, err := provider.ApplyDisableCascade(ctx, disable, time.Hour)
	if err != nil {
		t.Fatal("admit authoritative provider disable", err)
	}
	return proxyCustodyFenceSealFixture{ctx: ctx, primary: primary, authority: authority, provider: provider,
		key: key, local: local, db: db, lane: lane, admitted: admitted}
}

func (f proxyCustodyFenceSealFixture) activate(t *testing.T) {
	t.Helper()
	proxyCustodyFenceApply(t, f.ctx, f.db, ProxyCustodyWriteFenceActivationSource{Schema: "oauth_rp", Version: 103, Kind: f.lane.kind})
}

func (f proxyCustodyFenceSealFixture) request(admission ProviderDisableAdmission) ProxyCustodyFenceSealRequest {
	return ProxyCustodyFenceSealRequest{TenantID: admission.Disable.Key.TenantID, SourceCommandID: admission.Disable.CommandID,
		CascadeID: admission.CascadeID, Generation: admission.Generation}
}

func (f proxyCustodyFenceSealFixture) seal(t *testing.T, actor identity.ActorID, request ProxyCustodyFenceSealRequest) (ProxyCustodyFenceSeal, error) {
	t.Helper()
	operator, err := NewProxyCustodyFenceOperator(f.local, f.authority, ProxyCustodyFenceOperatorConfig{
		Schema: "oauth_rp", Kind: f.lane.kind, TenantID: f.key.TenantID, ActorID: actor, MaximumDuration: time.Second,
	})
	if err != nil {
		return ProxyCustodyFenceSeal{}, err
	}
	return operator.SealAdmittedProviderDisable(f.ctx, request)
}

func (f proxyCustodyFenceSealFixture) assertFloor(t *testing.T, want uint64) {
	t.Helper()
	var count int
	if err := f.local.Raw().QueryRow(f.ctx, `SELECT count(*) FROM oauth_rp.`+f.lane.fenceTable).Scan(&count); err != nil {
		t.Fatal("read role-local fence cardinality", err)
	}
	if want == 0 {
		if count != 0 {
			t.Fatal("rejected seal persisted a local fence", count)
		}
		return
	}
	var floor string
	if err := f.local.Raw().QueryRow(f.ctx, `SELECT denied_through::text FROM oauth_rp.`+f.lane.fenceTable+` WHERE tenant_id=$1 AND provider_id=$2`, string(f.key.TenantID), f.key.ProviderID).Scan(&floor); err != nil || count != 1 || floor != strconv.FormatUint(want, 10) {
		t.Fatal("seal lost its exact tenant/provider scope or monotone floor", floor, count, want, err)
	}
}

func (f proxyCustodyFenceSealFixture) snapshotSource(t *testing.T, admission ProviderDisableAdmission) string {
	t.Helper()
	var snapshot string
	var pending bool
	if err := f.primary.Raw().QueryRow(f.ctx, `SELECT to_jsonb(c)::text,status=$3 FROM onetap_oauth.provider_disable_cascades c
 WHERE tenant_id=$1 AND source_command_id=$2`, string(f.key.TenantID), string(admission.Disable.CommandID), int16(identity.RevocationPending)).Scan(&snapshot, &pending); err != nil || !pending {
		t.Fatal("seal source is not the exact pending authoritative admission", err)
	}
	return snapshot
}

func proxyCustodyFenceAssertSeal(t *testing.T, got ProxyCustodyFenceSeal, request ProxyCustodyFenceSealRequest, kind kernel.OAuthProxyRetirementKind, provider string, floor uint64) {
	t.Helper()
	if got.TenantID != request.TenantID || got.SourceCommandID != request.SourceCommandID || got.CascadeID != request.CascadeID ||
		got.Generation != request.Generation || got.Kind != kind || got.ProviderID != provider || got.DeniedThrough != floor {
		t.Fatal("seal substituted current authority or lost exact source correlation", got, request, floor)
	}
}

func TestProxyCustodyFenceSealUsesAdmittedSourceAfterReenableAndNeverLowersFloor(t *testing.T) {
	for _, lane := range proxyCustodyFenceFixtures() {
		t.Run(lane.name, func(t *testing.T) {
			f := newProxyCustodyFenceSealFixture(t, lane)
			f.activate(t)
			sourceBefore := f.snapshotSource(t, f.admitted)
			reenable := ProviderAuthorityChange{Key: f.key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 12, ProfileVersion: 4, Enabled: true}, CommandID: providerAuthorityCommand(t)}
			if _, err := f.provider.Apply(f.ctx, reenable); err != nil {
				t.Fatal("reenable provider before historical seal", err)
			}
			request := f.request(f.admitted)
			first, err := f.seal(t, oneTapStartActor, request)
			if err != nil {
				t.Fatal("seal admitted disable after provider re-enable", err)
			}
			proxyCustodyFenceAssertSeal(t, first, request, lane.kind, f.key.ProviderID, 7)
			f.assertFloor(t, 7)
			providerAuthorityAssertState(t, f.ctx, f.authority, f.key, reenable.Next)

			laterDisable := ProviderAuthorityChange{Key: f.key, ExpectedVersion: 12, Next: ProviderAuthorityState{Version: 14, ProfileVersion: 4}, CommandID: providerAuthorityCommand(t)}
			later, err := f.provider.ApplyDisableCascade(f.ctx, laterDisable, time.Hour)
			if err != nil {
				t.Fatal("admit later provider disable", err)
			}
			laterSourceBefore := f.snapshotSource(t, later)
			laterRequest := f.request(later)
			latest, err := f.seal(t, oneTapStartActor, laterRequest)
			if err != nil {
				t.Fatal("advance local floor using later admitted disable", err)
			}
			proxyCustodyFenceAssertSeal(t, latest, laterRequest, lane.kind, f.key.ProviderID, 12)
			for attempt := range 2 {
				older, err := f.seal(t, oneTapStartActor, request)
				if err != nil {
					t.Fatal("older exact admitted source ceased to be sealable", attempt, err)
				}
				proxyCustodyFenceAssertSeal(t, older, request, lane.kind, f.key.ProviderID, 12)
				f.assertFloor(t, 12)
			}
			repeated, err := f.seal(t, oneTapStartActor, laterRequest)
			if err != nil || repeated != latest {
				t.Fatal("exact seal retry changed its correlated result", repeated, latest, err)
			}
			if f.snapshotSource(t, f.admitted) != sourceBefore || f.snapshotSource(t, later) != laterSourceBefore {
				t.Fatal("local seal changed or acknowledged provider-primary admission")
			}
			providerAuthorityAssertState(t, f.ctx, f.authority, f.key, laterDisable.Next)
			proxyCustodyFenceInsertCommit(t, f.ctx, f.db, lane, 20, string(f.key.TenantID), f.key.ProviderID, 12, "23514")
			proxyCustodyFenceInsertCommit(t, f.ctx, f.db, lane, 30, string(f.key.TenantID), f.key.ProviderID, 13, "")
			proxyCustodyFenceInsertCommit(t, f.ctx, f.db, lane, 40, string(f.key.TenantID), "unrelated-provider", 12, "")
			proxyCustodyFenceInsertCommit(t, f.ctx, f.db, lane, 50, "unrelated-tenant", f.key.ProviderID, 12, "")
		})
	}
}

func TestProxyCustodyFenceSealRejectsMissingForgedLegacyAndWrongActorWithoutEffects(t *testing.T) {
	for _, lane := range proxyCustodyFenceFixtures() {
		t.Run(lane.name, func(t *testing.T) {
			f := newProxyCustodyFenceSealFixture(t, lane)
			f.activate(t)
			reenable := ProviderAuthorityChange{Key: f.key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 12, ProfileVersion: 4, Enabled: true}, CommandID: providerAuthorityCommand(t)}
			legacy := ProviderAuthorityChange{Key: f.key, ExpectedVersion: 12, Next: ProviderAuthorityState{Version: 13, ProfileVersion: 4}, CommandID: providerAuthorityCommand(t)}
			for _, change := range []ProviderAuthorityChange{reenable, legacy} {
				if _, err := f.provider.Apply(f.ctx, change); err != nil {
					t.Fatal("commit real provider history with non-admitted legacy disable", err)
				}
			}
			sourceBefore := f.snapshotSource(t, f.admitted)
			for _, test := range []struct {
				name   string
				actor  identity.ActorID
				change func(*ProxyCustodyFenceSealRequest)
			}{
				{name: "missing source", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = providerAuthorityCommand(t) }},
				{name: "forged cascade", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) {
					id, err := identity.NewCascadeID()
					if err != nil {
						t.Fatal(err)
					}
					r.CascadeID = id
				}},
				{name: "forged generation", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) { r.Generation = 2 }},
				{name: "foreign tenant", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) { r.TenantID = "AAAAAAAAAAAAAAAAAAAAAg" }},
				{name: "enabled command", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = reenable.CommandID }},
				{name: "legacy disable", actor: oneTapStartActor, change: func(r *ProxyCustodyFenceSealRequest) { r.SourceCommandID = legacy.CommandID }},
				{name: "wrong actor", actor: "AAAAAAAAAAAAAAAAAAAAAg", change: func(*ProxyCustodyFenceSealRequest) {}},
			} {
				t.Run(test.name, func(t *testing.T) {
					request := f.request(f.admitted)
					test.change(&request)
					got, err := f.seal(t, test.actor, request)
					if err == nil || !reflect.DeepEqual(got, ProxyCustodyFenceSeal{}) {
						t.Fatal("unauthorized selector returned a usable seal", got, err)
					}
					f.assertFloor(t, 0)
					if f.snapshotSource(t, f.admitted) != sourceBefore {
						t.Fatal("rejected seal changed its provider-primary source")
					}
					providerAuthorityAssertState(t, f.ctx, f.authority, f.key, legacy.Next)
				})
			}
		})
	}
}

func TestProxyCustodyFenceSealRequiresActivatedEnabledLocalTrigger(t *testing.T) {
	for _, lane := range proxyCustodyFenceFixtures() {
		t.Run(lane.name, func(t *testing.T) {
			f := newProxyCustodyFenceSealFixture(t, lane)
			request := f.request(f.admitted)
			sourceBefore := f.snapshotSource(t, f.admitted)
			got, err := f.seal(t, oneTapStartActor, request)
			if err == nil || !reflect.DeepEqual(got, ProxyCustodyFenceSeal{}) {
				t.Fatal("expansion without activation returned a seal", got, err)
			}
			f.assertFloor(t, 0)
			f.activate(t)
			if _, err := f.local.Raw().Exec(f.ctx, `ALTER TABLE oauth_rp.`+lane.table+` DISABLE TRIGGER proxy_custody_write_fence`); err != nil {
				t.Fatal("disable only fixture-owned activated custody trigger", err)
			}
			got, err = f.seal(t, oneTapStartActor, request)
			if err == nil || !reflect.DeepEqual(got, ProxyCustodyFenceSeal{}) {
				t.Fatal("disabled local enforcement returned a usable seal", got, err)
			}
			f.assertFloor(t, 0)
			if f.snapshotSource(t, f.admitted) != sourceBefore {
				t.Fatal("failed local activation check changed the authoritative source")
			}
			if _, err := f.local.Raw().Exec(f.ctx, `ALTER TABLE oauth_rp.`+lane.table+` ENABLE TRIGGER proxy_custody_write_fence`); err != nil {
				t.Fatal("restore fixture custody trigger", err)
			}
			accepted, err := f.seal(t, oneTapStartActor, request)
			if err != nil {
				t.Fatal("failed enforcement checks poisoned a valid seal retry", err)
			}
			proxyCustodyFenceAssertSeal(t, accepted, request, lane.kind, f.key.ProviderID, 7)
			f.assertFloor(t, 7)
		})
	}
}
