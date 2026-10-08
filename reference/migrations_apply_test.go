package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
)

func TestMigrationApplyPolicyBoundsAndRedaction(t *testing.T) {
	p := MigrationApplyPolicy{TenantID: "tenant", ActorID: "operator", LookupKey: [32]byte{0x71}, CleanupTimeout: time.Second}
	copy, err := copyMigrationApplyPolicy(&p)
	if err != nil || copy.LockTimeout != 30*time.Second {
		t.Fatal("explicit policy default", err)
	}
	p.LookupKey[0]++
	if copy.LookupKey == p.LookupKey {
		t.Fatal("policy not copied")
	}
	for _, mutate := range []func(*MigrationApplyPolicy){
		func(p *MigrationApplyPolicy) { p.TenantID = "" }, func(p *MigrationApplyPolicy) { p.ActorID = "bad scope" },
		func(p *MigrationApplyPolicy) { p.LookupKey = [32]byte{} }, func(p *MigrationApplyPolicy) { p.LockTimeout = time.Second - 1 },
		func(p *MigrationApplyPolicy) { p.LockTimeout = 5*time.Minute + 1 }, func(p *MigrationApplyPolicy) { p.CleanupTimeout = 0 },
		func(p *MigrationApplyPolicy) { p.CleanupTimeout = time.Minute + 1 },
	} {
		changed := *copy
		mutate(&changed)
		if _, err := copyMigrationApplyPolicy(&changed); err == nil {
			t.Fatal("invalid policy admitted")
		}
	}
	for _, duration := range []time.Duration{time.Second, 5 * time.Minute} {
		changed := *copy
		changed.LockTimeout = duration
		if _, err := copyMigrationApplyPolicy(&changed); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := copyMigrationApplyPolicy(nil); err != nil || got != nil {
		t.Fatal("nil enables apply")
	}
	for _, projection := range []string{fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprintf("%x", p), p.GoString(), p.LogValue().String()} {
		if strings.Contains(projection, "operator") || strings.Contains(projection, "LookupKey") || projection != "[migration apply policy]" {
			t.Fatal("policy diagnostic leak")
		}
	}
	wire, err := json.Marshal(p)
	if err != nil || !bytes.Equal(wire, []byte(`"[migration apply policy]"`)) {
		t.Fatal("policy JSON leak", err)
	}
}

func TestMigrationApplyRequestBoundsCopiesAndBinding(t *testing.T) {
	snapshot := planFixture(t, "a", "a", 2)
	p, err := buildMigrationPlan([]migrationSnapshot{snapshot}, []ModuleID{"a"})
	if err != nil {
		t.Fatal(err)
	}
	input := ReferenceMigrationApplyRequest{CommandID: "migration_command_0001", Plan: p}
	copy, ids, err := copyMigrationApplyRequest(input)
	if err != nil || !slices.Equal(ids, []ModuleID{"a"}) {
		t.Fatal(err)
	}
	copy.Plan.Modules[0].Module = "changed"
	copy.Plan.Steps[0].ID = "changed"
	if p.Modules[0].Module != "a" || p.Steps[0].ID == "changed" {
		t.Fatal("request not copied")
	}
	for _, mutate := range []func(*ReferenceMigrationApplyRequest){
		func(r *ReferenceMigrationApplyRequest) { r.CommandID = "short" }, func(r *ReferenceMigrationApplyRequest) { r.CommandID = identity.CommandID(strings.Repeat("a", 129)) },
		func(r *ReferenceMigrationApplyRequest) { r.CommandID = "migration;injected" }, func(r *ReferenceMigrationApplyRequest) { r.Plan = MigrationPlan{} },
		func(r *ReferenceMigrationApplyRequest) { r.Plan.Modules = nil }, func(r *ReferenceMigrationApplyRequest) { r.Plan.Modules = make([]ModuleVersion, 129) },
		func(r *ReferenceMigrationApplyRequest) { r.Plan.Steps = make([]MigrationStep, 4097) }, func(r *ReferenceMigrationApplyRequest) { r.Plan.CatalogDigest[0]++ },
		func(r *ReferenceMigrationApplyRequest) { r.Plan.Steps[0].Owner = "unknown" }, func(r *ReferenceMigrationApplyRequest) { r.Plan.Steps[0].ID = strings.Repeat("a", 129) },
		func(r *ReferenceMigrationApplyRequest) { r.Plan.Steps[0].ToVersion = 0 }, func(r *ReferenceMigrationApplyRequest) { r.Plan.Steps[0].StepDigest[0]++ },
		func(r *ReferenceMigrationApplyRequest) { r.Plan.Modules = append(r.Plan.Modules, r.Plan.Modules[0]) },
	} {
		changed := input
		changed.Plan.Modules = slices.Clone(p.Modules)
		changed.Plan.Steps = slices.Clone(p.Steps)
		mutate(&changed)
		if _, _, err := copyMigrationApplyRequest(changed); err == nil {
			t.Fatal("invalid request admitted")
		}
	}
	for _, n := range []int{16, 128} {
		changed := input
		changed.CommandID = identity.CommandID(strings.Repeat("a", n))
		if _, _, err := copyMigrationApplyRequest(changed); err != nil {
			t.Fatal(err)
		}
	}
	policy := MigrationApplyPolicy{TenantID: "tenant", ActorID: "operator", LookupKey: [32]byte{1}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	lookup, fingerprint := migrationApplyBindings(policy, p.Digest, [32]byte{2})
	changedPlan := p.Digest
	changedPlan[0]++
	nextLookup, nextFingerprint := migrationApplyBindings(policy, changedPlan, [32]byte{2})
	if lookup != nextLookup || fingerprint == nextFingerprint {
		t.Fatal("retry key can rebind a changed plan")
	}
	for _, mutate := range []func(*MigrationApplyPolicy){func(p *MigrationApplyPolicy) { p.ActorID = "other" }, func(p *MigrationApplyPolicy) { p.TenantID = "other" }, func(p *MigrationApplyPolicy) { p.LookupKey[0]++ }} {
		changed := policy
		mutate(&changed)
		l, f := migrationApplyBindings(changed, p.Digest, [32]byte{2})
		if l == lookup || f == fingerprint {
			t.Fatal("unbound operator/key scope")
		}
	}
}

func TestMigrationApplyProjectionAndUnknownClassification(t *testing.T) {
	out := ReferenceMigrationApplyResult{Result: MigrationApplyResult{command: "migration_command_0001", digest: [32]byte{1}, receipts: []MigrationContributorReceipt{{Module: "a", Version: 1}}}}
	copy := out.Result.Receipts()
	copy[0].Version++
	if out.Result.Receipts()[0].Version != 1 {
		t.Fatal("mutable receipt")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unknown, err := failMigrationNative(out, ctx, out.Result.command, migrationdb.ErrCommandOutcomeUnknown)
	var typed identity.UnknownCommitError
	var migrationErr MigrationError
	if !errors.As(err, &typed) || typed.CommandID != out.Result.command || !errors.As(err, &migrationErr) || migrationErr.State() != MigrationApplyUnknown || unknown.Result.State() != MigrationApplyUnknown || unknown.Result.CommandID() != out.Result.command || unknown.Result.Digest() != out.Result.digest {
		t.Fatal("unknown became cancellation/success", err)
	}
	_, err = failMigrationNative(out, context.Background(), out.Result.command, errors.New("secret driver diagnostic"))
	if strings.Contains(fmt.Sprintf("%+v %#v", err, err), "secret") {
		t.Fatal("driver diagnostic escaped")
	}
	for _, native := range []error{migrations.ErrInvalidRecord, migrations.ErrChecksumMismatch, migrations.ErrRenamedMigration, migrations.ErrDeletedMigration, migrations.ErrReorderedHistory} {
		result, err := failMigrationNative(out, context.Background(), out.Result.command, native)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || result.Result.State() != MigrationApplyIncompatible {
			t.Fatal("unrecognized history not incompatible", native)
		}
	}
}
