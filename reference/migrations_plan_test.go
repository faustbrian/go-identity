package reference

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func planFixture(t *testing.T, namespace string, owner ModuleID, count int) migrationSnapshot {
	t.Helper()
	h := migrationHistory{namespace: namespace, owners: make(map[migrations.Version]ModuleID)}
	for i := 1; i <= count; i++ {
		m, err := migrations.NewMigration(migrations.Version(i), "step", migrations.TransactionModeDefault, "SELECT 1", "")
		if err != nil {
			t.Fatal(err)
		}
		h.history = append(h.history, m)
		h.owners[m.Version()] = owner
	}
	return migrationSnapshot{history: h, statuses: h.project(nil)}
}

func TestMigrationPlanAggregateBudget(t *testing.T) {
	a, b := planFixture(t, "a", "a", 2048), planFixture(t, "b", "b", 2048)
	p, err := buildMigrationPlan([]migrationSnapshot{a, b}, []ModuleID{"a", "b"})
	if err != nil || len(p.Steps) != 4096 {
		t.Fatal("exact aggregate limit", len(p.Steps), err)
	}
	b = planFixture(t, "b", "b", 2049)
	p, err = buildMigrationPlan([]migrationSnapshot{a, b}, []ModuleID{"a", "b"})
	var invalid identity.InvalidInputError
	if !errors.As(err, &invalid) || p.Digest != ([32]byte{}) {
		t.Fatal("aggregate overflow accepted", err)
	}
	long := planFixture(t, "a", "a", 1)
	m, err := migrations.NewMigration(1, strings.Repeat("a", 127), migrations.TransactionModeDefault, "SELECT 1", "")
	if err != nil {
		t.Fatal(err)
	}
	long.history.history[0] = m
	if _, err := buildMigrationPlan([]migrationSnapshot{long}, []ModuleID{"a"}); !errors.As(err, &invalid) {
		t.Fatal("oversized step identity", err)
	}
	m, err = migrations.NewMigration(1, strings.Repeat("a", 126), migrations.TransactionModeDefault, "SELECT 1", "")
	if err != nil {
		t.Fatal(err)
	}
	long.history.history[0] = m
	if p, err := buildMigrationPlan([]migrationSnapshot{long}, []ModuleID{"a"}); err != nil || len(p.Steps[0].ID) != 128 {
		t.Fatal("exact step identity budget", err)
	}
}

func TestMigrationPlanCanonicalEncoding(t *testing.T) {
	s := planFixture(t, "a", "a", 1)
	p, err := buildMigrationPlan([]migrationSnapshot{s}, []ModuleID{"a"})
	if err != nil {
		t.Fatal(err)
	}
	// Independent wire oracle: deliberately does not call production helpers.
	var wire bytes.Buffer
	number := func(n uint64) {
		if err := binary.Write(&wire, binary.BigEndian, n); err != nil {
			t.Fatal(err)
		}
	}
	text := func(s string) { number(uint64(len(s))); wire.WriteString(s) }
	text("golib/reference/migrations/v1/plan")
	wire.Write(p.BaseLedgerDigest[:])
	wire.Write(p.CatalogDigest[:])
	number(1)
	text("a")
	number(0)
	number(1)
	step := p.Steps[0]
	text("a")
	text("1_step")
	number(0)
	number(1)
	wire.Write(step.SourceDigest[:])
	wire.Write(step.StepDigest[:])
	if want := sha256.Sum256(wire.Bytes()); p.Digest != want {
		t.Fatal("canonical encoding differs from independent oracle")
	}
	mutations := []func(*MigrationPlan){
		func(p *MigrationPlan) { p.BaseLedgerDigest[0] ^= 1 },
		func(p *MigrationPlan) { p.CatalogDigest[0] ^= 1 },
		func(p *MigrationPlan) { p.Modules[0].Module = "b" },
		func(p *MigrationPlan) { p.Modules[0].Version++ },
		func(p *MigrationPlan) { p.Modules = append(p.Modules, ModuleVersion{"b", 0}) },
		func(p *MigrationPlan) { p.Steps[0].Owner = "b" },
		func(p *MigrationPlan) { p.Steps[0].ID += "x" },
		func(p *MigrationPlan) { p.Steps[0].FromVersion++ },
		func(p *MigrationPlan) { p.Steps[0].ToVersion++ },
		func(p *MigrationPlan) { p.Steps[0].SourceDigest[0] ^= 1 },
		func(p *MigrationPlan) { p.Steps[0].StepDigest[0] ^= 1 },
		func(p *MigrationPlan) { p.Steps = append(p.Steps, p.Steps[0]) },
	}
	for i, mutate := range mutations {
		copy := p
		copy.Modules = append([]ModuleVersion(nil), p.Modules...)
		copy.Steps = append([]MigrationStep(nil), p.Steps...)
		mutate(&copy)
		if migrationPlanDigest(copy) == p.Digest {
			t.Fatal("unbound field", i)
		}
	}
	if migrationStepDigest(step) == p.Digest || step.SourceDigest == p.Digest || p.BaseLedgerDigest == p.CatalogDigest {
		t.Fatal("digest domains collide")
	}
	x, y := newMigrationDigest("step"), newMigrationDigest("step")
	x.string("ab")
	x.string("c")
	y.string("a")
	y.string("bc")
	if x.sum() == y.sum() {
		t.Fatal("ambiguous string boundaries")
	}
}

func TestMigrationPlanBindsSourceAndLedger(t *testing.T) {
	s := planFixture(t, "a", "a", 2)
	p, err := buildMigrationPlan([]migrationSnapshot{s}, []ModuleID{"a"})
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*migrationHistory){
		func(h *migrationHistory) { h.preflight = "SELECT 1" },
		func(h *migrationHistory) { h.namespace = "b" },
		func(h *migrationHistory) { h.owners[1] = "b" },
		func(h *migrationHistory) {
			h.guards = []migrationGuard{{version: 1, schema: "owned", tables: []string{"t"}, roles: []string{"r"}, columns: []string{"t.c"}, functions: []string{"f"}}}
		},
		func(h *migrationHistory) {
			m, _ := migrations.NewMigration(1, "renamed", migrations.TransactionModeDefault, "SELECT 1", "")
			h.history[0] = m
		},
		func(h *migrationHistory) {
			m, _ := migrations.NewMigration(1, "step", migrations.TransactionModeNone, "SELECT 1", "")
			h.history[0] = m
		},
		func(h *migrationHistory) {
			m, _ := migrations.NewMigration(1, "step", migrations.TransactionModeDefault, "SELECT 2", "")
			h.history[0] = m
		},
	}
	for i, mutate := range mutations {
		copy := planFixture(t, "a", "a", 2).history
		mutate(&copy)
		if migrationSourceDigest(copy) == p.Steps[0].SourceDigest {
			t.Fatal("unbound source identity", i)
		}
	}
	m := s.history.history[0]
	r, err := migrations.NewRecord(migrations.RecordKindMigration, m.Version(), m.Name(), m.Checksum(), time.Unix(100, 0), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	s.records = []migrations.Record{r}
	s.statuses = s.history.project(s.records)
	installed, err := buildMigrationPlan([]migrationSnapshot{s}, []ModuleID{"a"})
	if err != nil || installed.BaseLedgerDigest == p.BaseLedgerDigest || installed.CatalogDigest != p.CatalogDigest || !reflect.DeepEqual(installed.Modules, []ModuleVersion{{"a", 1}}) || len(installed.Steps) != 1 || installed.Steps[0].FromVersion != 1 {
		t.Fatal("prefix binding", err)
	}
	r, err = migrations.NewRecord(migrations.RecordKindMigration, m.Version(), m.Name(), m.Checksum(), time.Unix(101, 0), 2*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	s.records[0] = r
	changed, err := buildMigrationPlan([]migrationSnapshot{s}, []ModuleID{"a"})
	if err != nil || changed.BaseLedgerDigest == installed.BaseLedgerDigest || changed.CatalogDigest != installed.CatalogDigest {
		t.Fatal("completion metadata not bound", err)
	}
}
