package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestDirectoryAuthorityDecodePreservesScopeAndFullVersions(t *testing.T) {
	q := DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}
	for _, n := range []uint64{1, 1<<53 + 1, 1 << 63, math.MaxUint64} {
		text := strconv.FormatUint(n, 10)
		got, err := decodeDirectoryAuthority(q, "deployment", "tenant", text, text, false)
		if err != nil || got.Query != q || got.GlobalVersion != n || got.TenantVersion != n || got.Enabled {
			t.Fatal("scope or unsigned epoch changed", err)
		}
	}
	for _, malformed := range []string{"", "0", "01", "-1", "1.0", "18446744073709551616"} {
		if _, err := decodeDirectoryAuthority(q, "deployment", "tenant", malformed, "1", true); err == nil {
			t.Fatal("malformed global authority admitted")
		}
		if _, err := decodeDirectoryAuthority(q, "deployment", "tenant", "1", malformed, true); err == nil {
			t.Fatal("malformed tenant authority admitted")
		}
	}
	for _, pair := range [][2]string{{"foreign", "tenant"}, {"deployment", "foreign"}} {
		if _, err := decodeDirectoryAuthority(q, pair[0], pair[1], "1", "1", true); err == nil {
			t.Fatal("foreign authority admitted")
		}
	}
	if _, err := (*Repository)(nil).GetDirectoryAuthority(context.Background(), q); err == nil {
		t.Fatal("zero repository admitted")
	}
	if b, err := json.Marshal(q); err == nil || len(b) != 0 || strings.Contains(fmt.Sprintf("%#v", q), "deployment") {
		t.Fatal("authority scope disclosed")
	}
}

func TestDirectoryAuthorityMigrationPreservesHistoryAndExplicitBootstrap(t *testing.T) {
	base := MigrationSource{}
	history, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := DirectoryAuthorityMigrationSource{Base: base, Version: 15, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
	got, err := source.Load(context.Background())
	if err != nil || len(got) != len(history)+1 {
		t.Fatal("authority migration missing", err)
	}
	for i := range history {
		if history[i].Checksum() != got[i].Checksum() {
			t.Fatal("historical migration changed")
		}
	}
	for _, bad := range []DirectoryAuthorityMigrationSource{{}, {Base: base, Version: 9, GlobalAuthorityID: "deployment"}, {Base: base, Version: 15}, {Base: base, Version: 15, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant", "tenant"}}} {
		if rows, err := bad.Load(context.Background()); err == nil || rows != nil {
			t.Fatal("invalid bootstrap admitted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Load(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestDirectoryAuthorityRequiresExactInvocationAndTenantBeforeSQL(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	native, foreign := &scopeFeatureParticipant{}, &scopeFeatureParticipant{}
	plan.Feature.Contributor = native.Descriptor()
	newWork := func() Work {
		return Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: native}}
	}
	valid := DirectoryAuthorityAdmission{Query: DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: spec.Binding.TenantID}, GlobalVersion: 1, TenantVersion: 1}
	for _, change := range []func(*DirectoryAuthorityAdmission){func(q *DirectoryAuthorityAdmission) { q.Query.TenantID = "foreign" }, func(q *DirectoryAuthorityAdmission) { q.GlobalVersion = 0 }, func(q *DirectoryAuthorityAdmission) { q.TenantVersion = 0 }, func(q *DirectoryAuthorityAdmission) { q.Query.GlobalAuthorityID = "" }} {
		w := newWork()
		expected := valid
		change(&expected)
		if err := w.RequireActiveDirectoryAuthority(context.Background(), native, expected); err == nil || w.state.sqlStarted {
			t.Fatal("malformed scope reached SQL")
		}
	}
	for _, p := range []FeatureExecutionContributor{nil, foreign} {
		w := newWork()
		if err := w.RequireActiveDirectoryAuthority(context.Background(), p, valid); err == nil || w.state.sqlStarted {
			t.Fatal("foreign participant reached SQL")
		}
	}
	if err := (Work{}).RequireActiveDirectoryAuthority(context.Background(), native, valid); err == nil {
		t.Fatal("zero Work admitted")
	}
}
