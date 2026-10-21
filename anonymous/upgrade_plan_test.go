package anonymous_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
)

func upgradePlanFixture(t testing.TB) anonymous.MergePlan {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	target, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	source, err := anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: id, UserID: identity.UserID(id), TenantID: "tenant-a", State: anonymous.StateActive, Version: 1, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), Cleanup: anonymous.CleanupAnonymize})
	if err != nil {
		t.Fatal(err)
	}
	return anonymous.MergePlan{Source: source, Target: target, Conflicts: []anonymous.Conflict{{Field: "profile.display_name", Disposition: anonymous.KeepTarget}, {Field: "application.cart", Disposition: anonymous.Merge}}}
}

func TestUpgradePlanFreezesCanonicalDecisionsWithoutTakingAccountAuthority(t *testing.T) {
	input := upgradePlanFixture(t)
	wantSource, _ := input.Source.Record()
	plan, err := input.Validated()
	if err != nil {
		t.Fatal(err)
	}
	want := []anonymous.Conflict{{Field: "application.cart", Disposition: anonymous.Merge}, {Field: "profile.display_name", Disposition: anonymous.KeepTarget}}
	gotSource, _ := plan.Source.Record()
	if gotSource != wantSource || plan.Target != input.Target || !reflect.DeepEqual(plan.Conflicts, want) {
		t.Fatal("merge plan changed source scope, target or explicit decisions")
	}
	input.Conflicts[0].Disposition = anonymous.KeepSource
	input.Conflicts[1].Field = "changed"
	if !reflect.DeepEqual(plan.Conflicts, want) {
		t.Fatal("caller mutation changed the retained plan")
	}
	copy, err := plan.Validated()
	if err != nil {
		t.Fatal(err)
	}
	copy.Conflicts[0].Disposition = anonymous.Reject
	if !reflect.DeepEqual(plan.Conflicts, want) {
		t.Fatal("validated projection aliases original decisions")
	}
	// This is structural planning, not live authority: it must preserve original
	// expiry for the native command's later current-state and freshness fences.
	if !gotSource.ExpiresAt.Equal(wantSource.ExpiresAt) {
		t.Fatal("planning renewed the anonymous lifetime")
	}
	for _, disposition := range []anonymous.ConflictDisposition{anonymous.KeepSource, anonymous.KeepTarget, anonymous.Merge, anonymous.Reject} {
		input.Conflicts = []anonymous.Conflict{{Field: "application.cart", Disposition: disposition}}
		if _, err := input.Validated(); err != nil {
			t.Fatal("closed explicit disposition rejected", err)
		}
	}
	input.Conflicts = nil
	if _, err := input.Validated(); err != nil {
		t.Fatal("explicit no-transfer plan rejected", err)
	}
	input.Conflicts = []anonymous.Conflict{}
	if empty, err := input.Validated(); err != nil || empty.Conflicts != nil {
		t.Fatal("equivalent empty plan has a different canonical representation", err)
	}
}

func FuzzUpgradePlanConflicts(f *testing.F) {
	for _, field := range []string{"", "application.cart", "profile.display_name", "profile..name", "x\x00", strings.Repeat("a", 128), strings.Repeat("a", 129)} {
		for _, disposition := range []uint8{0, 1, 2, 3, 4, 255} {
			f.Add(field, disposition)
		}
	}
	base := upgradePlanFixture(f)
	f.Fuzz(func(t *testing.T, field string, disposition uint8) {
		input := base
		input.Conflicts = []anonymous.Conflict{{Field: field, Disposition: anonymous.ConflictDisposition(disposition)}}
		plan, err := input.Validated()
		if err != nil {
			if err != anonymous.ErrInvalidInput {
				t.Fatal("input classification changed", err)
			}
			return
		}
		if len(field) == 0 || len(field) > 128 || disposition < 1 || disposition > 4 || len(plan.Conflicts) != 1 || plan.Conflicts[0] != input.Conflicts[0] || plan.Target != base.Target {
			t.Fatal("accepted plan lost its bounded original decision")
		}
		again, err := plan.Validated()
		if err != nil || !reflect.DeepEqual(again.Conflicts, plan.Conflicts) {
			t.Fatal("canonical plan is not stable", err)
		}
		input.Conflicts[0].Field = "changed"
		if plan.Conflicts[0].Field != field {
			t.Fatal("accepted plan aliases input")
		}
	})
}

func TestUpgradePlanRejectsAmbiguousOrUnboundedDecisions(t *testing.T) {
	for _, mutate := range []func(*anonymous.MergePlan){
		func(p *anonymous.MergePlan) { p.Source = anonymous.AnonymousSubject{} },
		func(p *anonymous.MergePlan) { p.Target = "" },
		func(p *anonymous.MergePlan) { p.Target = "invalid\nidentity" },
		func(p *anonymous.MergePlan) { s, _ := p.Source.Record(); p.Target = s.ID },
		func(p *anonymous.MergePlan) {
			s, _ := p.Source.Record()
			s.State, s.Version = anonymous.StateUpgraded, 2
			p.Source, _ = anonymous.NewAnonymousSubject(s)
		},
		func(p *anonymous.MergePlan) {
			s, _ := p.Source.Record()
			s.Version = ^uint64(0)
			p.Source, _ = anonymous.NewAnonymousSubject(s)
		},
		func(p *anonymous.MergePlan) { p.Conflicts[0].Disposition = anonymous.Unspecified },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Disposition = 255 },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = strings.Repeat("a", 129) },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "profile..name" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "Profile.name" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "profile.name\n" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "profile.é" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "profile.1name" },
		func(p *anonymous.MergePlan) { p.Conflicts[0].Field = "profile.name-" },
		func(p *anonymous.MergePlan) { p.Conflicts = append(p.Conflicts, p.Conflicts[0]) },
		func(p *anonymous.MergePlan) { p.Conflicts = make([]anonymous.Conflict, 65) },
	} {
		p := upgradePlanFixture(t)
		mutate(&p)
		if _, err := p.Validated(); err != anonymous.ErrInvalidInput {
			t.Fatal("ambiguous or unbounded upgrade plan admitted", err)
		}
	}
	input := upgradePlanFixture(t)
	input.Conflicts = nil
	for n := range 64 {
		input.Conflicts = append(input.Conflicts, anonymous.Conflict{Field: fmt.Sprintf("application.field%d", n), Disposition: anonymous.KeepTarget})
	}
	if _, err := input.Validated(); err != nil {
		t.Fatal("exact conflict bound rejected", err)
	}
	if _, err := (anonymous.MergePlan{}).Validated(); err != anonymous.ErrInvalidInput {
		t.Fatal("zero upgrade plan accepted", err)
	}
}

func TestUpgradePlanPreservesPermanentDirectoryIdentifiers(t *testing.T) {
	// Permanent directory IDs keep their existing canonical-ID policy; unlike
	// newly generated anonymous subjects they need not be opaque base64url IDs.
	for _, target := range []identity.SubjectID{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "existing-directory-user"} {
		input := upgradePlanFixture(t)
		input.Target = target
		plan, err := input.Validated()
		if err != nil || plan.Target != target {
			t.Fatal("upgrade rejected or rewrote an existing canonical permanent ID", err)
		}
	}
}

func TestUpgradePlanRejectsImplicitDisclosure(t *testing.T) {
	plan := upgradePlanFixture(t)
	source, _ := plan.Source.Record()
	for _, value := range []any{plan, plan.Conflicts[0]} {
		if _, err := json.Marshal(value); !errors.Is(err, anonymous.ErrDisclosure) {
			t.Fatal("implicit serialization disclosed an upgrade plan", err)
		}
		text := fmt.Sprintf("%#v", value)
		if strings.Contains(text, string(source.ID)) || strings.Contains(text, string(plan.Target)) || strings.Contains(text, "profile.display_name") {
			t.Fatal("diagnostic leaked upgrade scope or decisions")
		}
	}
}
