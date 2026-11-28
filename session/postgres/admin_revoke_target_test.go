package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestAdminRevokeTargetUsesExactPrimaryScopeAndRecord(t *testing.T) {
	record, _, _ := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	b := revokeBinding()
	op := session.AdminSessionRevokeOperation()
	b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, "another-admin"
	b.RecordID, b.OperationID, b.SchemaID = spec.SessionID, op.OperationID, op.SchemaID
	for _, tc := range []struct {
		name     string
		adjust   func(*StoredSession, *identity.CommandBinding, *string)
		eligible bool
		invalid  bool
	}{
		{name: "exact different actor", eligible: true},
		{name: "wrong user", adjust: func(_ *StoredSession, b *identity.CommandBinding, _ *string) { b.UserID = "wrong-user" }},
		{name: "wrong audience", adjust: func(_ *StoredSession, _ *identity.CommandBinding, a *string) { *a = "wrong-audience" }},
		{name: "revoked", adjust: func(s *StoredSession, _ *identity.CommandBinding, _ *string) { s.Revoked = true }},
		{name: "family revoked", adjust: func(s *StoredSession, _ *identity.CommandBinding, _ *string) { s.FamilyRevoked = true }},
		{name: "mismatched stored identity", invalid: true, adjust: func(_ *StoredSession, b *identity.CommandBinding, _ *string) { b.RecordID = "wrong-session" }},
		{name: "mismatched stored tenant", invalid: true, adjust: func(_ *StoredSession, b *identity.CommandBinding, _ *string) { b.TenantID = "wrong-tenant" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, aud := b, spec.Audience
			stored := StoredSession{Session: record, CurrentFamilyVersion: spec.FamilyVersion}
			if tc.adjust != nil {
				tc.adjust(&stored, &b, &aud)
			}
			target, present, err := freezeAdminRevokeTarget(b, aud, stored)
			if (err != nil) != tc.invalid || present != tc.eligible {
				t.Fatal("inconsistent exact-scope target", err, present)
			}
			if !present {
				if target.version != 0 || target.record != (session.Session{}) {
					t.Fatal("no-op disclosed target data")
				}
				return
			}
			payload, _, err := encodeRecord(record)
			if err != nil || target.version != spec.Version || target.digest != sha256.Sum256(payload) || target.record != record {
				t.Fatal("target record was replaced or not bound", err)
			}
		})
	}
}

func TestAdminRevokeParticipantRequiresProtectedExactTargetPlan(t *testing.T) {
	record, _, _ := identifierSessionFixture(t)
	spec, _ := record.Bindings()
	op := session.AdminSessionRevokeOperation()
	b := revokeBinding()
	b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, "another-admin"
	b.RecordID, b.OperationID, b.SchemaID = spec.SessionID, op.OperationID, op.SchemaID
	target, present, err := freezeAdminRevokeTarget(b, spec.Audience, StoredSession{Session: record, CurrentFamilyVersion: spec.FamilyVersion})
	if err != nil || !present {
		t.Fatal("exact target fixture unavailable", err)
	}
	c, err := mapAdminRevokeCommand(b, target)
	if err != nil {
		t.Fatal(err)
	}
	p := &adminRevokeParticipant{Repository: &Repository{schema: "session_store"}}
	plan := kernel.CommandPlan{
		SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op},
		Lifecycle: &kernel.LifecyclePlan{EventType: "session.revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1},
		Audits:    []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "protected"}},
	}
	if err := p.ValidateFeatureCommand(c, plan); err != nil {
		t.Fatal("exact plan denied", err)
	}
	if _, err := p.ApplyFeature(context.Background(), kernel.Work{}, c); err == nil {
		t.Fatal("structural plan obtained mutation authority")
	}
	plan.Audits[0].RetentionClass = "standard"
	if err := p.ValidateFeatureCommand(c, plan); err == nil {
		t.Fatal("privileged write downgraded its audit policy")
	}
	plan.Audits[0].RetentionClass = "protected"
	plan.Lifecycle.AfterVersion++
	if err := p.ValidateFeatureCommand(c, plan); err == nil {
		t.Fatal("plan invented successor")
	}
}

func TestAdminRevokeCommitResultPreservesUnknown(t *testing.T) {
	b := revokeBinding()
	var unavailable identity.UnavailableError
	r := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}
	result, err := adminRevokeCommitResult(b, 1, r, unavailable)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || unknown.CommandID != b.CommandID || result.Revoked || result.Version != 0 {
		t.Fatal("ambiguous write lost recoverable command identity", err)
	}
}

func TestAdminRevokeWorkRequiresFreshnessAtFinalCommit(t *testing.T) {
	var participant any = &adminRevokeParticipant{}
	if _, ok := participant.(kernel.FeatureCommitContributor); !ok {
		t.Fatal("admin revocation is not revalidated after audit and outbox staging")
	}
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                         string
		lease, primary, factor, want time.Time
	}{
		{"original observation first", now.Add(time.Second), now.Add(3 * time.Second), now.Add(2 * time.Second), now.Add(time.Second)},
		{"original password freshness first", now.Add(3 * time.Second), now.Add(time.Second), now.Add(2 * time.Second), now.Add(time.Second)},
		{"original factor freshness first", now.Add(3 * time.Second), now.Add(2 * time.Second), now.Add(time.Second), now.Add(time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := earliestAdminRevokeDeadline(test.lease, test.primary, test.factor); !got.Equal(test.want) {
				t.Fatal("protected work retained a later deadline")
			}
		})
	}
}
