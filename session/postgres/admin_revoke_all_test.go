package postgres

import (
	"context"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestAdminRevokeAllPlanFencesSessionOnlyTargetAndGeneration(t *testing.T) {
	b := revokeBinding()
	op := session.AdminSessionRevokeAllOperation()
	b.ActorID = "original-admin"
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, string(b.UserID)
	p := &adminRevokeAllParticipant{Repository: &Repository{schema: "session_store"}}
	for _, before := range []uint64{0, 18} {
		cmd, err := mapAdminRevokeAllCommand(b, before)
		if err != nil {
			t.Fatal("exact target was rejected", err)
		}
		plan := kernel.CommandPlan{SubjectType: "session_set", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op},
			Lifecycle: &kernel.LifecyclePlan{EventType: "session.set-revoked.v1", BeforeVersion: before, AfterVersion: before + 1},
			Audits:    []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "protected"}}}
		if err := p.ValidateFeatureCommand(cmd, plan); err != nil {
			t.Fatal("exact session-only generation transition rejected", err)
		}
		if _, err := p.ApplyFeature(context.Background(), kernel.Work{}, cmd); err == nil {
			t.Fatal("structural intent permitted execution without original Work and actor")
		}
		plan.Lifecycle.AfterVersion++
		if p.ValidateFeatureCommand(cmd, plan) == nil {
			t.Fatal("invented successor accepted")
		}
	}
	if _, err := mapAdminRevokeAllCommand(b, ^uint64(0)); err == nil {
		t.Fatal("overflowing version accepted")
	}
	b.RecordID = "foreign-session"
	if _, err := mapAdminRevokeAllCommand(b, 0); err == nil {
		t.Fatal("session ID used as bulk aggregate")
	}
}
