//go:build integration

package postgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// The real protected issuer and real audit/outbox contributors supply these
// records. This tests native transactional effects, not the public caller
// authentication/orchestration factory that is the next owned adapter step.
func testNativeSetRevocation(t *testing.T, ctx context.Context, pool *database.Pool, executor *IssueExecutor, issue func(*testing.T, string) session.Session) {
	prepare := func(t *testing.T, source session.Session, all, include bool, maximum uint32) (identity.CommandBinding, identity.Command, kernel.CommandPlan) {
		t.Helper()
		spec, _ := source.Bindings()
		op := session.RevokeOtherOperation()
		if all {
			op = session.RevokeAllOperation()
		}
		b := revokeBinding()
		b.TenantID, b.UserID, b.ActorID, b.RecordID, b.OperationID, b.SchemaID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID), spec.SessionID, op.OperationID, op.SchemaID
		var err error
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := mapSessionRecord(b, op, source)
		if err != nil {
			t.Fatal(err)
		}
		fields, _ := command.Feature()
		fields.Fields = append(fields.Fields,
			identity.FeatureField{Name: "set.maximum", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(maximum)}},
			identity.FeatureField{Name: "set.include-current", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: include}},
			identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: time.Now().UTC().Add(19 * time.Second).Format(storedTimeLayout)}},
		)
		command, err = identity.NewFeatureCommand(fields)
		if err != nil {
			t.Fatal(err)
		}
		builder, err := audit.NewBuilder(audit.BuilderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.session.revoke", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "session", "aggregate.id": b.RecordID, "aggregate.before_version": strconv.FormatUint(spec.Version, 10), "aggregate.after_version": strconv.FormatUint(spec.Version+1, 10), "retention.class": "standard"}})
		if err != nil {
			t.Fatal(err)
		}
		digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", seed)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := executor.coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: executor.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: executor.native.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.set-revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard", RetentionPolicyVersion: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native set plan", err)
		}
		return b, command, plan
	}
	active := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions WHERE tenant_id='issue' AND user_id='issue-user' AND state='active'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	execute := func(t *testing.T, b identity.CommandBinding, c identity.Command, p kernel.CommandPlan) (identity.CommandResult, error) {
		t.Helper()
		reservation, result, err := executor.coordinator.ReserveCommand(ctx, b, c, p)
		if err != nil || reservation == (kernel.Reservation{}) {
			return result, err
		}
		w, err := executor.coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.coordinator.Abort(w, identity.UnavailableError{})
		provisional, err := executor.coordinator.ApplyFeature(ctx, w, c)
		if err != nil {
			return executor.coordinator.Abort(w, err)
		}
		return executor.coordinator.Commit(w, provisional)
	}
	t.Run("bulk bound rolls back the complete set", func(t *testing.T) {
		source := issue(t, "")
		issue(t, "")
		issue(t, "")
		before := active(t)
		b, c, p := prepare(t, source, false, false, 1)
		result, err := execute(t, b, c, p)
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted || active(t) != before {
			t.Fatal("truncated or partial bulk revocation", err)
		}
		var n int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.set_revocations WHERE command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&n); err != nil || n != 0 {
			t.Fatal("failed bulk retained success", err)
		}
		spec, _ := source.Bindings()
		stored, err := executor.native.Get(ctx, spec.TenantID, spec.SessionID)
		payload, _, _ := encodeRecord(stored.Session)
		original, _, _ := encodeRecord(source)
		if err != nil || stored.Revoked || string(payload) != string(original) {
			t.Fatal("source changed on bound denial", err)
		}
	})
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run("native "+mode, func(t *testing.T) {
			source := issue(t, "")
			sibling := issue(t, "")
			// Exceed one Work page: a first-page-only implementation must not
			// commit a truncated set or a count inconsistent with its tombstones.
			for i := 0; i < 18; i++ {
				issue(t, "")
			}
			before := active(t)
			spec, _ := source.Bindings()
			other, _ := sibling.Bindings()
			b, c, p := prepare(t, source, mode != "other", mode == "all-include", 100)
			result, err := execute(t, b, c, p)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Feature.BeforeVersion != spec.Version || result.Feature.AfterVersion != spec.Version+1 {
				t.Fatal("native bulk commit", err)
			}
			include := mode == "all-include"
			want := before - 1
			if include {
				want = before
			}
			var count int
			var subject string
			var current bool
			if err = pool.Raw().QueryRow(ctx, `SELECT revoked_count,subject_version::text,include_current FROM session_store.set_revocations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), mustCommandBytes(t, b.CommandID)).Scan(&count, &subject, &current); err != nil || count != want || current != include {
				t.Fatal("wrong retained result", err, count, want)
			}
			vector, _ := spec.Authority.Bindings()
			if subject != strconv.FormatUint(vector.User.Version, 10) {
				t.Fatal("new subject invalidation authority")
			}
			stored, err := executor.native.Get(ctx, spec.TenantID, spec.SessionID)
			if err != nil || stored.Revoked != include || stored.FamilyRevoked {
				t.Fatal("source disposition", err)
			}
			after, _ := stored.Session.Bindings()
			afterVector, _ := after.Authority.Bindings()
			if after.Lookup != spec.Lookup || after.Authentication != spec.Authentication || after.IssuedAt != spec.IssuedAt || after.LastActivityAt != spec.LastActivityAt || afterVector.User != vector.User {
				t.Fatal("source survivor renewed or owner invalidated")
			}
			expectedVersion := spec.Version + 1
			if include {
				expectedVersion = spec.Version
			}
			if after.Version != expectedVersion || afterVector.Session.Version != expectedVersion {
				t.Fatal("source/snapshot version inconsistent")
			}
			revoked, err := executor.native.Get(ctx, other.TenantID, other.SessionID)
			original, _, _ := encodeRecord(sibling)
			payload, _, _ := encodeRecord(revoked.Session)
			if err != nil || !revoked.Revoked || revoked.FamilyRevoked || string(original) != string(payload) {
				t.Fatal("sibling tombstone/history", err)
			}
			remaining := 1
			if include {
				remaining = 0
			}
			if active(t) != remaining {
				t.Fatal("incomplete user set")
			}
			_, replay, err := executor.coordinator.ReserveCommand(ctx, b, c, p)
			if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID {
				t.Fatal("bulk replay changed receipt", err)
			}
			q, caller := revokeRecoveryInput(b)
			recovered, err := executor.coordinator.RecoverCommand(ctx, q, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != b {
				t.Fatal("native retained recovery", err)
			}
			var audits, events int
			if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, b.CommandID)).Scan(&audits, &events); err != nil || audits != 1 || events != 1 {
				t.Fatal("real same-command effects", err)
			}
		})
	}
	t.Run("abort rolls back staged tombstones and retained effects", func(t *testing.T) {
		source := issue(t, "")
		sibling := issue(t, "")
		before := active(t)
		b, c, p := prepare(t, source, true, true, 100)
		reservation, _, err := executor.coordinator.ReserveCommand(ctx, b, c, p)
		if err != nil {
			t.Fatal(err)
		}
		w, err := executor.coordinator.Begin(ctx, reservation)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.coordinator.Abort(w, identity.UnavailableError{})
		if _, err = executor.coordinator.ApplyFeature(ctx, w, c); err != nil {
			t.Fatal("stage complete native set", err)
		}
		result, _ := executor.coordinator.Abort(w, context.Canceled)
		if result.Outcome == identity.CommitOutcomeCommitted || active(t) != before {
			t.Fatal("abort retained partial mutation")
		}
		for _, original := range []session.Session{source, sibling} {
			spec, _ := original.Bindings()
			stored, readErr := executor.native.Get(ctx, spec.TenantID, spec.SessionID)
			oldPayload, _, _ := encodeRecord(original)
			payload, _, _ := encodeRecord(stored.Session)
			if readErr != nil || stored.Revoked || string(payload) != string(oldPayload) {
				t.Fatal("abort changed original source/target", readErr)
			}
		}
		var retained, audits, events int
		if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.set_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, b.CommandID), int64(audit.OutcomeSucceeded)).Scan(&retained, &audits, &events); err != nil || retained != 0 || audits != 0 || events != 0 {
			t.Fatal("abort retained participant/audit/lifecycle effects", err)
		}
		var canonical []byte
		if err = pool.Raw().QueryRow(ctx, `SELECT r.canonical_record FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1`, mustCommandBytes(t, b.CommandID)).Scan(&canonical); err != nil {
			t.Fatal("missing terminal failure audit", err)
		}
		failure, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
		if err != nil || failure.Outcome() == audit.OutcomeSucceeded || !failure.Changes().NoChange() || failure.Attributes()["aggregate.before_version"] != failure.Attributes()["aggregate.after_version"] {
			t.Fatal("abort retained success audit or version transition", err)
		}
	})
}
