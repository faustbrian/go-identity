package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-audit/memory"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// The fault is only at the acknowledgement seam: the real native sink has
// already accepted the immutable records when its acknowledgement is lost.
type lostAuditAcknowledgement struct{ audit.Sink }

func (s lostAuditAcknowledgement) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	result, err := s.Sink.AppendBatch(ctx, records)
	if err != nil {
		return result, err
	}
	return audit.BatchResult{}, audit.NewAppendError(audit.AppendUnknown, errors.New("synthetic lost acknowledgement"))
}

func custodyRecord(t *testing.T) audit.Record {
	t.Helper()
	builder, err := identity.NewIdentitySecurityEventV1(clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.Build(t.Context(), identity.SecurityEventInput{Action: identity.SecurityHIBPQueryRange, OccurredAt: time.Now().UTC(), Outcome: audit.OutcomeSucceeded, Reason: identity.SecurityCompleted, TenantID: baselineTenant, CommandID: command, CorrelationID: command, Actor: audit.ActorInput{Kind: audit.ActorSystem, ID: baselineActor}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(command), PolicyID: baselineResetPolicy, PolicyVersion: 9, Provider: identity.SecurityProvider{Kind: identity.SecurityProviderHIBP, Profile: identity.SecurityHIBPRange, Version: 1, Result: identity.SecurityProviderAccepted}})
	if err != nil {
		t.Fatal("native security record unavailable")
	}
	return record
}

func custodySink(t *testing.T) *memory.Store {
	t.Helper()
	store, err := memory.New(memory.Config{MaxRecords: 16, MaxBytes: 1 << 20, MaxBatchRecords: 2})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestLocalAuditCustodyReconcilesUnknownOriginalAfterRestart(t *testing.T) {
	ctx := t.Context()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store := custodySink(t)
	record := custodyRecord(t)
	canonical, _ := audit.CanonicalJSON(record)
	parsed, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits())
	if err != nil || parsed.RedactionApplied() {
		t.Fatal("native decoder unexpectedly trusts serialized privacy policy")
	}
	if _, err := store.Append(ctx, parsed); !errors.Is(err, audit.ErrRedactionRequired) {
		t.Fatal("native persistence accepted a decoded record without privacy policy")
	}
	custody, err := openLocalAuditCustody(directory, lostAuditAcknowledgement{store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.Append(ctx, record); err == nil || audit.AppendOutcomeOf(err) != audit.AppendUnknown {
		t.Fatal("lost primary acknowledgement became usable audit evidence")
	}
	entries, err := os.ReadDir(filepath.Join(directory, "audit-custody"))
	if err != nil || len(entries) != 1 {
		t.Fatal("unknown original event lost durable recovery custody")
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openLocalAuditCustody(directory, store)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Reconcile(ctx); err != nil {
		t.Fatal("original native event cannot reconcile after restart", err)
	}
	if err := reopened.Reconcile(ctx); err != nil {
		t.Fatal("confirmed reconciliation is not repeatable", err)
	}
	tenant, _ := audit.Tenant(baselineTenant)
	query, _ := audit.NewQuery(audit.QueryInput{Tenant: tenant, RecordID: record.ID(), Limit: 2})
	page, err := store.Query(ctx, query)
	if err != nil || len(page.Records) != 1 {
		t.Fatal("reconciliation lost or duplicated native event identity")
	}
	recovered, _ := audit.CanonicalJSON(page.Records[0])
	if !bytes.Equal(recovered, canonical) {
		t.Fatal("reconciliation changed original native bytes")
	}
	entries, err = os.ReadDir(filepath.Join(directory, "audit-custody"))
	if err != nil || len(entries) != 0 {
		t.Fatal("confirmed audit delivery left stale recovery custody")
	}
}

func TestLocalAuditCustodyRequiresDirectoryAcknowledgementBeforePrimary(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store := custodySink(t)
	custody, err := openLocalAuditCustody(directory, store)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	record := custodyRecord(t)
	acknowledge := custody.syncDirectory
	custody.syncDirectory = func(*os.Root) error { return errors.New("synthetic directory acknowledgement failure") }
	for range 2 {
		if _, err := custody.Append(t.Context(), record); err == nil || audit.AppendOutcomeOf(err) != audit.AppendRejected {
			t.Fatal("unacknowledged custody reached the primary sink")
		}
	}
	tenant, _ := audit.Tenant(baselineTenant)
	query, _ := audit.NewQuery(audit.QueryInput{Tenant: tenant, RecordID: record.ID(), Limit: 2})
	page, err := store.Query(t.Context(), query)
	if err != nil || len(page.Records) != 0 {
		t.Fatal("primary persisted despite failed original or repeated custody acknowledgement")
	}
	custody.syncDirectory = acknowledge
	if err := custody.Reconcile(t.Context()); err != nil {
		t.Fatal("original custody did not recover after directory acknowledgement")
	}
	page, err = store.Query(t.Context(), query)
	if err != nil || len(page.Records) != 1 {
		t.Fatal("custody recovery lost original event")
	}
}

func TestLocalAuditCustodyDeniesCancelledAndUnsafeReentry(t *testing.T) {
	for _, variant := range []string{"cancelled", "public", "symlink", "digest", "privacy"} {
		t.Run(variant, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			store := custodySink(t)
			custody, err := openLocalAuditCustody(directory, store)
			if err != nil {
				t.Fatal(err)
			}
			defer custody.Close()
			record := custodyRecord(t)
			canonical, _ := audit.CanonicalJSON(record)
			if variant == "privacy" {
				// Canonical field position is stable; add this disallowed field in
				// that position so the official parser, not syntax, is exercised.
				canonical = bytes.Replace(canonical, []byte(`"actor":`), []byte(`"description":"unapproved-private-field","actor":`), 1)
				if _, err := audit.ParseCanonicalJSON(canonical, audit.DefaultLimits()); err != nil {
					t.Fatal("privacy fixture is not an otherwise valid canonical record")
				}
			}
			raw, _ := json.Marshal([]json.RawMessage{canonical})
			name := auditCustodyName(raw)
			path := filepath.Join(directory, "audit-custody", name)
			if variant == "digest" {
				path = filepath.Join(directory, "audit-custody", "mismatched.json")
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if variant == "public" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "symlink" {
				outside := filepath.Join(directory, "outside.json")
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if variant == "cancelled" {
				cancel()
			}
			if err := custody.Reconcile(ctx); err == nil {
				t.Fatal("unsafe or cancelled recovery reached primary acknowledgement")
			}
			tenant, _ := audit.Tenant(baselineTenant)
			query, _ := audit.NewQuery(audit.QueryInput{Tenant: tenant, RecordID: record.ID(), Limit: 2})
			page, err := store.Query(t.Context(), query)
			if err != nil || len(page.Records) != 0 {
				t.Fatal("unsafe recovery persisted a record")
			}
		})
	}
}

func TestLocalAuditCustodyRecoversAtCapacityAfterPublicationCrash(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := memory.New(memory.Config{MaxRecords: 256, MaxBytes: 1 << 20, MaxBatchRecords: 2})
	if err != nil {
		t.Fatal(err)
	}
	custody, err := openLocalAuditCustody(directory, store)
	if err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(directory, "audit-custody")
	for index := range 256 {
		record := custodyRecord(t)
		canonical, _ := audit.CanonicalJSON(record)
		raw, _ := json.Marshal([]json.RawMessage{canonical})
		path := filepath.Join(spool, auditCustodyName(raw))
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if index == 255 {
			// The complete synced file still has its staging name when the
			// process crashes after hard-link publication, before defer runs.
			if err := os.Link(path, filepath.Join(spool, ".pending-00000000000000000000000000000000")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := custody.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openLocalAuditCustody(directory, store)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Reconcile(t.Context()); err != nil {
		t.Fatal("at-capacity publication crash permanently blocks original audit recovery", err)
	}
	tenant, _ := audit.Tenant(baselineTenant)
	query, err := audit.NewQuery(audit.QueryInput{Tenant: tenant, Limit: 256})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Query(t.Context(), query)
	if err != nil || len(page.Records) != 256 {
		t.Fatal("capacity recovery lost original retained batches")
	}
	entries, err := os.ReadDir(spool)
	if err != nil || len(entries) != 0 {
		t.Fatal("publication leftovers continued to consume audit capacity")
	}
}
