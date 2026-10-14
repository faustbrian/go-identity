package postgres

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func privacyJournalFixture(t *testing.T) (claimRequest, identity.CommandResult) {
	t.Helper()
	command := recordPrivacy(t, nil, nil, "privacy-key")
	c, _ := command.RequestPrivacyExport()
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewPrivacyExportEvidenceKey(7, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	spec := identity.PrivacyExportSnapshotSpecV1{ExportID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: c.Binding.TenantID, SubjectID: c.Binding.UserID, CommandID: c.Binding.CommandID, IdentityVersion: c.ExpectedIdentityVersion, PrivacyEpoch: c.ExpectedPrivacyEpoch + 1, LifecycleSequence: ^uint64(0), RequestedAtMicroseconds: 1000000000}
	// These synthetic cuts exercise receipt encoding, not owner provenance.
	for _, p := range c.Projections {
		spec.Cuts = append(spec.Cuts, identity.PrivacyExportContributorCutV1{ContributorID: p.ContributorID, ProjectionID: p.ProjectionID, CheckpointPosition: ^uint64(0)})
	}
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := identity.PrivacyExportIntentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	r := identity.CommandResult{Binding: c.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "privacy-audit", PrivacyExport: &identity.PrivacyExportRequestReceipt{Status: identity.PrivacyExportQueued, Snapshot: snapshot.Record(), ExpectedAuthorityVersion: c.ExpectedAuthorityVersion, ExpectedPrivacyEpoch: c.ExpectedPrivacyEpoch, MaximumBytes: c.MaximumBytes, ArtifactTTL: c.ArtifactTTL, IntentDigest: digest}}
	if _, err := r.ValidatePrivacyExportRequest(c, key); err != nil {
		t.Fatal(err)
	}
	return q, r
}

func TestPrivacyJournalRetainsExactIntent(t *testing.T) {
	q, r := privacyJournalFixture(t)
	wire, err := encodeJournalResult(q, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJournalResult(q, wire)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("original receipt changed", err)
	}
	for name, change := range map[string]func(*identity.PrivacyExportRequestReceipt){
		"intent":    func(p *identity.PrivacyExportRequestReceipt) { p.IntentDigest[0]++ },
		"authority": func(p *identity.PrivacyExportRequestReceipt) { p.ExpectedAuthorityVersion++ },
		"privacy":   func(p *identity.PrivacyExportRequestReceipt) { p.ExpectedPrivacyEpoch++; p.Snapshot.PrivacyEpoch++ },
		"identity":  func(p *identity.PrivacyExportRequestReceipt) { p.Snapshot.IdentityVersion++ },
		"maximum":   func(p *identity.PrivacyExportRequestReceipt) { p.MaximumBytes++ },
		"ttl":       func(p *identity.PrivacyExportRequestReceipt) { p.ArtifactTTL += time.Second },
		"projection": func(p *identity.PrivacyExportRequestReceipt) {
			p.Snapshot.Contributors[0].ProjectionID = identity.PrivacyExportStagedSubjectV1
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed identity.CommandResult
			if json.Unmarshal(wire, &changed) != nil {
				t.Fatal("fixture decode")
			}
			change(changed.PrivacyExport)
			if changed.Validate() != nil {
				t.Fatal("fixture must remain structurally valid")
			}
			if _, err := encodeJournalResult(q, changed); err == nil {
				t.Fatal("different original request accepted for persistence")
			}
			bad, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeJournalResult(q, bad); err == nil {
				t.Fatal("different original request accepted for replay")
			}
		})
	}
	for name, change := range map[string]func(*identity.PrivacyExportRequestCommand){
		"session":         func(c *identity.PrivacyExportRequestCommand) { c.SessionID = "other-session" },
		"session-version": func(c *identity.PrivacyExportRequestCommand) { c.SessionVersion++ },
		"policy":          func(c *identity.PrivacyExportRequestCommand) { c.Binding.PolicyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			other, err := prepareClaim(recordPrivacy(t, change, nil, "privacy-key"), [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeJournalResult(other, wire); err == nil {
				t.Fatal("receipt recovered under changed request")
			}
		})
	}
	// Scope-only observation cannot prove request intent or MAC validity. It
	// must preserve bytes for the service's retained-key verification, not
	// manufacture a request or reject historical terminal records.
	observed := q
	observed.source = nil
	if got, err := decodeJournalResult(observed, wire); err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("scope-only observation changed", err)
	}
	q.source = nil
	r.Outcome, r.PrivacyExport, r.AuditEventID = identity.CommitOutcomeNotCommitted, nil, ""
	if _, err := encodeJournalResult(q, r); err != nil {
		t.Fatal("noncommitted receipt requires unused intent", err)
	}
}
