package identity

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func privacyReceiptFixture(t *testing.T) (PrivacyExportRequestCommand, CommandResult, PrivacyExportEvidenceKey) {
	t.Helper()
	c := privacyRequestFixture()
	key, spec := privacySnapshotFixture(t)
	spec.CommandID, spec.TenantID, spec.SubjectID = c.Binding.CommandID, c.Binding.TenantID, c.Binding.UserID
	spec.IdentityVersion, spec.PrivacyEpoch = c.ExpectedIdentityVersion, c.ExpectedPrivacyEpoch+1
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PrivacyExportIntentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	r := CommandResult{Binding: c.Binding, Outcome: CommitOutcomeCommitted, AuditEventID: "privacy-audit", PrivacyExport: &PrivacyExportRequestReceipt{Status: PrivacyExportQueued, Snapshot: snapshot.Record(), ExpectedAuthorityVersion: c.ExpectedAuthorityVersion, ExpectedPrivacyEpoch: c.ExpectedPrivacyEpoch, MaximumBytes: c.MaximumBytes, ArtifactTTL: c.ArtifactTTL, IntentDigest: digest}}
	return c, r, key
}

func TestPrivacyReceiptQueuedAdmissionAndDurableReconstruction(t *testing.T) {
	c, r, key := privacyReceiptFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.ValidatePrivacyExportRequest(c, key)
	if err != nil || !snapshot.Valid() {
		t.Fatal("exact receipt refused", err)
	}
	wire, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var replay CommandResult
	if err := json.Unmarshal(wire, &replay); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.ValidatePrivacyExportRequest(c, key); err != nil {
		t.Fatal("durable metadata lost", err)
	}
	r.PrivacyExport.Snapshot.Contributors[0].Checkpoint.Position++
	if snapshot.Record().Contributors[0].Checkpoint.Position != 1 {
		t.Fatal("verified snapshot aliased receipt")
	}
	if _, err := r.ValidatePrivacyExportRequest(c, key); err == nil {
		t.Fatal("mutated cut accepted")
	}
}

func TestPrivacyReceiptRejectsCrossScopeAndMixedOrCompletedAdmission(t *testing.T) {
	for i, mutate := range []func(*CommandResult){
		func(r *CommandResult) { r.PrivacyExport.Status = PrivacyExportReady },
		func(r *CommandResult) { r.PrivacyExport.Status = PrivacyExportRunning },
		func(r *CommandResult) { r.PrivacyExport.Status = PrivacyExportFailed },
		func(r *CommandResult) { r.PrivacyExport.Status = PrivacyExportCancelled },
		func(r *CommandResult) { r.PrivacyExport.Status = PrivacyExportExpired },
		func(r *CommandResult) { r.PrivacyExport.Status = "unknown" },
		func(r *CommandResult) { r.PrivacyExport = nil },
		func(r *CommandResult) { r.Feature = &FeatureReceipt{} },
		func(r *CommandResult) { r.Profile = &UserProfile{} },
		func(r *CommandResult) { r.Revocation = &RevocationOutcome{} },
		func(r *CommandResult) { r.Unlink = &AccountUnlinkReceipt{} },
		func(r *CommandResult) { r.Link = &AccountLinkReceipt{} },
		func(r *CommandResult) { r.Identifier = &IdentifierReceipt{} },
		func(r *CommandResult) { r.User = User{ID: r.Binding.UserID} },
		func(r *CommandResult) { r.ExpectedVersion = 1 },
		func(r *CommandResult) { r.AuditEventID = "" },
		func(r *CommandResult) { r.RetryAfter = time.Second },
		func(r *CommandResult) { r.Binding.OperationID = "identity.user.create" },
		func(r *CommandResult) { r.Binding.SchemaVersion = 2 },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.CommandID = "AgICAgICAgICAgICAgICAg" },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.SubjectID = "AgICAgICAgICAgICAgICAg" },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.TenantID = "AgICAgICAgICAgICAgICAg" },
		func(r *CommandResult) { r.PrivacyExport.ExpectedPrivacyEpoch++ },
		func(r *CommandResult) { r.PrivacyExport.ExpectedPrivacyEpoch = math.MaxUint64 },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.SchemaMinor = 1 },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.EvidenceKeyVersion = 0 },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.Digest = [32]byte{} },
		func(r *CommandResult) {
			r.PrivacyExport.Snapshot.Contributors = r.PrivacyExport.Snapshot.Contributors[:22]
		},
		func(r *CommandResult) { r.PrivacyExport.Snapshot.Contributors[0].Checkpoint.Position = 0 },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.Contributors[0].ScopeKeyDigest = [32]byte{} },
		func(r *CommandResult) {
			r.PrivacyExport.Snapshot.Contributors[1] = r.PrivacyExport.Snapshot.Contributors[0]
		},
		func(r *CommandResult) { r.PrivacyExport.MaximumBytes = 0 },
		func(r *CommandResult) { r.PrivacyExport.ArtifactTTL = 0 },
		func(r *CommandResult) { r.PrivacyExport.IntentDigest = [32]byte{} },
	} {
		_, r, _ := privacyReceiptFixture(t)
		mutate(&r)
		if r.Validate() == nil {
			t.Fatalf("invalid admission %d", i)
		}
	}
}

func TestPrivacyReceiptMatchesOriginalIntentAndRetainedKey(t *testing.T) {
	for i, mutate := range []func(*CommandResult){
		func(r *CommandResult) { r.PrivacyExport.ExpectedAuthorityVersion++ },
		func(r *CommandResult) { r.PrivacyExport.IntentDigest[0]++ },
		func(r *CommandResult) { r.PrivacyExport.MaximumBytes++ },
		func(r *CommandResult) { r.PrivacyExport.ArtifactTTL += time.Second },
		func(r *CommandResult) { r.PrivacyExport.Snapshot.IdentityVersion++ },
		func(r *CommandResult) {
			r.PrivacyExport.Snapshot.Contributors[0].ProjectionID = PrivacyExportStagedSubjectV1
		},
		func(r *CommandResult) { r.Binding.CorrelationID = "other-correlation" },
	} {
		c, r, key := privacyReceiptFixture(t)
		mutate(&r)
		if _, err := r.ValidatePrivacyExportRequest(c, key); err == nil {
			t.Fatalf("substitution %d", i)
		}
	}
	c, r, _ := privacyReceiptFixture(t)
	wrong, _ := NewPrivacyExportEvidenceKey(7, [32]byte{9})
	if _, err := r.ValidatePrivacyExportRequest(c, wrong); err == nil {
		t.Fatal("wrong key")
	}
	if _, err := r.ValidatePrivacyExportRequest(c, PrivacyExportEvidenceKey{}); err == nil {
		t.Fatal("missing retained key")
	}
}

func TestPrivacyReceiptKnownNoncommittedOutcomes(t *testing.T) {
	for _, outcome := range []CommitOutcome{CommitOutcomeNotCommitted, CommitOutcomeUnknown, CommitOutcomeConflict, CommitOutcomeInProgress} {
		c, r, _ := privacyReceiptFixture(t)
		r.Outcome, r.PrivacyExport, r.AuditEventID = outcome, nil, ""
		if outcome == CommitOutcomeInProgress {
			r.RetryAfter = time.Minute
		}
		if err := r.Validate(); err != nil {
			t.Fatal("known outcome discarded", outcome, err)
		}
		if s, err := r.ValidatePrivacyExportRequest(c, PrivacyExportEvidenceKey{}); err != nil || s.Valid() {
			t.Fatal("known outcome fabricated snapshot", outcome, err)
		}
		r.PrivacyExport = &PrivacyExportRequestReceipt{}
		if r.Validate() == nil {
			t.Fatal("noncommitted payload")
		}
	}
}

func TestPrivacyReceiptFullWidthCountersAndRedaction(t *testing.T) {
	c, r, key := privacyReceiptFixture(t)
	c.ExpectedIdentityVersion, c.ExpectedAuthorityVersion, c.ExpectedPrivacyEpoch = math.MaxUint64, math.MaxUint64, math.MaxUint64-1
	_, spec := privacySnapshotFixture(t)
	spec.IdentityVersion, spec.PrivacyEpoch = c.ExpectedIdentityVersion, math.MaxUint64
	snapshot, err := key.SealSnapshotV1(spec)
	if err != nil {
		t.Fatal(err)
	}
	r.PrivacyExport.Snapshot = snapshot.Record()
	r.PrivacyExport.ExpectedPrivacyEpoch = c.ExpectedPrivacyEpoch
	r.PrivacyExport.ExpectedAuthorityVersion = c.ExpectedAuthorityVersion
	r.PrivacyExport.IntentDigest, err = PrivacyExportIntentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ValidatePrivacyExportRequest(c, key); err != nil {
		t.Fatal("full-width counters corrupted", err)
	}
	if strings.Contains(fmt.Sprintf("%#v", *r.PrivacyExport), string(c.Binding.UserID)) {
		t.Fatal("receipt disclosed scope")
	}
	r.PrivacyExport.ExpectedPrivacyEpoch = math.MaxUint64
	if r.Validate() == nil {
		t.Fatal("privacy epoch overflow accepted")
	}
}

func TestPrivacyReceiptNilJSONPreservesPreviousFields(t *testing.T) {
	// Use the old field set to independently encode bytes; the new nil member
	// must not insert a null into retained historical command JSON.
	r := CommandResult{Binding: CommandBinding{OperationID: "identity.user.create"}, Outcome: CommitOutcomeUnknown}
	old := struct {
		Binding         CommandBinding
		Outcome         CommitOutcome
		User            User
		AuditEventID    string
		RetryAfter      time.Duration
		ExpectedVersion uint64
		Profile         *UserProfile
		Revocation      *RevocationOutcome
		Unlink          *AccountUnlinkReceipt
		Link            *AccountLinkReceipt
		Identifier      *IdentifierReceipt
		Feature         *FeatureReceipt `json:",omitempty"`
	}{Binding: r.Binding, Outcome: r.Outcome}
	want, _ := json.Marshal(old)
	got, err := json.Marshal(r)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("old receipt JSON changed", err)
	}
}
