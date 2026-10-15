package identity

import "time"

// FeatureReceipt is a storage-neutral safe primary-record receipt, never a
// feature-native response or authentication proof. Operation retains the exact
// trusted descriptor on every outcome. A committed record-target operation has
// AfterVersion == BeforeVersion+1 without overflow; creation starts at 0 -> 1.
// Record-free operations and every noncommitted outcome keep both versions zero.
// The target ID is CommandResult.Binding.RecordID, not an alternate locator.
// Feature owners validate their native result and complete command schema;
// this shared vocabulary carries no arbitrary payload, bearer or secret.
// Public fields permit trusted durable reconstruction; zero is invalid through
// CommandResult.Validate. Callers must not mutate a receipt concurrently.
// Structural validation does not confirm a commit, grant current authority or
// enable coordinator execution; only the owning durable outcome establishes it.
type FeatureReceipt struct {
	Operation     FeatureOperation
	BeforeVersion uint64
	AfterVersion  uint64
}

func validFeatureResult(r CommandResult) bool {
	f := *r.Feature
	if r.Binding.ValidateFor(f.Operation) != nil || r.User != (User{}) || r.ExpectedVersion != 0 || r.Profile != nil || r.Revocation != nil || r.Unlink != nil || r.Link != nil || r.Identifier != nil || r.PrivacyExport != nil {
		return false
	}
	removal := f.Operation == (FeatureOperation{Owner: "identity/email", OperationID: "identity.email.address-remove", SchemaID: "identity.email.address-remove.native-v1", SchemaVersion: 1, RecordRequirement: FeatureRecordRequired})
	if r.Cascade != nil && (!removal || r.Outcome != CommitOutcomeCommitted || r.Cascade.Validate(r.Binding) != nil) || removal && r.Outcome == CommitOutcomeCommitted && r.Cascade == nil {
		return false
	}
	switch r.Outcome {
	case CommitOutcomeCommitted:
		if r.RetryAfter != 0 || !validDirectoryID(r.AuditEventID) {
			return false
		}
		if f.Operation.RecordRequirement == FeatureRecordRequired {
			return f.BeforeVersion < ^uint64(0) && f.AfterVersion == f.BeforeVersion+1
		}
		return f.BeforeVersion == 0 && f.AfterVersion == 0
	case CommitOutcomeNotCommitted, CommitOutcomeUnknown, CommitOutcomeConflict:
		return f.BeforeVersion == 0 && f.AfterVersion == 0 && r.AuditEventID == "" && r.RetryAfter == 0
	case CommitOutcomeInProgress:
		return f.BeforeVersion == 0 && f.AfterVersion == 0 && r.AuditEventID == "" && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		return false
	}
}
