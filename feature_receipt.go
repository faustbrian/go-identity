package identity

import "time"

// FeatureReceipt is a storage-neutral safe primary-record receipt, never a
// feature-native response or authentication proof. Operation retains the exact
// trusted descriptor on every outcome. Sequential record-target operations have
// AfterVersion == BeforeVersion+1 without overflow; creation starts at 0 -> 1.
// Explicit snapshot imports instead preserve a positive source version from
// absent-local BeforeVersion zero. This never authorizes overwriting a record.
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
	cascadeOperation := identifierLifecycleFeatureOperation(f.Operation.OperationID)
	if f.Operation.OperationID == "identity.phone.update" && f.Operation != cascadeOperation {
		return false
	}
	requiresCascade := cascadeOperation.Owner != "" && f.Operation == cascadeOperation
	if r.Cascade != nil && (!requiresCascade || r.Outcome != CommitOutcomeCommitted || r.Cascade.Validate(r.Binding) != nil) || requiresCascade && r.Outcome == CommitOutcomeCommitted && r.Cascade == nil {
		return false
	}
	switch r.Outcome {
	case CommitOutcomeCommitted:
		if r.RetryAfter != 0 || !validDirectoryID(r.AuditEventID) {
			return false
		}
		return f.Operation.ValidateRecordVersions(f.BeforeVersion, f.AfterVersion) == nil
	case CommitOutcomeNotCommitted, CommitOutcomeUnknown, CommitOutcomeConflict:
		return f.BeforeVersion == 0 && f.AfterVersion == 0 && r.AuditEventID == "" && r.RetryAfter == 0
	case CommitOutcomeInProgress:
		return f.BeforeVersion == 0 && f.AfterVersion == 0 && r.AuditEventID == "" && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		return false
	}
}
