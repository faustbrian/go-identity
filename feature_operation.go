package identity

import "github.com/faustbrian/go-authorization"

// FeatureRecordRequirement fixes whether an operation has one exact record
// target. It is a schema decision, not inferred from submitted input. Zero and
// unknown values are invalid; feature operations never borrow account LinkMode.
type FeatureRecordRequirement uint8

const (
	// FeatureRecordOmitted requires an empty CommandBinding.RecordID.
	FeatureRecordOmitted FeatureRecordRequirement = iota + 1
	// FeatureRecordRequired requires a valid exact CommandBinding.RecordID.
	FeatureRecordRequired
)

// FeatureOperation identifies one storage-neutral feature-owned operation.
// Trusted composition supplies a compile-time descriptor, never request data.
// Owner is a canonical lowercase slash-separated module label; OperationID is
// a lowercase dot-separated operation name (each segment starts with a letter,
// ends with a letter/digit and otherwise allows letters, digits and hyphens).
// Both are bounded to 128 bytes. SchemaID follows existing safe directory-ID
// rules; SchemaVersion is positive. The record requirement is explicit.
// Descriptors are scalar values: freeze them at composition and do not mutate
// one concurrently with validation. Validation performs no I/O, registration,
// authorization or command execution. Kernel-owned operations are excluded.
type FeatureOperation struct {
	Owner             string
	OperationID       string
	SchemaID          string
	SchemaVersion     uint32
	RecordRequirement FeatureRecordRequirement
}

// Validate checks structural descriptor identity, not ownership authenticity.
// The owning feature adapter must validate its full typed command and selected
// policy; the coordinator must match the exact immutable registered descriptor
// before admission. Names alone never enable an execution phase. Invalid input
// returns a redacted InvalidInputError; zero is invalid.
func (d FeatureOperation) Validate() error {
	if !validFeatureName(d.Owner, '/') || d.Owner == "identity" || !validFeatureName(d.OperationID, '.') || kernelOperationID(d.OperationID) || !validDirectoryID(d.SchemaID) || d.SchemaVersion == 0 || (d.RecordRequirement != FeatureRecordOmitted && d.RecordRequirement != FeatureRecordRequired) {
		return InvalidInputError{Field: "feature_operation"}
	}
	return nil
}

// ValidateFor checks every common scope field against one exact feature schema.
// It preserves canonical command identity, safe directory IDs, actual upstream
// actor kinds and positive policy versions. Required targets cannot be omitted;
// record-free operations cannot carry one. LinkMode must be zero. Descriptor
// ownership and policy must come from trusted composition, not this input.
// This is structural validation, not authentication, authorization, current
// authority, registration, a fingerprint or a transaction. Existing kernel
// Kernel Command constructors and kernel receipts remain separate closed
// variants. Feature receipts require their explicit Feature branch. Zero is invalid;
// invalid input returns redacted InvalidInputError. No I/O or callbacks run.
func (b CommandBinding) ValidateFor(d FeatureOperation) error {
	_, validID := decodeID(string(b.CommandID))
	if d.Validate() != nil || !validID || !validDirectoryID(string(b.TenantID)) || !validDirectoryID(string(b.UserID)) || !validDirectoryID(string(b.ActorID)) || !featureActorKind(b.ActorKind) || b.OperationID != d.OperationID || !validDirectoryID(b.PolicyID) || b.PolicyVersion == 0 || b.SchemaID != d.SchemaID || b.SchemaVersion != d.SchemaVersion || !validDirectoryID(b.CorrelationID) || b.LinkMode != 0 || (d.RecordRequirement == FeatureRecordOmitted && b.RecordID != "") || (d.RecordRequirement == FeatureRecordRequired && !validDirectoryID(b.RecordID)) {
		return InvalidInputError{Field: "feature_command_binding"}
	}
	return nil
}

func featureActorKind(kind authorization.SubjectKind) bool {
	return kind == authorization.SubjectUser || kind == authorization.SubjectAPIKey || kind == authorization.SubjectServiceAccount
}

func validFeatureName(s string, separator byte) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	start := true
	for i := range len(s) {
		b := s[i]
		if b == separator {
			if start || i == 0 || s[i-1] == '-' {
				return false
			}
			start = true
			continue
		}
		if start {
			if b < 'a' || b > 'z' {
				return false
			}
			start = false
		} else if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return !start && s[len(s)-1] != '-'
}

func kernelOperationID(op string) bool {
	return op == "identity.user.create" || op == "identity.user.update-admin" || op == "identity.profile.update" || op == "identity.account.unlink" || op == "identity.account.link-token" || statusTarget(op).Valid() || identifierAction(op) != 0
}
