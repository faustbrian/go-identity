package identity

import "github.com/faustbrian/go-authorization/v3"

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

// FeatureSubjectRequirement fixes an operation's target identity namespace at
// trusted composition. The default preserves existing user-targeted schemas.
// Anonymous-flow targeting is explicit and never substitutes a flow for UserID.
// This does not authenticate a flow or grant execution/recovery authority.
type FeatureSubjectRequirement uint8

const (
	// FeatureSubjectUser requires UserID and forbids AnonymousFlowID.
	FeatureSubjectUser FeatureSubjectRequirement = iota
	// FeatureSubjectAnonymousFlow requires AnonymousFlowID and an empty UserID.
	// The actor remains a separately verified user, API key or service account.
	FeatureSubjectAnonymousFlow
)

// FeatureVersionPolicy fixes a record's version transition at trusted schema
// composition. It is not selected by request data or a stored source snapshot.
type FeatureVersionPolicy uint8

const (
	// FeatureVersionSequential preserves creation at 0 -> 1 and one-step updates.
	FeatureVersionSequential FeatureVersionPolicy = iota
	// FeatureVersionSnapshotImport preserves a positive source version only
	// when no local record exists. The native owner must fence that absence;
	// this policy cannot perform an update or establish source authority.
	FeatureVersionSnapshotImport
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
	// SubjectRequirement is frozen schema policy, not selected by request data.
	// Zero retains the original user-only contract and serialized shape.
	SubjectRequirement FeatureSubjectRequirement `json:",omitempty"`
	// VersionPolicy defaults to the existing sequential contract and omitted
	// serialized shape. Snapshot import requires a record-targeted operation.
	VersionPolicy FeatureVersionPolicy `json:",omitempty"`
}

// Validate checks structural descriptor identity, not ownership authenticity.
// The owning feature adapter must validate its full typed command and selected
// policy; the coordinator must match the exact immutable registered descriptor
// before admission. Names alone never enable an execution phase. Invalid input
// returns a redacted InvalidInputError; zero is invalid.
func (d FeatureOperation) Validate() error {
	if !validFeatureName(d.Owner, '/') || d.Owner == "identity" || !validFeatureName(d.OperationID, '.') || kernelOperationID(d.OperationID) || !validDirectoryID(d.SchemaID) || d.SchemaVersion == 0 || (d.RecordRequirement != FeatureRecordOmitted && d.RecordRequirement != FeatureRecordRequired) || d.SubjectRequirement > FeatureSubjectAnonymousFlow || d.VersionPolicy > FeatureVersionSnapshotImport || d.VersionPolicy == FeatureVersionSnapshotImport && d.RecordRequirement != FeatureRecordRequired {
		return InvalidInputError{Field: "feature_operation"}
	}
	return nil
}

// ValidateRecordVersions checks the selected structural transition, not a
// commit, existing record, authentication or import authority. Native owners
// must bind the exact descriptor and fence actual prior state in the mutation.
// Sequential declarations retain their existing overflow rule. Snapshot import
// admits only absent-local 0 -> positive source versions, including full width;
// it never permits overwriting an existing record or resetting a version.
func (d FeatureOperation) ValidateRecordVersions(before, after uint64) error {
	if err := d.Validate(); err != nil {
		return err
	}
	valid := before == 0 && after == 0
	if d.RecordRequirement == FeatureRecordRequired {
		if d.VersionPolicy == FeatureVersionSnapshotImport {
			valid = before == 0 && after > 0
		} else {
			valid = before < ^uint64(0) && after == before+1
		}
	}
	if !valid {
		return InvalidInputError{Field: "feature_record_versions"}
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
	if d.Validate() != nil || !validID || !validDirectoryID(string(b.TenantID)) || !validFeatureSubject(b, d) || !validDirectoryID(string(b.ActorID)) || !featureActorKind(b.ActorKind) || b.OperationID != d.OperationID || !validDirectoryID(b.PolicyID) || b.PolicyVersion == 0 || b.SchemaID != d.SchemaID || b.SchemaVersion != d.SchemaVersion || !validDirectoryID(b.CorrelationID) || b.LinkMode != 0 || (d.RecordRequirement == FeatureRecordOmitted && b.RecordID != "") || (d.RecordRequirement == FeatureRecordRequired && !validDirectoryID(b.RecordID)) {
		return InvalidInputError{Field: "feature_command_binding"}
	}
	return nil
}

func validFeatureSubject(b CommandBinding, d FeatureOperation) bool {
	if d.SubjectRequirement == FeatureSubjectAnonymousFlow {
		return b.UserID == "" && validDirectoryID(b.AnonymousFlowID)
	}
	return b.AnonymousFlowID == "" && validDirectoryID(string(b.UserID))
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
	return op == "identity.user.create" || op == "identity.user.update-admin" || op == "identity.profile.update" || op == "identity.account.unlink" || op == "identity.account.link-token" || op == privacyExportRequestOperation || statusTarget(op).Valid() || identifierAction(op) != 0
}
