package identity

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization"
)

// CommandID is a canonical nonzero random 128-bit command identity. It is not
// derived from user data; preserve it across retries, including unknown outcomes.
// Possession grants no identity or database authority. Empty is invalid.
type CommandID string

var (
	// ErrInvalidCommandID identifies noncanonical command IDs without input.
	ErrInvalidCommandID = errors.New("identity: invalid command ID")
	// ErrCommandIDEntropy identifies generation failure without provider details.
	ErrCommandIDEntropy = errors.New("identity: command ID entropy unavailable")
)

// NewCommandID reads exactly 16 crypto/rand bytes and rejects all-zero entropy.
func NewCommandID() (CommandID, error) {
	id, err := newID(rand.Reader, ErrCommandIDEntropy)
	return CommandID(id), err
}

// ParseCommandID reconstructs only the canonical 22-byte unpadded base64url form.
func ParseCommandID(raw string) (CommandID, error) {
	if _, ok := decodeID(raw); !ok {
		return "", ErrInvalidCommandID
	}
	return CommandID(raw), nil
}

// CommitOutcome is the sole closed durable-command observation. Cancellation,
// panic, transport failure or a lease timeout is not evidence of rollback.
type CommitOutcome uint8

const (
	CommitOutcomeInvalid CommitOutcome = iota
	CommitOutcomeNotCommitted
	CommitOutcomeCommitted
	CommitOutcomeUnknown
	CommitOutcomeConflict
	CommitOutcomeInProgress
)

// CommandBinding is an immutable logical command scope, not an authority proof.
// Positive policy/schema versions and canonical safe IDs are mandatory. Actor
// kind is the exact upstream kind, not a caller role or administrator flag.
// CorrelationID is safe correlation only; it grants no continuation authority.
type CommandBinding struct {
	CommandID     CommandID
	TenantID      TenantID
	UserID        UserID
	ActorID       ActorID
	ActorKind     authorization.SubjectKind
	OperationID   string
	PolicyID      string
	PolicyVersion uint64
	SchemaID      string
	SchemaVersion uint32
	CorrelationID string
	// RecordID is the exact account/identifier target for kernel record commands,
	// including every noncommitted receipt; other kernel operations omit it.
	// Feature bindings follow their FeatureOperation.RecordRequirement instead.
	RecordID string
	// LinkMode is required only for account-link commands, for every outcome.
	LinkMode AccountLinkMode
}

// CreateUserCommand contains one prepared initial creation. Initial status is
// active; other lifecycle states require their own versioned lifecycle command.
// Attributes are not authority and must never contain credentials. Configure
// or construct values without concurrent mutation; Command freezes a deep copy.
type CreateUserCommand struct {
	Binding    CommandBinding
	Status     Status
	Attributes []AttributeUpdate
}

// Command is a closed immutable storage-neutral mutation. Its zero value is
// invalid. It exposes no transactions, arbitrary callbacks or participants.
// Formatting is always redacted and JSON serialization is forbidden. Adapter
// mapping uses the typed accessor, never reflection or command JSON. The adapter
// owns versioned keyed canonical fingerprints, reservations and durable replay.
type Command struct {
	create     *CreateUserCommand
	update     *UpdateUserCommand
	profile    *ProfileUpdateCommand
	status     *UserStatusCommand
	unlink     *AccountUnlinkCommand
	link       *AccountLinkCommand
	identifier *IdentifierCommand
}

// NewUserCreationCommand validates and snapshots a creation's structural input.
// It does NOT authorize, canonicalize directory IDs or validate a field schema.
// Trusted composition uses UserCreationService before crossing UnitOfWork.
func NewUserCreationCommand(spec CreateUserCommand) (Command, error) {
	if !validCommandBinding(spec.Binding) || spec.Binding.OperationID != "identity.user.create" || spec.Status != StatusActive || len(spec.Attributes) > 128 {
		return Command{}, InvalidInputError{Field: "creation_command"}
	}
	total := 0
	for i, update := range spec.Attributes {
		if !validFieldName(update.Name) || reservedFieldName(update.Name) {
			return Command{}, InvalidInputError{Field: "creation_command"}
		}
		for _, previous := range spec.Attributes[:i] {
			if previous.Name == update.Name {
				return Command{}, InvalidInputError{Field: "creation_command"}
			}
		}
		n, ok := attributeSize(update.Value, update.Value.Kind)
		if !ok || n > attributeBudget-total {
			return Command{}, InvalidInputError{Field: "creation_command"}
		}
		total += n
	}
	spec.Attributes = cloneUpdates(spec.Attributes)
	return Command{create: &spec}, nil
}

// CreateUser returns a private copy and false for an invalid/zero command.
// Returned contents are for trusted adapters, never diagnostics or snapshots.
func (c Command) CreateUser() (CreateUserCommand, bool) {
	if c.create == nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.identifier != nil {
		return CreateUserCommand{}, false
	}
	spec := *c.create
	spec.Attributes = cloneUpdates(spec.Attributes)
	return spec, true
}

// Format prevents payload exposure for all fmt verbs, including %#v and %x.
func (Command) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "identity.Command(redacted)")
}

// MarshalJSON rejects implicit command persistence or accidental HTTP exposure.
func (Command) MarshalJSON() ([]byte, error) {
	return nil, errors.New("identity: command serialization forbidden")
}

// CommandResult is the adapter's authoritative redacted receipt, not current
// user authority. A committed creation returns its immutable initial version-1
// user and stable audit event ID. Other outcomes carry neither user nor audit ID.
// InProgress carries a positive retry delay up to one minute; all others zero.
type CommandResult struct {
	Binding      CommandBinding
	Outcome      CommitOutcome
	User         User
	AuditEventID string
	RetryAfter   time.Duration
	// ExpectedVersion is present only on a committed update receipt; the
	// immutable result must be exactly one greater. Creation keeps it zero.
	ExpectedVersion uint64
	// Profile exists only for a committed self-service profile command. Adapters
	// retain immutable copies; callers must never mutate a receipt concurrently.
	Profile *UserProfile
	// Revocation is present only on a committed status admission. It records
	// pending cleanup, never fabricated asynchronous completion.
	Revocation *RevocationOutcome
	// Unlink is present only for a committed account unlink, never external
	// provider completion. Treat retained receipts as immutable snapshots.
	Unlink *AccountUnlinkReceipt
	// Link is present only for committed identity-owned account link admission.
	Link *AccountLinkReceipt
	// Identifier is present only on a committed identifier mutation.
	Identifier *IdentifierReceipt
}

// Validate checks the closed receipt shape, immutable operation binding,
// version relationships and outcome-specific payload without authorization or
// current-state I/O. It returns a redacted InvalidInputError for invalid values.
// The zero value is invalid. Callers must not mutate a receipt concurrently.
func (r CommandResult) Validate() error {
	if !r.valid() {
		return InvalidInputError{Field: "command_result"}
	}
	return nil
}

// RecoveryQuery scopes a primary-authority lookup to the original command,
// tenant, target, actor, operation and exact record/link mode for all outcomes.
// The owner must match every field against immutable command scope before
// returning any outcome, including conflict, not-committed and in-progress.
// Non-record operations omit RecordID/LinkMode. A command ID alone never permits public lookup.
// No fields, alternate command IDs, callbacks or transaction handles are accepted.
type RecoveryQuery struct {
	CommandID   CommandID
	TenantID    TenantID
	UserID      UserID
	ActorID     ActorID
	ActorKind   authorization.SubjectKind
	OperationID string
	RecordID    string
	LinkMode    AccountLinkMode
}

func validCommandBinding(b CommandBinding) bool {
	if !validCommandRecordBinding(b) {
		return false
	}
	_, validID := decodeID(string(b.CommandID))
	return validID && validDirectoryID(string(b.TenantID)) && validDirectoryID(string(b.UserID)) && validDirectoryID(string(b.ActorID)) && (b.ActorKind == authorization.SubjectUser || b.ActorKind == authorization.SubjectAPIKey || b.ActorKind == authorization.SubjectServiceAccount) && kernelOperationID(b.OperationID) && validDirectoryID(b.PolicyID) && b.PolicyVersion > 0 && validDirectoryID(b.SchemaID) && b.SchemaVersion > 0 && validDirectoryID(b.CorrelationID)
}

func validCommandRecordBinding(b CommandBinding) bool {
	if b.OperationID == "identity.account.link-token" {
		return validDirectoryID(b.RecordID) && b.LinkMode >= AccountLinkExplicit && b.LinkMode <= AccountLinkAdministrative
	}
	if b.OperationID == "identity.account.unlink" || identifierAction(b.OperationID) != 0 {
		return validDirectoryID(b.RecordID) && b.LinkMode == 0
	}
	return b.RecordID == "" && b.LinkMode == 0
}

func cloneUpdates(updates []AttributeUpdate) []AttributeUpdate {
	updates = slices.Clone(updates)
	for i := range updates {
		updates[i].Value = cloneAttribute(updates[i].Value)
	}
	return updates
}

func (r CommandResult) valid() bool {
	if !validCommandBinding(r.Binding) {
		return false
	}
	switch r.Outcome {
	case CommitOutcomeCommitted:
		if r.RetryAfter != 0 || r.User.Validate(r.Binding.TenantID) != nil || r.User.ID != r.Binding.UserID || !validDirectoryID(r.AuditEventID) {
			return false
		}
		if action := identifierAction(r.Binding.OperationID); action != 0 {
			return r.Profile == nil && r.Revocation == nil && r.Unlink == nil && r.Link == nil && r.Identifier != nil && r.Identifier.valid() && r.Identifier.Action == action && string(r.Identifier.IdentifierID) == r.Binding.RecordID && r.User.Status == StatusActive && r.Binding.ActorKind == authorization.SubjectUser && string(r.Binding.ActorID) == string(r.User.ID) && unlinkVersion(r.ExpectedVersion) && r.User.Version == r.ExpectedVersion+1
		}
		if r.Identifier != nil {
			return false
		}
		if r.Binding.OperationID == "identity.account.unlink" {
			return r.Link == nil && r.Profile == nil && r.Revocation == nil && r.Unlink != nil && r.Unlink.valid() && string(r.Unlink.AccountID) == r.Binding.RecordID && r.User.Status == StatusActive && r.Binding.ActorKind == authorization.SubjectUser && string(r.Binding.ActorID) == string(r.User.ID) && unlinkVersion(r.ExpectedVersion) && r.User.Version == r.ExpectedVersion+1
		}
		if r.Binding.OperationID == "identity.account.link-token" {
			return r.Unlink == nil && r.Profile == nil && r.Revocation == nil && r.Link != nil && r.Link.valid() && string(r.Link.AccountID) == r.Binding.RecordID && r.Link.Mode == r.Binding.LinkMode && r.User.Status == StatusActive && validLinkActor(r.Link.Mode, r.Binding.ActorKind, r.Binding.ActorID, r.User.ID) && unlinkVersion(r.ExpectedVersion) && r.User.Version == r.ExpectedVersion+1
		}
		if r.Unlink != nil || r.Link != nil {
			return false
		}
		if target := statusTarget(r.Binding.OperationID); target.Valid() {
			return r.Profile == nil && r.Revocation != nil && r.Revocation.validAdmission(r.Binding.OperationID) && r.User.Status == target && r.ExpectedVersion > 0 && r.ExpectedVersion < ^uint64(0) && r.User.Version == r.ExpectedVersion+1
		}
		if r.Revocation != nil {
			return false
		}
		if r.Binding.OperationID == "identity.user.create" {
			return r.Profile == nil && r.ExpectedVersion == 0 && r.User.Status == StatusActive && r.User.Version == 1
		}
		if r.Binding.OperationID == "identity.profile.update" {
			return r.Profile != nil && validProfile(*r.Profile) && r.Profile.ID == r.User.ID && r.Profile.TenantID == r.User.TenantID && r.Profile.Version == r.User.Version && r.User.Status == StatusActive && r.Binding.ActorKind == authorization.SubjectUser && string(r.Binding.ActorID) == string(r.User.ID) && r.ExpectedVersion > 0 && r.ExpectedVersion < ^uint64(0) && r.User.Version == r.ExpectedVersion+1
		}
		if r.Profile != nil {
			return false
		}
		return r.ExpectedVersion > 0 && r.ExpectedVersion < ^uint64(0) && r.User.Version == r.ExpectedVersion+1 && r.User.Status != StatusDeleted && r.User.Status != StatusAnonymized
	case CommitOutcomeNotCommitted, CommitOutcomeUnknown, CommitOutcomeConflict:
		return r.Identifier == nil && r.Link == nil && r.Unlink == nil && r.Revocation == nil && r.Profile == nil && r.ExpectedVersion == 0 && r.User == (User{}) && r.AuditEventID == "" && r.RetryAfter == 0
	case CommitOutcomeInProgress:
		return r.Identifier == nil && r.Link == nil && r.Unlink == nil && r.Revocation == nil && r.Profile == nil && r.ExpectedVersion == 0 && r.User == (User{}) && r.AuditEventID == "" && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		return false
	}
}
