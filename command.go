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
	create  *CreateUserCommand
	update  *UpdateUserCommand
	profile *ProfileUpdateCommand
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
	if c.create == nil || c.update != nil || c.profile != nil {
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
}

// RecoveryQuery scopes a primary-authority lookup to the original command,
// tenant, target and actor. A command ID alone never permits public lookup.
// No fields, alternate command IDs, callbacks or transaction handles are accepted.
type RecoveryQuery struct {
	CommandID CommandID
	TenantID  TenantID
	UserID    UserID
	ActorID   ActorID
	ActorKind authorization.SubjectKind
}

func validCommandBinding(b CommandBinding) bool {
	_, validID := decodeID(string(b.CommandID))
	return validID && validDirectoryID(string(b.TenantID)) && validDirectoryID(string(b.UserID)) && validDirectoryID(string(b.ActorID)) && (b.ActorKind == authorization.SubjectUser || b.ActorKind == authorization.SubjectAPIKey || b.ActorKind == authorization.SubjectServiceAccount) && (b.OperationID == "identity.user.create" || b.OperationID == "identity.user.update-admin" || b.OperationID == "identity.profile.update") && validDirectoryID(b.PolicyID) && b.PolicyVersion > 0 && validDirectoryID(b.SchemaID) && b.SchemaVersion > 0 && validDirectoryID(b.CorrelationID)
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
		return r.Profile == nil && r.ExpectedVersion == 0 && r.User == (User{}) && r.AuditEventID == "" && r.RetryAfter == 0
	case CommitOutcomeInProgress:
		return r.Profile == nil && r.ExpectedVersion == 0 && r.User == (User{}) && r.AuditEventID == "" && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		return false
	}
}
