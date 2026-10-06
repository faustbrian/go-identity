package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
)

// LifecycleContributor is the open outbox-owned same-Work lifecycle phase.
// Only the Coordinator invokes it after complete staging. Implementations
// persist these safe events atomically with the mutation, preserve deterministic
// IDs and reject different bytes under an existing ID. They must not retain
// Work, close or begin transactions, invoke caller hooks or perform network I/O.
// Success means staging, not commit or downstream consumer acknowledgement.
type LifecycleContributor interface {
	Contributor
	PersistLifecycle(context.Context, Work) error
}

// LifecyclePlan declares the single current kernel lifecycle event before SQL.
// EventType is the exact supported command mapping, not caller-selected text.
// Versions describe one aggregate transition; AfterVersion must be the checked
// successor. User creation and identifier attachment start at 0. Account
// linking starts at 0 only for a never-used ID; a relink preserves its current
// tombstone version. Every other operation starts above 0.
// The full cascade consumer/checkpoint profile is separate and still pending.
type LifecyclePlan struct {
	EventType     string
	EventIndex    uint16
	BeforeVersion uint64
	AfterVersion  uint64
}

// StagedLifecycle is an owned, scalar-only safe outbox record. It intentionally
// cannot carry attributes, identifier values, tokens or arbitrary payloads.
// ID is deterministic from command ID, lifecycle class and index; event bytes
// also bind tenant, subject, operation, version transition and occurrence time.
// This projection does not imply a completed cascade or external effect.
type StagedLifecycle struct {
	ID            string
	CommandID     identity.CommandID
	TenantID      identity.TenantID
	UserID        identity.UserID
	OperationID   string
	EventType     string
	EventIndex    uint16
	SubjectType   string
	SubjectID     string
	BeforeVersion uint64
	AfterVersion  uint64
	OccurredAt    time.Time
}

type workLifecycle struct {
	plan   LifecyclePlan
	record *StagedLifecycle
}

func validateLifecyclePlan(binding identity.CommandBinding, plan *LifecyclePlan) error {
	if plan == nil {
		return nil
	}
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	creating := binding.OperationID == "identity.user.create" || binding.OperationID == "identity.identifier.attach"
	wrongInitialVersion := creating && plan.BeforeVersion != 0 || !creating && binding.OperationID != "identity.account.link-token" && plan.BeforeVersion == 0
	if probe.Validate() != nil || plan.EventType == "" || plan.EventType != kernelLifecycleEvent(binding.OperationID) || plan.BeforeVersion == ^uint64(0) || plan.AfterVersion != plan.BeforeVersion+1 || wrongInitialVersion {
		return invalidLifecycle()
	}
	return nil
}

func bindLifecyclePlan(w Work, plan *LifecyclePlan) error {
	if err := w.usable(); err != nil {
		return err
	}
	valid := plan != nil
	if valid && w.state.feature == nil {
		valid = validateLifecyclePlan(w.state.binding, plan) == nil
	} else if valid {
		valid = featureEventName(plan.EventType) && auditName(w.state.subjectType)
		if w.state.feature.Operation.RecordRequirement == identity.FeatureRecordRequired {
			valid = valid && plan.BeforeVersion != ^uint64(0) && plan.AfterVersion == plan.BeforeVersion+1
		} else {
			valid = valid && plan.BeforeVersion == 0 && plan.AfterVersion == 0
		}
	}
	if w.state.lifecycle != nil || w.state.sqlStarted || !valid {
		return invalidLifecycle()
	}
	w.state.lifecycle = &workLifecycle{plan: *plan}
	return nil
}

// StageLifecycle materializes the predeclared event without accepting an
// arbitrary payload. OccurredAt must be the primary UTC instant obtained by
// the trusted adapter through Work.DatabaseTime, microsecond-exact and within
// PostgreSQL years 1..9999. It is not a caller clock/freshness proof. Work does
// not perform I/O or independently check its provenance during staging.
// Undeclared, duplicate or invalid staging poisons Work. Closed, expired or
// failed Work cannot stage. This does not persist or acknowledge delivery.
func (w Work) StageLifecycle(index uint16, occurredAt time.Time) error {
	if err := w.usable(); err != nil {
		return err
	}
	l := w.state.lifecycle
	if l == nil || l.record != nil || index != l.plan.EventIndex || !postgresExactTime(occurredAt) || occurredAt.Location() != time.UTC {
		return w.fail(w.state.ctx, invalidLifecycle())
	}
	b := w.state.binding
	kind, target := "user", string(b.UserID)
	if w.state.feature != nil {
		kind = w.state.subjectType
		target = featureTargetID(b)
	} else if b.RecordID != "" {
		target = b.RecordID
		switch kernelCommandAudit(b.OperationID) {
		case "identity.account.link", "identity.account.unlink":
			kind = "account"
		case "identity.identifier.add", "identity.identifier.change", "identity.identifier.remove":
			kind = "identifier"
		case "identity.identifier.verify":
			kind = "identifier"
		default:
			return w.fail(w.state.ctx, invalidLifecycle())
		}
	}
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(uint64(index))}))
	l.record = &StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, OperationID: b.OperationID, EventType: l.plan.EventType, EventIndex: index, SubjectType: kind, SubjectID: target, BeforeVersion: l.plan.BeforeVersion, AfterVersion: l.plan.AfterVersion, OccurredAt: occurredAt}
	return nil
}

// StagedLifecycle returns one owned record only after the declared event was
// staged and its successful audit agrees on the exact aggregate and versions.
// Conflicting audit evidence poisons Work; denial/failure cannot produce a
// success lifecycle notification. Missing or invalid Work returns no records.
// The outbox contributor
// must persist it through this same Work before successful terminalization.
func (w Work) StagedLifecycle() ([]StagedLifecycle, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	if w.state.lifecycle == nil || w.state.lifecycle.record == nil {
		return nil, invalidLifecycle()
	}
	if err := completeAudits(w); err != nil {
		return nil, err
	}
	r := w.state.lifecycle.record
	for _, record := range w.state.audits.records {
		attributes := record.Attributes()
		if record.Outcome() != audit.OutcomeSucceeded || record.Subject().Type() != r.SubjectType || record.Subject().ID() != r.SubjectID || attributes["aggregate.before_version"] != strconv.FormatUint(r.BeforeVersion, 10) || attributes["aggregate.after_version"] != strconv.FormatUint(r.AfterVersion, 10) {
			return nil, w.fail(w.state.ctx, invalidLifecycle())
		}
	}
	return []StagedLifecycle{*w.state.lifecycle.record}, nil
}

func kernelLifecycleEvent(operation string) string {
	switch kernelCommandAudit(operation) {
	case "identity.user.create":
		return "identity.created.v1"
	case "identity.user.update":
		return "identity.updated.v1"
	case "identity.user.suspend":
		return "identity.suspended.v1"
	case "identity.user.restore":
		return "identity.restored.v1"
	case "identity.user.delete":
		return "identity.deletion_requested.v1"
	case "identity.account.link":
		return "social_provider.linked.v1"
	case "identity.account.unlink":
		return "social_provider.unlinked.v1"
	case "identity.identifier.add":
		return "identifier.added.v1"
	case "identity.identifier.change":
		return "identifier.changed.v1"
	case "identity.identifier.remove":
		return "identifier.removed.v1"
	case "identity.identifier.verify":
		return "identifier.verified.v1"
	}
	return ""
}

func invalidLifecycle() error { return identity.InvalidInputError{Field: "lifecycle_event"} }
