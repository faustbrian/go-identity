package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// AuditPlan declares one required security event slot before SQL execution.
// Values are copied by the coordinator, never changed in flight. SchemaVersion
// is the audit canonical schema (currently 1), not the command schema. Each
// index requires exactly one record; indices increase strictly, at most 64.
// Byte bounds may lower but never exceed the 16 KiB identity security profile.
// RetentionPolicyVersion is the exact durable policy selected at admission;
// staging does not read or mutate retention policy. Zero and Required=false
// are invalid. This declaration alone grants no persistence authority.
type AuditPlan struct {
	EventType              string
	SchemaVersion          uint32
	EventIndex             uint16
	BindingDigest          [32]byte
	RetentionPolicyVersion uint64
	RequiredRecordCount    uint16
	MaxRecordBytes         uint32
	MaxAggregateBytes      uint32
	Required               bool
}

type workAudits struct {
	plans   []AuditPlan
	records []audit.Record
	staged  []bool
	ids     map[string]struct{}
	bytes   int
}

func securityAuditLimits() audit.Limits {
	return audit.Limits{MaxRecordBytes: 16384, MaxFieldBytes: 256, MaxDescriptionBytes: 1, MaxAttributeEntries: 32, MaxAttributeBytes: 8192, MaxChangeEntries: 32, MaxChangeBytes: 8192, MaxIntegrityBytes: 32}
}

// AuditBindingDigest computes the domain-separated deterministic binding of a
// kernel event to the exact core command, actor and target. It includes neither
// event ID nor outcome: Builder owns random IDs, and success/denial/failure is
// selected at execution. It is correlation, not authentication or redaction
// evidence. Invalid/mismatched scopes return redacted InvalidInputError.
// The current kernel profile accepts redacted/no-change records only; broader
// feature profiles and typed event construction remain under development.
func AuditBindingDigest(binding identity.CommandBinding, record audit.Record) ([32]byte, error) {
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Microsecond}
	attrs := record.Attributes()
	actor := record.Actor()
	if probe.Validate() != nil || record.Context().TenantID() != string(binding.TenantID) || record.Context().CorrelationID() != binding.CorrelationID || attrs["command.id"] != string(binding.CommandID) || record.Policy().PolicyID != binding.PolicyID || record.Policy().Version != strconv.FormatUint(binding.PolicyVersion, 10) || actor.ID() != string(binding.ActorID) || actor.DelegatedBy() != (audit.Actor{}) {
		return [32]byte{}, invalidAudit()
	}
	if binding.ActorKind == authorization.SubjectUser && actor.Kind() != audit.ActorHuman || binding.ActorKind == authorization.SubjectServiceAccount && actor.Kind() != audit.ActorService || binding.ActorKind != authorization.SubjectUser && binding.ActorKind != authorization.SubjectServiceAccount {
		return [32]byte{}, invalidAudit()
	}
	if !auditSafeID(record.Subject().ID()) || !auditName(record.Subject().Type()) {
		return [32]byte{}, invalidAudit()
	}
	target, kind := string(binding.UserID), "user"
	if binding.RecordID != "" {
		target = binding.RecordID
		if strings.HasPrefix(binding.OperationID, "identity.account.") {
			kind = "account"
		} else if strings.HasPrefix(binding.OperationID, "identity.identifier.") {
			kind = "identifier"
		} else {
			return [32]byte{}, invalidAudit()
		}
	}
	if attrs["aggregate.id"] != target || attrs["aggregate.type"] != kind || attrs["aggregate.before_version"] == "" || attrs["aggregate.after_version"] == "" || record.Subject().Type() != kind || record.Subject().ID() != target {
		return [32]byte{}, invalidAudit()
	}
	if (strings.HasPrefix(binding.OperationID, "identity.admin.") || binding.OperationID == "identity.user.update-admin" || binding.LinkMode == identity.AccountLinkAdministrative) && attrs["retention.class"] != "protected" {
		return [32]byte{}, invalidAudit()
	}
	encoded := cborMap(map[string][]byte{"domain": cborText("identity-audit-binding-v1"), "command": cborMap(commandScope(binding)), "actor_kind": cborUint(uint64(actor.Kind())), "actor_id": cborText(actor.ID()), "subject_type": cborText(record.Subject().Type()), "subject_id": cborText(record.Subject().ID())})
	return sha256.Sum256(encoded), nil
}

// bindAuditPlans is coordinator-private and must precede any SQL or staging.
// No adapter can late-enlist an audit slot or restart a staging budget.
func bindAuditPlans(w Work, plans []AuditPlan) error {
	if err := w.usable(); err != nil {
		return err
	}
	// Each currently implemented kernel command has exactly one mandatory
	// action. Feature composition will declare its own exhaustive multi-action
	// mapping; do not accept an empty or duplicated kernel action meanwhile.
	if w.state.audits != nil || w.state.sqlStarted || len(plans) != 1 {
		return invalidAudit()
	}
	for i, p := range plans {
		if !kernelAuditAction(p.EventType) || p.EventType != kernelCommandAudit(w.state.binding.OperationID) || p.SchemaVersion != 1 || p.BindingDigest == ([32]byte{}) || p.RetentionPolicyVersion == 0 || p.RequiredRecordCount != 1 || !p.Required || p.MaxRecordBytes == 0 || p.MaxRecordBytes > 16384 || p.MaxAggregateBytes < p.MaxRecordBytes || p.MaxAggregateBytes > 16384 || i > 0 && plans[i-1].EventIndex >= p.EventIndex {
			return invalidAudit()
		}
	}
	w.state.audits = &workAudits{plans: append([]AuditPlan(nil), plans...), records: make([]audit.Record, len(plans)), staged: make([]bool, len(plans)), ids: make(map[string]struct{})}
	return nil
}

// StageAudit stages a canonical privacy-processed audit record at its exact
// declared index. It preserves Builder's opaque random ID, rejects duplicate
// IDs/indices, mismatched binding/schema/action and oversized or non-profile
// records, and poisons Work on admission failure. Work lifetime applies even
// though this method performs no I/O. It never calls user policy, a sink, or a
// transaction closer. The future registered audit contributor must persist these
// records through this same Work before terminalization; staging alone is not
// durable audit delivery or evidence that a command committed.
func (w Work) StageAudit(index uint16, record audit.Record) error {
	if err := w.usable(); err != nil {
		return err
	}
	deny := func() error { return w.fail(w.state.ctx, invalidAudit()) }
	a := w.state.audits
	if a == nil {
		return deny()
	}
	position := -1
	for i, p := range a.plans {
		if p.EventIndex == index {
			position = i
			break
		}
	}
	if position < 0 || a.staged[position] {
		return deny()
	}
	p := a.plans[position]
	if _, exists := a.ids[record.ID()]; exists {
		return deny()
	}
	if record.Action() != p.EventType || !validKernelAuditRecord(record) {
		return deny()
	}
	digest, err := AuditBindingDigest(w.state.binding, record)
	if err != nil || digest != p.BindingDigest {
		return deny()
	}
	encoded, err := audit.CanonicalJSON(record)
	if err != nil || len(encoded) > int(p.MaxRecordBytes) || len(encoded) > int(p.MaxAggregateBytes) || len(encoded) > (1<<20)-a.bytes {
		return deny()
	}
	if _, err = audit.ParseCanonicalJSON(encoded, securityAuditLimits()); err != nil {
		return deny()
	}
	if err = w.usable(); err != nil {
		return err
	}
	a.records[position] = record
	a.staged[position] = true
	a.ids[record.ID()] = struct{}{}
	a.bytes += len(encoded)
	return nil
}

func completeAudits(w Work) error {
	if err := w.usable(); err != nil {
		return err
	}
	if w.state.audits == nil {
		return invalidAudit()
	}
	for _, staged := range w.state.audits.staged {
		if !staged {
			return invalidAudit()
		}
	}
	return nil
}

func validKernelAuditRecord(r audit.Record) bool {
	if !r.RedactionApplied() || r.Description() != "" || !kernelAuditContext(r.Context()) || !randomAuditID(r.ID()) || !auditOutcomeReason(r.Outcome(), r.ReasonCode()) {
		return false
	}
	changes := r.Changes()
	if len(changes.Before()) != 0 || len(changes.After()) != 0 || !changes.NoChange() && !changes.Redacted() {
		return false
	}
	attrs := r.Attributes()
	if attrs["identity.profile"] != "identity.security.v1" || attrs["retention.class"] != "standard" && attrs["retention.class"] != "protected" || len(attrs) > 32 {
		return false
	}
	for key, value := range attrs {
		switch key {
		case "identity.profile", "command.id", "retention.class":
		case "aggregate.id":
			if !auditSafeID(value) {
				return false
			}
		case "aggregate.type":
			if value != "user" && value != "account" && value != "identifier" {
				return false
			}
		case "aggregate.before_version", "aggregate.after_version":
			v, e := strconv.ParseUint(value, 10, 64)
			if e != nil || strconv.FormatUint(v, 10) != value {
				return false
			}
		case "authorization.reason", "error.code":
			if !auditReason(value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func kernelAuditContext(c audit.RecordContext) bool {
	if c.NetworkOrigin() != "" || c.UserAgent() != "" {
		return false
	}
	for _, s := range []string{c.TenantID(), c.CorrelationID(), c.CausationID(), c.RequestID(), c.TraceID(), c.IdempotencyID()} {
		if s != "" && !auditSafeID(s) {
			return false
		}
	}
	for _, s := range []string{c.SourceService(), c.SourceVersion(), c.Environment()} {
		if len(s) > 64 {
			return false
		}
		for _, b := range []byte(s) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
				return false
			}
		}
	}
	return true
}
func auditOutcomeReason(outcome audit.Outcome, reason string) bool {
	switch outcome {
	case audit.OutcomeSucceeded:
		return reason == "completed"
	case audit.OutcomeUnknown:
		return reason == "commit_unknown"
	case audit.OutcomeFailed:
		return reason == "provider_unavailable" || reason == "timeout" || reason == "cancelled"
	case audit.OutcomeDenied:
		return auditReason(reason) && reason != "completed" && reason != "commit_unknown" && reason != "provider_unavailable" && reason != "timeout" && reason != "cancelled"
	}
	return false
}

func kernelAuditAction(s string) bool {
	switch s {
	case "identity.user.create", "identity.user.update", "identity.user.suspend", "identity.user.restore", "identity.user.anonymize", "identity.user.delete", "identity.account.link", "identity.account.unlink", "identity.identifier.add", "identity.identifier.request_verification", "identity.identifier.verify", "identity.identifier.change", "identity.identifier.remove":
		return true
	}
	return false
}
func kernelCommandAudit(s string) string {
	switch s {
	case "identity.account.link-token":
		return "identity.account.link"
	case "identity.identifier.attach":
		return "identity.identifier.add"
	case "identity.identifier.replace", "identity.identifier.make-primary":
		// Primary selection changes the existing identifier; it is not a new
		// identifier or a verification event and has no synonymous audit action.
		return "identity.identifier.change"
	case "identity.user.update-admin", "identity.profile.update":
		return "identity.user.update"
	case "identity.admin.user-ban":
		return "identity.user.suspend"
	case "identity.admin.user-unban":
		return "identity.user.restore"
	case "identity.admin.user-delete":
		return "identity.user.delete"
	}
	if kernelAuditAction(s) {
		return s
	}
	return ""
}
func randomAuditID(s string) bool {
	if _, err := identity.ParseSubjectID(s); err == nil {
		return true
	}
	if len(s) != 32 {
		return false
	}
	id, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(id) != s {
		return false
	}
	for _, b := range id {
		if b != 0 {
			return true
		}
	}
	return false
}
func auditReason(s string) bool {
	switch s {
	case "completed", "invalid_input", "not_authenticated", "not_authorized", "not_found_hidden", "conflict", "expired", "replayed", "rate_limited", "risk_denied", "step_up_required", "provider_denied", "provider_unavailable", "timeout", "cancelled", "commit_unknown":
		return true
	}
	return false
}
func auditSafeID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func auditName(s string) bool {
	if len(s) == 0 || len(s) > 96 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func invalidAudit() error { return identity.InvalidInputError{Field: "audit_staging"} }
