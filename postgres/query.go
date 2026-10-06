package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// CommandQueryPolicy enables receipt disclosure using the existing policy
// service, not historical grants. PolicyVersion must be positive; Authorization
// and Clock must be nonnil, concurrency-safe and bounded. Authorization runs
// before SQL and must honor cancellation. Neither dependency runs in an open
// transaction. The constructor copies configuration; caller-owned services
// must retain their immutable revision contract for this Coordinator's lifetime.
type CommandQueryPolicy struct {
	Authorization authorization.Service
	Clock         clock.Clock
	PolicyVersion uint64
}

// Format hides runtime policy dependencies in diagnostic formatting.
func (CommandQueryPolicy) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("postgres.CommandQueryPolicy(redacted)"))
}

// MarshalJSON rejects serialization of runtime policy composition.
func (CommandQueryPolicy) MarshalJSON() ([]byte, error) { return nil, coordinatorError() }

func validCommandQueryPolicy(p CommandQueryPolicy) bool {
	return p.PolicyVersion > 0 && !nilQueryDependency(p.Authorization) && !nilQueryDependency(p.Clock)
}

func nilQueryDependency(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

type commandObservation struct {
	tenant, purpose       string
	scope                 []byte
	fingerprint           []byte
	fingerprintKeyVersion int64
	retired               bool
	state                 *string
	until                 *time.Time
	now                   time.Time
	resultVersion         *int32
	class                 *string
	result, plan          []byte
}

// CommandRecord is a safe historical command observation. It contains scope,
// outcome and bounded retry delay only: no replayed user/profile values,
// credential/account payload, audit record or contributor authority. Historical
// bindings are correlation, not current authorization or credential freshness.
// The zero value is invalid. Values are immutable copies safe for concurrent
// reads; successful lookup may accompany a classified terminal failure error.
type CommandRecord struct {
	Binding    identity.CommandBinding
	Outcome    identity.CommitOutcome
	RetryAfter time.Duration
	// Feature preserves the exact historical schema for feature-owned commands.
	// Nil denotes a kernel command. This owned scalar copy contains no native
	// receipt, current authority, contributor handle or feature result payload.
	Feature *identity.FeatureOperation
}

// Validate checks the closed public observation shape, not authority or proof
// that storage was read. Committed/NotCommitted have no retry delay; InProgress
// has a positive delay at most one minute. Unknown is not a primary observation.
func (r CommandRecord) Validate() error {
	probe := identity.CommandResult{Binding: r.Binding, Outcome: identity.CommitOutcomeNotCommitted}
	if r.Feature != nil {
		probe.Feature = &identity.FeatureReceipt{Operation: *r.Feature}
	}
	valid := probe.Validate() == nil
	switch r.Outcome {
	case identity.CommitOutcomeCommitted, identity.CommitOutcomeNotCommitted:
		valid = valid && r.RetryAfter == 0
	case identity.CommitOutcomeInProgress:
		valid = valid && r.RetryAfter > 0 && r.RetryAfter <= time.Minute
	default:
		valid = false
	}
	if !valid {
		return identity.InvalidInputError{Field: "command_record"}
	}
	return nil
}

func (c *Coordinator) readCommand(ctx context.Context, id identity.CommandID) (commandObservation, error) {
	key, _ := base64.RawURLEncoding.DecodeString(string(id))
	var observed commandObservation
	err := c.pool.Raw().QueryRow(ctx, `SELECT coalesce(c.tenant_id::text,''),coalesce(c.purpose,''),c.safe_fields,c.retired,
j.state,j.lease_until,clock_timestamp(),j.result_version,j.terminal_class,j.result,j.command_plan,c.fingerprint,coalesce(c.fingerprint_key_version,0)
FROM identity.identity_command_id_claims c LEFT JOIN identity.commands j
ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose
WHERE c.command_id=$1`, key).Scan(&observed.tenant, &observed.purpose, &observed.scope, &observed.retired, &observed.state, &observed.until, &observed.now, &observed.resultVersion, &observed.class, &observed.result, &observed.plan, &observed.fingerprint, &observed.fingerprintKeyVersion)
	return observed, err
}

// QueryCommand performs one bounded, uncached primary observation and one
// current authorization decision. Caller is trusted authenticated composition,
// never a client-decoded identity override; it must bind actor, tenant, original
// operation and identity.user resource to query.UserID (or the exact
// identity.anonymous-flow resource to query.AnonymousFlowID) at the configured policy
// revision. Command possession is not authorization. The policy receives copied
// bounded inputs, trusted current time and recovery/read-admission attributes.
//
// Valid missing, wrong-scope and denied requests take the same decision/read
// shape and return zero plus ForbiddenError; this does not promise identical
// network latency. Every RecoveryQuery field must match immutable stored scope.
// Successful observations preserve historical metadata, not current identity
// state or authority. Only safe scope/outcome metadata is returned; protected
// replay payloads stay inside the owned adapter/core recovery boundary.
//
// Pending, even expired, returns InProgress; absence never proves NotCommitted.
// Terminal receipts are canonical and classification-checked. Matching claims
// without complete journals fail Unavailable. This method never locks for
// mutation, changes ownership, renews leases or invokes contributors. It is not
// RecoverCommand. QueryPolicy is opt-in; disabled/invalid composition fails
// before I/O. Earlier caller deadlines win; driver/policy errors stay redacted.
func (c *Coordinator) QueryCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (CommandRecord, error) {
	receipt, err := c.queryCommandReceipt(ctx, q, caller)
	return commandRecord(receipt), err
}

func commandRecord(receipt identity.CommandResult) CommandRecord {
	result := CommandRecord{Binding: receipt.Binding, Outcome: receipt.Outcome, RetryAfter: receipt.RetryAfter}
	if receipt.Feature != nil {
		operation := receipt.Feature.Operation
		result.Feature = &operation
	}
	return result
}

// Full replay payloads are adapter-private. The owned UnitOfWork bridge must
// route them through the core's current field redaction, never public lookup.
func (c *Coordinator) queryCommandReceipt(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	return c.queryCommandReceiptChecked(ctx, q, caller, nil)
}

// The optional owned check narrows disclosure after the shared authorization,
// primary read and complete historical validation. It never grants authority.
func (c *Coordinator) queryCommandReceiptChecked(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, check func(commandObservation) error) (identity.CommandResult, error) {
	if ctx == nil || c == nil || c.commandRead == nil || c.queryPolicy == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return identity.CommandResult{}, coordinatorError()
	}
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "command_id"}
	}
	if !validQuerySubject(q) {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "command_query"}
	}
	for _, value := range []string{string(q.TenantID), string(q.ActorID), string(q.ActorKind), q.OperationID} {
		if !queryScopeText(value) {
			return identity.CommandResult{}, identity.InvalidInputError{Field: "command_query"}
		}
	}
	if q.RecordID != "" && !queryScopeText(q.RecordID) {
		return identity.CommandResult{}, identity.InvalidInputError{Field: "command_query"}
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.CommandResult{}, readFailure(bounded, err)
	}
	allowed, policyErr := c.authorizeCommandQuery(bounded, q, caller)
	// No early denial: the same primary read is performed for missing, wrong
	// scope and denied valid callers. No transaction is held across the policy.
	observed, err := c.commandRead(bounded, q.CommandID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) || bounded.Err() != nil {
		return identity.CommandResult{}, readFailure(bounded, err)
	}
	if policyErr != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if !allowed {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	result, receiptErr := commandReceipt(q, observed, err)
	if result.Outcome != identity.CommitOutcomeInvalid && check != nil {
		if err := check(observed); err != nil {
			return identity.CommandResult{}, err
		}
	}
	return result, receiptErr
}

// Both owned recovery and authorized public metadata lookup share the same
// historical fences. This parser grants no caller authorization or ownership.
func commandReceipt(q identity.RecoveryQuery, observed commandObservation, err error) (identity.CommandResult, error) {
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if errors.Is(err, pgx.ErrNoRows) || observed.retired || observed.tenant != string(q.TenantID) || observed.purpose != q.OperationID {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	binding, feature, decodeErr := decodeObservedScope(observed.scope)
	if decodeErr != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if binding.CommandID != q.CommandID || binding.TenantID != q.TenantID || binding.UserID != q.UserID || binding.AnonymousFlowID != q.AnonymousFlowID || binding.ActorID != q.ActorID || binding.ActorKind != q.ActorKind || binding.OperationID != q.OperationID || binding.RecordID != q.RecordID || binding.LinkMode != q.LinkMode {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	if observed.state == nil || observed.until == nil || !postgresExactTime(*observed.until) || !postgresExactTime(observed.now) || len(observed.plan) == 0 || len(observed.plan) > 65536 {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if len(observed.fingerprint) != 32 {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	var plan CommandPlan
	if feature == nil {
		plan, err = decodeKernelPlan(binding, [32]byte(observed.fingerprint), observed.plan)
	} else {
		plan, err = decodeFeaturePlan(binding, [32]byte(observed.fingerprint), observed.plan)
	}
	if err != nil || feature != nil && (plan.Feature == nil || plan.Feature.Operation != *feature) {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if *observed.state == "pending" {
		if observed.resultVersion != nil || observed.class != nil || observed.result != nil {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		retry := observed.until.Sub(observed.now)
		if retry < time.Microsecond {
			retry = time.Microsecond
		} else if retry > time.Minute {
			retry = time.Minute
		}
		result := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: retry}
		if feature != nil {
			result.Feature = &identity.FeatureReceipt{Operation: *feature}
		}
		return result, nil
	}
	if observed.resultVersion == nil || *observed.resultVersion != 1 || observed.class == nil || (*observed.state != "committed" && *observed.state != "aborted") {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	result, err := decodeJournalResult(claimRequest{safeFields: observed.scope, feature: feature}, observed.result)
	if err != nil || (*observed.state == "committed") != (result.Outcome == identity.CommitOutcomeCommitted) {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if *observed.state == "committed" {
		// A locally valid successor is not this command's declared transition.
		// Compare against immutable history, never today's aggregate or registry.
		if feature != nil && (plan.Lifecycle == nil || result.Feature.BeforeVersion != plan.Lifecycle.BeforeVersion || result.Feature.AfterVersion != plan.Lifecycle.AfterVersion) {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		if *observed.class != "committed" {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		return result, nil
	}
	switch *observed.class {
	case "denied":
		return result, identity.ForbiddenError{}
	case "conflict":
		return result, identity.ConflictError{CommandID: q.CommandID}
	case "cancelled":
		return result, identity.CancelledError{}
	case "deadline-exceeded":
		return result, identity.DeadlineExceededError{}
	case "dependency-failure":
		return result, identity.UnavailableError{}
	default:
		return identity.CommandResult{}, identity.UnavailableError{}
	}
}

func (c *Coordinator) authorizeCommandQuery(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (allowed bool, err error) {
	return authorizeCommandObservation(ctx, q, caller, c.queryPolicy, false)
}

func authorizeCommandObservation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, policy *CommandQueryPolicy, admission bool) (allowed bool, err error) {
	defer func() {
		if recover() != nil {
			allowed, err = false, identity.UnavailableError{}
		}
	}()
	if !boundedQueryCaller(caller) {
		return false, nil
	}
	dc := caller.Clone()
	now := policy.Clock.Now()
	if now.IsZero() {
		return false, identity.UnavailableError{}
	}
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for name := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(name), "identity.command.") {
			delete(dc.Request.Resource.Attributes, name)
		}
	}
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(!admission)
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(admission)
	dc.Request.Resource.Attributes["identity.command.id"] = authorization.StringValue(string(q.CommandID))
	dc.Request.Resource.Attributes["identity.command.record-id"] = authorization.StringValue(q.RecordID)
	dc.Request.Resource.Attributes["identity.command.link-mode"] = authorization.StringValue(strconv.FormatUint(uint64(q.LinkMode), 10))
	if len(dc.Request.Resource.Attributes) > 128 {
		return false, nil
	}
	decision, err := policy.Authorization.Decide(ctx, dc)
	if err != nil {
		return false, identity.UnavailableError{}
	}
	r := dc.Request
	resourceType, resourceID := authorization.ResourceType("identity.user"), string(q.UserID)
	if q.AnonymousFlowID != "" {
		resourceType, resourceID = "identity.anonymous-flow", q.AnonymousFlowID
	}
	matched := r.Subject.ID == authorization.SubjectID(q.ActorID) && r.Subject.Kind == q.ActorKind && r.Tenant == authorization.TenantID(q.TenantID) && r.Action == authorization.Action(q.OperationID) && r.Resource.Type == resourceType && r.Resource.ID == authorization.ResourceID(resourceID) && dc.PolicyRevision == authorization.Revision(policy.PolicyVersion)
	return matched && decision.Outcome == authorization.Allow && decision.Revision == authorization.Revision(policy.PolicyVersion), nil
}

func validQuerySubject(q identity.RecoveryQuery) bool {
	if q.AnonymousFlowID != "" {
		return q.UserID == "" && queryScopeText(q.AnonymousFlowID)
	}
	return queryScopeText(string(q.UserID))
}

func queryScopeText(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func boundedQueryCaller(dc authorization.DecisionContext) bool {
	if len(dc.Request.Subject.Groups) > 32 || dc.Validate() != nil {
		return false
	}
	for _, value := range []string{string(dc.Request.Subject.ID), string(dc.Request.Subject.Kind), string(dc.Request.Tenant), string(dc.Request.Action), string(dc.Request.Resource.Type), string(dc.Request.Resource.ID)} {
		if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
			return false
		}
	}
	for _, group := range dc.Request.Subject.Groups {
		if len(group) == 0 || len(group) > 128 || !utf8.ValidString(string(group)) {
			return false
		}
	}
	for _, attrs := range []authorization.Attributes{dc.Request.Subject.Attributes, dc.Request.Resource.Attributes, dc.Request.Environment.Attributes, dc.Request.Attributes} {
		if len(attrs) > 128 {
			return false
		}
		for name, value := range attrs {
			if len(name) == 0 || len(name) > 128 || !utf8.ValidString(string(name)) || value.Kind() == authorization.ValueMissing {
				return false
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return false
			}
			if count, ok := value.CollectionLength(); ok {
				if count > 64 {
					return false
				}
				items, _ := value.StringSet()
				for _, text := range items {
					if len(text) > 4096 || !utf8.ValidString(text) {
						return false
					}
				}
			}
		}
	}
	return true
}
