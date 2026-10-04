package postgres

import (
	"context"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// enqueueExecutor is the owned Queue's private prepared-command execution
// component, not a public Queue or another command owner. Trusted composition
// supplies the same coordinator/registry and native/custody pair. It owns no
// pool, transaction, provider, mutable configuration or generic workflow.
// Current policy is checked before reservation, including committed replay.
// Admit owns pre-encryption policy and retained profile selection for explicit
// workflow inputs. Recipient discovery and keyed public Queue remain unfinished.
type enqueueExecutor struct {
	coordinator                     *identitypostgres.Coordinator
	registry                        *identitypostgres.ContributorRegistry
	native                          *EnqueueContributor
	custody                         *Contributor
	authorize                       authorization.Service
	policyID                        string
	policyVersion, retentionVersion uint64
	timeout                         time.Duration
}

func newEnqueueExecutor(c *identitypostgres.Coordinator, r *identitypostgres.ContributorRegistry, n *EnqueueContributor, custody *Contributor, a authorization.Service, policy string, revision, retention uint64, timeout time.Duration) (*enqueueExecutor, error) {
	if c == nil || r == nil || n == nil || custody == nil || custody.store == nil || n.custody != custody || a == nil || !safeID(policy, false) || revision == 0 || retention == 0 || timeout < time.Second || timeout > 5*time.Second {
		return nil, delivery.ErrInvalidInput
	}
	value := reflect.ValueOf(a)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, delivery.ErrInvalidInput
	}
	return &enqueueExecutor{c, r, n, custody, a, policy, revision, retention, timeout}, nil
}

func (e *enqueueExecutor) Execute(ctx context.Context, prepared PreparedDelivery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.coordinator == nil || prepared.state == nil || prepared.state.owner != e.custody {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.CommandResult{}, err
	}
	command, err := prepared.EnqueueCommand()
	if err != nil {
		return identity.CommandResult{}, err
	}
	spec, _ := command.Feature()
	b := spec.Binding
	if err := e.allow(bounded, b, caller); err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := prepared.Plan()
	if err != nil {
		return identity.CommandResult{}, err
	}
	digest, err := enqueueAuditDigest(b)
	if err != nil {
		return identity.CommandResult{}, delivery.ErrUnavailable
	}
	declaration := identitypostgres.CommandPlan{
		Contributors: e.registry.Descriptors(), SubjectType: "delivery_intent",
		Feature:   &identitypostgres.FeatureRegistration{Contributor: e.native.Descriptor(), Operation: EnqueueOperation()},
		Audits:    []identitypostgres.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: e.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}},
		Lifecycle: &identitypostgres.LifecyclePlan{EventType: "delivery.enqueued.v1", AfterVersion: 1}, Delivery: &plan,
	}
	declaration, err = e.coordinator.PrepareCommandPlan(b, command, declaration)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := e.coordinator.ReserveCommand(bounded, b, command, declaration)
	if err != nil || reservation == (identitypostgres.Reservation{}) {
		return result, err
	}
	work, err := e.coordinator.Begin(bounded, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: EnqueueOperation()}}, err
	}
	defer e.coordinator.Abort(work, identity.UnavailableError{})
	provisional, err := e.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		return e.coordinator.Abort(work, err)
	}
	if err := e.custody.Stage(bounded, work, prepared); err != nil {
		return e.coordinator.Abort(work, err)
	}
	return e.coordinator.Commit(work, provisional)
}

func (e *enqueueExecutor) allow(ctx context.Context, b identity.CommandBinding, dc authorization.DecisionContext) (err error) {
	defer func() {
		if recover() != nil {
			err = delivery.ErrUnavailable
		}
	}()
	r := dc.Request
	if b.PolicyID != e.policyID || b.PolicyVersion != e.policyVersion || dc.PolicyRevision != authorization.Revision(e.policyVersion) || dc.CorrelationID != b.CorrelationID || r.Action != authorization.Action(b.OperationID) || r.Tenant != authorization.TenantID(b.TenantID) || r.Subject.ID != authorization.SubjectID(b.ActorID) || r.Subject.Kind != b.ActorKind || r.Resource.Type != "identity.user" || r.Resource.ID != authorization.ResourceID(b.UserID) || len(r.Subject.Groups) > 32 {
		return delivery.ErrForbidden
	}
	// Bound the entire input before Clone or dispatch. CollectionLength avoids
	// allocating a caller-sized copy through StringSet before rejecting it.
	remaining := 64 * 1024
	for _, group := range r.Subject.Groups {
		if !safeID(string(group), false) {
			return delivery.ErrInvalidInput
		}
		remaining -= len(group)
	}
	for _, attrs := range []authorization.Attributes{r.Subject.Attributes, r.Resource.Attributes, r.Environment.Attributes, r.Attributes} {
		if len(attrs) > 128 {
			return delivery.ErrInvalidInput
		}
		for name, value := range attrs {
			if !safeID(string(name), false) {
				return delivery.ErrInvalidInput
			}
			remaining -= len(name) + 1
			switch value.Kind() {
			case authorization.ValueString:
				text, _ := value.String()
				if len(text) > 4096 || !utf8.ValidString(text) {
					return delivery.ErrInvalidInput
				}
				remaining -= len(text)
			case authorization.ValueStringSet:
				length, _ := value.CollectionLength()
				if length > 64 {
					return delivery.ErrInvalidInput
				}
				members, _ := value.StringSet()
				for _, member := range members {
					if len(member) > 4096 || !utf8.ValidString(member) {
						return delivery.ErrInvalidInput
					}
					remaining -= len(member) + 1
				}
			case authorization.ValueNull, authorization.ValueBool, authorization.ValueInt, authorization.ValueFloat, authorization.ValueTime, authorization.ValueIP:
				remaining -= 32
			default:
				return delivery.ErrInvalidInput
			}
			if remaining < 0 {
				return delivery.ErrInvalidInput
			}
		}
	}
	if dc.Validate() != nil {
		return delivery.ErrInvalidInput
	}
	dc = dc.Clone()
	dc.Request.Environment.Time = time.Now().UTC()
	decision, err := e.authorize.Decide(ctx, dc)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return delivery.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return delivery.ErrForbidden
	}
	return nil
}

// Only scope identity is needed before execution; the kernel owns the actual
// protected success/failure audit, its event ID and database occurrence time.
func enqueueAuditDigest(b identity.CommandBinding) ([32]byte, error) {
	return deliveryFeatureAuditDigest(b, EnqueueOperation())
}

func deliveryFeatureAuditDigest(b identity.CommandBinding, operation identity.FeatureOperation) ([32]byte, error) {
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return [32]byte{}, err
	}
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "delivery_intent", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "delivery_intent", "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return [32]byte{}, err
	}
	return identitypostgres.FeatureAuditBindingDigest(b, operation, "delivery_intent", record)
}
