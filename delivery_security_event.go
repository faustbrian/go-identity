package identity

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
)

// DeliverySecurityTransition classifies committed local delivery bookkeeping,
// not a provider invocation or an unknown database commit. Zero is invalid.
type DeliverySecurityTransition uint8

const (
	DeliverySecurityAttempt       DeliverySecurityTransition = iota + 1 // Committed invocation lease, before provider IO.
	DeliverySecurityAccepted                                            // Provider acceptance, not delivery.
	DeliverySecurityConfirmed                                           // Authoritative delivery success.
	DeliverySecurityRejected                                            // Permanent rejection or bounce.
	DeliverySecurityRetry                                               // Authoritative transient no-success evidence.
	DeliverySecurityUnknown                                             // Observed ambiguous provider outcome.
	DeliverySecurityCancelled                                           // Local stop, not remote confirmation.
	DeliverySecurityExpired                                             // Unsent work expired and custody erased.
	DeliverySecurityExhausted                                           // Retry policy exhausted, not provider rejection.
	DeliverySecurityReleased                                            // Lease released with authoritative no-invocation evidence.
	DeliverySecurityPayloadErased                                       // Expired custody erased without inventing an outcome.
	DeliverySecurityLeaseLost                                           // Lease expired without an observed provider result.
)

// DeliverySecurityEventInput is trusted owned-adapter attribution. IDs are
// stable internal tokens, not usernames, addresses or credentials. IntentID is
// the exact nonzero 64-byte lowercase hexadecimal effect ID. WorkerActorID is
// the authenticated service account, not a lease name or the message owner.
// Versions are the database-owned status versions before/after this transition.
// CommandID and causation preserve the original owning command. No fields carry
// recipient, rendering, provider reference, raw receipt, or arbitrary claims.
type DeliverySecurityEventInput struct {
	Transition                     DeliverySecurityTransition
	OccurredAt                     time.Time
	TenantID                       TenantID
	IntentID                       string
	CommandID                      CommandID
	WorkerActorID, CorrelationID   string
	PolicyID                       string
	PolicyVersion, ProviderVersion uint64
	BeforeVersion, AfterVersion    uint64
}

// BuildDelivery builds the delivery subset of the shared immutable security
// profile. It never persists, retries or grants authority. OutcomeSucceeded
// means local bookkeeping was recorded; ambiguous provider evidence is a
// mark_unknown event, not OutcomeUnknown (reserved for an unknown commit).
// Accepted/retry/expiry/exhaustion/erasure do not claim provider confirmation.
// Exhaustion is local policy evidence and emits no provider-result assertion.
// Caller owns the bounded database transaction when it stages the result.
func (b *IdentitySecurityEventV1) BuildDelivery(ctx context.Context, i DeliverySecurityEventInput) (audit.Record, error) {
	if ctx == nil || b == nil || b.builder == nil || b.redactor == nil {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	if err := ctx.Err(); err != nil {
		return audit.Record{}, err
	}
	if i.Transition < DeliverySecurityAttempt || i.Transition > DeliverySecurityLeaseLost || i.OccurredAt.IsZero() || i.OccurredAt.Location() != time.UTC || !deliveryAuditToken(string(i.TenantID)) || !deliveryAuditToken(i.WorkerActorID) || !deliveryAuditToken(i.CorrelationID) || !deliveryAuditToken(i.PolicyID) || !securityCommandID(i.CommandID) || !deliveryAuditEffect(i.IntentID) || i.PolicyVersion == 0 || i.ProviderVersion == 0 || i.BeforeVersion == 0 || i.BeforeVersion == ^uint64(0) || i.AfterVersion != i.BeforeVersion+1 {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	action, result := "identity.delivery.attempt", ""
	reason := "completed"
	switch i.Transition {
	case DeliverySecurityAccepted:
		result = "accepted"
	case DeliverySecurityConfirmed:
		action, result = "identity.delivery.confirm", "accepted"
	case DeliverySecurityRejected:
		action, result = "identity.delivery.reject", "denied"
	case DeliverySecurityRetry:
		result = "unavailable"
	case DeliverySecurityUnknown:
		action, result = "identity.delivery.mark_unknown", "ambiguous"
	case DeliverySecurityLeaseLost:
		action = "identity.delivery.mark_unknown"
	case DeliverySecurityCancelled:
		action, reason = "identity.delivery.cancel", "cancelled"
	case DeliverySecurityExpired, DeliverySecurityPayloadErased:
		reason = "expired"
	}
	attrs := map[string]string{"identity.profile": "identity.security.v1", "command.id": string(i.CommandID), "retention.class": "protected", "provider.kind": "delivery", "provider.profile": "delivery.worker.v1", "provider.version": strconv.FormatUint(i.ProviderVersion, 10), "aggregate.type": "delivery_intent", "aggregate.id": i.IntentID, "aggregate.before_version": strconv.FormatUint(i.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(i.AfterVersion, 10)}
	if result != "" {
		attrs["provider.result"] = result
	}
	r, err := b.builder.Build(audit.RecordInput{OccurredAt: i.OccurredAt, Action: action, Outcome: audit.OutcomeSucceeded, ReasonCode: reason,
		Actor: audit.ActorInput{Kind: audit.ActorSystem, ID: i.WorkerActorID}, Subject: audit.SubjectInput{Type: "delivery_intent", ID: i.IntentID},
		Context: audit.ContextInput{TenantID: string(i.TenantID), CorrelationID: i.CorrelationID, CausationID: string(i.CommandID)},
		Policy:  audit.PolicyMetadata{PolicyID: i.PolicyID, Version: strconv.FormatUint(i.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: attrs})
	if err != nil {
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	r, err = b.redactor.Redact(ctx, r)
	if err != nil {
		if ctx.Err() != nil {
			return audit.Record{}, ctx.Err()
		}
		return audit.Record{}, ErrInvalidSecurityEvent
	}
	return r, nil
}

func deliveryAuditToken(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func deliveryAuditEffect(s string) bool {
	if len(s) != 64 {
		return false
	}
	nonzero := false
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}
