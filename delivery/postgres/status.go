package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

// StatusSnapshot is bounded primary metadata and its database-owned intent
// version from one statement. It grants no authority. Zero is not an observed
// snapshot. Retain StatusVersion and Status.AttemptGeneration unchanged for
// retries of a protected mutation; a later read must not rewrite its command.
// Effective lease/expiry classification can change without an intent UPDATE,
// so StatusVersion is a mutation fence, not a cache freshness guarantee.
type StatusSnapshot struct {
	Status        delivery.StatusGetResult
	StatusVersion uint64
}

// VersionedStatusGet observes the same authorized, redacted metadata as
// StatusGet with an atomic status-version fence. It requires StateTracking;
// legacy profiles return ErrInvalidInput rather than fabricate a version.
// Current policy applies before database access; failures return no snapshot.
// Concurrent calls are supported, bounded by the configured timeout. This
// method neither mutates state nor reserves a cancellation command.
func (s *EnqueueService) VersionedStatusGet(ctx context.Context, q delivery.StatusGetRequest, user identity.UserID, caller authorization.DecisionContext) (StatusSnapshot, error) {
	if s == nil || !s.stateTracking {
		return StatusSnapshot{}, delivery.ErrInvalidInput
	}
	return s.observeStatus(ctx, q, user, caller, true)
}

// StatusGet observes bounded primary delivery metadata under current exact
// actor, tenant and target-user authorization. Caller must be authenticated
// trusted composition, with action identity.delivery.status-get and resource
// identity.user targeting user. IDs alone grant no access. The service adds the
// reserved delivery.intent attribute; caller delivery.* attributes are rejected.
// Missing and foreign targets return the same NotFound result. No payload is
// decrypted, no provider is contacted and no durable state is mutated.
// No-op intents expose queued/expired metadata rather than an existence bit.
// Expired queued intents and lost leases reflect effective expiry/uncertainty,
// not provider rejection or permission to retry. This is not the complete Queue.
func (s *EnqueueService) StatusGet(ctx context.Context, q delivery.StatusGetRequest, user identity.UserID, caller authorization.DecisionContext) (delivery.StatusGetResult, error) {
	snapshot, err := s.observeStatus(ctx, q, user, caller, false)
	return snapshot.Status, err
}

func (s *EnqueueService) observeStatus(ctx context.Context, q delivery.StatusGetRequest, user identity.UserID, caller authorization.DecisionContext, versioned bool) (StatusSnapshot, error) {
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || !safeID(string(q.TenantID), false) || !safeID(string(user), false) || len(q.IntentID) != 64 {
		return StatusSnapshot{}, delivery.ErrInvalidInput
	}
	intent, err := hex.DecodeString(string(q.IntentID))
	if err != nil || hex.EncodeToString(intent) != string(q.IntentID) {
		return StatusSnapshot{}, delivery.ErrInvalidInput
	}
	w, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	if err := w.Err(); err != nil {
		return StatusSnapshot{}, err
	}
	for _, attrs := range []authorization.Attributes{caller.Request.Subject.Attributes, caller.Request.Resource.Attributes, caller.Request.Environment.Attributes, caller.Request.Attributes} {
		if len(attrs) > 128 {
			return StatusSnapshot{}, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return StatusSnapshot{}, delivery.ErrInvalidInput
			}
		}
	}
	attrs := make(authorization.Attributes, len(caller.Request.Resource.Attributes)+1)
	for name, value := range caller.Request.Resource.Attributes {
		attrs[name] = value
	}
	attrs["delivery.intent"] = authorization.StringValue(string(q.IntentID))
	caller.Request.Resource.Attributes = attrs
	b := identity.CommandBinding{TenantID: identity.TenantID(q.TenantID), UserID: user, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: "identity.delivery.status-get", PolicyID: s.executor.policyID, PolicyVersion: s.executor.policyVersion, CorrelationID: caller.CorrelationID}
	if err := s.executor.allow(w, b, caller); err != nil {
		return StatusSnapshot{}, err
	}
	var snapshot deliveryStatus
	stopColumn := "NULL::text"
	if s.stateTracking {
		stopColumn = "i.local_stop_state"
	}
	versionColumn := "NULL::text"
	if versioned {
		versionColumn = "i.status_version::text"
	}
	var version *string
	var bindingAAD []byte
	receiptColumn, receiptJoin := "NULL::smallint", ""
	if s.receiptTracking {
		receiptColumn = "r.result_state"
		// The installed observation index supplies one generation-scoped row.
		// No event identity, body, provider reference or custody is loaded.
		receiptJoin = `LEFT JOIN LATERAL (
SELECT result_state FROM identity.delivery_receipts r
WHERE r.deployment=i.deployment AND r.tenant_id=i.tenant_id
AND r.effect_id=i.effect_id AND r.provider=i.provider AND r.generation=p.generation
ORDER BY observed_at DESC NULLS LAST,event_digest LIMIT 1
) r ON true
`
	}
	err = s.keyed.pool.QueryRow(w, `SELECT i.state,COALESCE(p.generation,0),h.outcome,
p.lease_owner IS NOT NULL AND p.lease_until>clock_timestamp(),
h.provider_reference_digest IS NOT NULL,i.no_op,i.expires_at<=clock_timestamp(),`+stopColumn+`,`+versionColumn+`,`+receiptColumn+`,i.binding_aad
FROM identity.delivery_intents i
LEFT JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)
LEFT JOIN identity.delivery_attempt_history h ON h.deployment=p.deployment AND h.tenant_id=p.tenant_id AND h.effect_id=p.effect_id AND h.generation=p.generation
`+receiptJoin+`WHERE i.deployment=$1 AND i.tenant_id=$2 AND i.effect_id=$3 AND i.subject_id=$4`, s.keyed.deployment, string(q.TenantID), string(q.IntentID), string(user)).Scan(&snapshot.state, &snapshot.generation, &snapshot.outcome, &snapshot.live, &snapshot.reference, &snapshot.noop, &snapshot.expired, &snapshot.localStop, &version, &snapshot.receipt, &bindingAAD)
	if errors.Is(err, pgx.ErrNoRows) {
		return StatusSnapshot{}, delivery.ErrNotFound
	}
	if err != nil {
		return StatusSnapshot{}, attemptFailure(w, err)
	}
	if _, err := decodeUserBinding(bindingAAD, s.keyed.deployment, string(q.TenantID), string(q.IntentID), string(user)); err != nil {
		return StatusSnapshot{}, err
	}
	status, err := snapshot.result()
	if err != nil {
		return StatusSnapshot{}, err
	}
	out := StatusSnapshot{Status: status}
	if versioned {
		if version == nil {
			return StatusSnapshot{}, delivery.ErrUnavailable
		}
		out.StatusVersion, err = strconv.ParseUint(*version, 10, 64)
		if err != nil || out.StatusVersion == 0 {
			return StatusSnapshot{}, delivery.ErrUnavailable
		}
	}
	return out, nil
}

// Safe metadata only. PostgreSQL owns the snapshot; no reference/content bytes
// are loaded, and classification cannot create an attempt or provider receipt.
type deliveryStatus struct {
	state                          string
	generation                     int64
	outcome                        *int16
	receipt                        *int16
	live, reference, noop, expired bool
	localStop                      *string
}

func (s deliveryStatus) result() (delivery.StatusGetResult, error) {
	if s.generation < 0 || s.generation > 4294967295 {
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	out := delivery.StatusGetResult{AttemptGeneration: uint32(s.generation), ProviderReferencePresent: s.reference}
	if s.receipt != nil && (*s.receipt < 2 || *s.receipt > 12 || s.generation == 0 || s.noop || s.state == "planned") {
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	if !s.noop && s.localStop != nil {
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	if s.noop {
		if s.state != "cancelled" || s.generation != 0 || s.outcome != nil || s.live || s.reference {
			return delivery.StatusGetResult{}, delivery.ErrUnavailable
		}
		if s.localStop != nil {
			switch *s.localStop {
			case "cancelled":
				out.State = delivery.StateCancelled
			case "expired":
				out.State = delivery.StateExpired
			default:
				return delivery.StatusGetResult{}, delivery.ErrUnavailable
			}
			out.Terminal = true
			return out, nil
		}
		out.State = delivery.StateQueued
		if s.expired {
			out.State, out.Terminal = delivery.StateExpired, true
		}
		return out, nil
	}
	switch s.state {
	case "planned":
		if s.generation != 0 || s.outcome != nil || s.live || s.reference {
			return delivery.StatusGetResult{}, delivery.ErrUnavailable
		}
		out.State = delivery.StateQueued
		if s.expired {
			out.State, out.Terminal = delivery.StateExpired, true
		}
	case "submitted":
		if s.receipt != nil && delivery.DeliveryState(*s.receipt) == delivery.StateAccepted {
			// Definitive receipt settlement fences the worker but intentionally
			// retains its original unknown/transient completion for exact replay.
			if s.live {
				return delivery.StatusGetResult{}, delivery.ErrUnavailable
			}
			out.State = delivery.StateAccepted
		} else if s.outcome != nil {
			if delivery.DeliveryState(*s.outcome) != delivery.StateAccepted || s.live {
				return delivery.StatusGetResult{}, delivery.ErrUnavailable
			}
			out.State = delivery.StateAccepted
		} else if s.live {
			out.State = delivery.StateAttempting
		} else {
			out.State = delivery.StateOutcomeUnknown
		}
	case "retry-wait":
		out.State = delivery.StateRetryWait
		if s.expired {
			out.State, out.Terminal = delivery.StateExpired, true
		}
	case "outcome-unknown":
		out.State = delivery.StateOutcomeUnknown
	case "confirmed":
		out.State, out.Terminal = delivery.StateDelivered, true
	case "rejected":
		out.State, out.Terminal = delivery.StateRejected, true
		if s.outcome != nil && delivery.DeliveryState(*s.outcome) == delivery.StateBounced || s.receipt != nil && delivery.DeliveryState(*s.receipt) == delivery.StateBounced {
			out.State = delivery.StateBounced
		}
	case "cancelled":
		out.State, out.Terminal = delivery.StateCancelled, true
	case "expired":
		out.State, out.Terminal = delivery.StateExpired, true
	case "exhausted":
		out.State, out.Terminal = delivery.StateExhausted, true
	case "superseded":
		out.State, out.Terminal = delivery.StateSuperseded, true
	default:
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	if s.generation == 0 && out.State != delivery.StateQueued && out.State != delivery.StateCancelled && out.State != delivery.StateExpired && out.State != delivery.StateSuperseded {
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	return out, nil
}
