package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

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
	if ctx == nil || s == nil || s.executor == nil || s.keyed == nil || s.keyed.pool == nil || !safeID(string(q.TenantID), false) || !safeID(string(user), false) || len(q.IntentID) != 64 {
		return delivery.StatusGetResult{}, delivery.ErrInvalidInput
	}
	intent, err := hex.DecodeString(string(q.IntentID))
	if err != nil || hex.EncodeToString(intent) != string(q.IntentID) {
		return delivery.StatusGetResult{}, delivery.ErrInvalidInput
	}
	w, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	if err := w.Err(); err != nil {
		return delivery.StatusGetResult{}, err
	}
	for _, attrs := range []authorization.Attributes{caller.Request.Subject.Attributes, caller.Request.Resource.Attributes, caller.Request.Environment.Attributes, caller.Request.Attributes} {
		if len(attrs) > 128 {
			return delivery.StatusGetResult{}, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return delivery.StatusGetResult{}, delivery.ErrInvalidInput
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
		return delivery.StatusGetResult{}, err
	}
	var snapshot deliveryStatus
	stopColumn := "NULL::text"
	if s.stateTracking {
		stopColumn = "i.local_stop_state"
	}
	err = s.keyed.pool.QueryRow(w, `SELECT i.state,COALESCE(p.generation,0),h.outcome,
p.lease_owner IS NOT NULL AND p.lease_until>clock_timestamp(),
h.provider_reference_digest IS NOT NULL,i.no_op,i.expires_at<=clock_timestamp(),`+stopColumn+`
FROM identity.delivery_intents i
LEFT JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)
LEFT JOIN identity.delivery_attempt_history h ON h.deployment=p.deployment AND h.tenant_id=p.tenant_id AND h.effect_id=p.effect_id AND h.generation=p.generation
WHERE i.deployment=$1 AND i.tenant_id=$2 AND i.effect_id=$3 AND i.subject_id=$4`, s.keyed.deployment, string(q.TenantID), string(q.IntentID), string(user)).Scan(&snapshot.state, &snapshot.generation, &snapshot.outcome, &snapshot.live, &snapshot.reference, &snapshot.noop, &snapshot.expired, &snapshot.localStop)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.StatusGetResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.StatusGetResult{}, attemptFailure(w, err)
	}
	return snapshot.result()
}

// Safe metadata only. PostgreSQL owns the snapshot; no reference/content bytes
// are loaded, and classification cannot create an attempt or provider receipt.
type deliveryStatus struct {
	state                          string
	generation                     int64
	outcome                        *int16
	live, reference, noop, expired bool
	localStop                      *string
}

func (s deliveryStatus) result() (delivery.StatusGetResult, error) {
	if s.generation < 0 || s.generation > 4294967295 {
		return delivery.StatusGetResult{}, delivery.ErrUnavailable
	}
	out := delivery.StatusGetResult{AttemptGeneration: uint32(s.generation), ProviderReferencePresent: s.reference}
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
		if s.outcome != nil {
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
		if s.outcome != nil && delivery.DeliveryState(*s.outcome) == delivery.StateBounced {
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
