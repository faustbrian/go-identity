package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpostgres "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

// workerAudit is immutable authenticated deployment attribution. The existing
// effect transaction owns state, history and audit; this is not another command
// journal. Private legacy stores without this selection remain private only.
type workerAudit struct {
	actor, correlation, policy string
	policyVersion              uint64
}

type workerAuditClock time.Time

// Match the shared profile's documented privacy-safe internal-token grammar
// before any lease is admitted, rather than discovering invalid attribution
// while staging a record after a database mutation.
func workerAuditToken(s string) bool {
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

func (c workerAuditClock) Now() time.Time { return time.Time(c) }

func (s *attemptStore) stageCleanupAudit(ctx context.Context, tx pgx.Tx, tenant delivery.TenantID, id string, transition identity.DeliverySecurityTransition) error {
	if s.audit == nil {
		return nil
	}
	var aad []byte
	var state string
	if err := tx.QueryRow(ctx, `SELECT binding_aad,state FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(tenant), id).Scan(&aad, &state); err != nil {
		return delivery.ErrUnavailable
	}
	b, err := decodeBinding(aad)
	if err != nil || string(b.Command.TenantID) != string(tenant) || b.Intent.EffectID != id || b.Intent.ProviderConfigVersion != s.providerVersion {
		return delivery.ErrUnavailable
	}
	if transition == identity.DeliverySecurityExpired && state != "expired" {
		transition = identity.DeliverySecurityPayloadErased
	}
	return s.stageWorkerAudit(ctx, tx, b, transition)
}

func (s *attemptStore) stageWorkerAudit(ctx context.Context, tx pgx.Tx, b payloadBinding, transition identity.DeliverySecurityTransition) error {
	if s.audit == nil {
		return nil
	}
	var version string
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT status_version::text,clock_timestamp() FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, s.deployment, string(b.Command.TenantID), b.Intent.EffectID).Scan(&version, &now); err != nil {
		return delivery.ErrUnavailable
	}
	after, err := strconv.ParseUint(version, 10, 64)
	if err != nil || after < 2 {
		return delivery.ErrUnavailable
	}
	builder, err := identity.NewIdentitySecurityEventV1(workerAuditClock(now.UTC()))
	if err != nil {
		return delivery.ErrUnavailable
	}
	record, err := builder.BuildDelivery(ctx, identity.DeliverySecurityEventInput{
		Transition: transition, OccurredAt: now.UTC(), TenantID: b.Command.TenantID,
		IntentID: b.Intent.EffectID, CommandID: b.Command.CommandID, WorkerActorID: s.audit.actor,
		CorrelationID: s.audit.correlation, PolicyID: s.audit.policy, PolicyVersion: s.audit.policyVersion,
		ProviderVersion: b.Intent.ProviderConfigVersion, BeforeVersion: after - 1, AfterVersion: after,
	})
	if err != nil {
		return delivery.ErrUnavailable
	}
	writer, err := auditpostgres.NewTx(tx, auditpostgres.Config{MaxBatchRecords: 1})
	if err != nil {
		return delivery.ErrUnavailable
	}
	if _, err := writer.Stage(ctx, []audit.Record{record}); err != nil {
		return delivery.ErrUnavailable
	}
	return nil
}

func workerCompletionTransition(q delivery.CompleteRequest, state delivery.DeliveryState) identity.DeliverySecurityTransition {
	switch state {
	case delivery.StateAccepted:
		return identity.DeliverySecurityAccepted
	case delivery.StateDelivered:
		return identity.DeliverySecurityConfirmed
	case delivery.StateRejected, delivery.StateBounced:
		return identity.DeliverySecurityRejected
	case delivery.StateOutcomeUnknown:
		return identity.DeliverySecurityUnknown
	case delivery.StateCancelled:
		return identity.DeliverySecurityCancelled
	case delivery.StateExpired:
		return identity.DeliverySecurityExpired
	case delivery.StateExhausted:
		return identity.DeliverySecurityExhausted
	case delivery.StateRetryWait:
		if !q.Invoked {
			return identity.DeliverySecurityReleased
		}
		return identity.DeliverySecurityRetry
	}
	return 0
}
