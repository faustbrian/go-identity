package impersonationpostgres

import (
	"context"
	"database/sql"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	database "github.com/faustbrian/go-postgres"
)

// The six tenant/grant primary keys bound this snapshot to one row, including
// the fixed-one approval history. Bindings are checked rather than filtered out:
// a malformed retained marker must not make a terminal grant appear live.
const quorumSnapshotSQL = `SELECT
 g.requester_id,g.target_id,g.requested_at,g.expires_at,g.state,g.version,
 octet_length(g.request_digest)=32,
 p.command_id,p.approver_id,p.decided_at,
 CASE WHEN p.grant_id IS NULL THEN true ELSE
  p.requester_id=g.requester_id AND p.target_id=g.target_id AND p.request_digest=g.request_digest
 END,
 a.state,a.version,a.started_at,a.expires_at,
 CASE WHEN a.grant_id IS NULL THEN true ELSE
  a.actor_id=g.requester_id AND a.target_id=g.target_id AND a.request_digest=g.request_digest
  AND a.approval_command_id=p.command_id AND a.approver_id=p.approver_id
  AND a.activation_command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
  AND a.activation_command_id<>'AAAAAAAAAAAAAAAAAAAAAA'
  AND a.activation_command_id<>g.grant_id AND a.activation_command_id<>p.command_id
 END,
 d.grant_id IS NOT NULL,
 CASE WHEN d.grant_id IS NULL THEN true ELSE
  d.requester_id=g.requester_id AND d.target_id=g.target_id AND d.request_digest=g.request_digest
  AND d.denier_id<>g.requester_id AND d.denier_id<>g.target_id
  AND d.command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
  AND d.command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND d.command_id<>g.grant_id
  AND d.before_version=1 AND d.after_version=2
  AND d.denied_at>=g.requested_at AND d.denied_at<g.expires_at
 END,
 r.grant_id IS NOT NULL,
 CASE WHEN r.grant_id IS NULL THEN true ELSE
  r.requester_id=g.requester_id AND r.target_id=g.target_id AND r.request_digest=g.request_digest
  AND r.revoker_id<>g.target_id
  AND r.command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
  AND r.command_id<>'AAAAAAAAAAAAAAAAAAAAAA' AND r.command_id<>g.grant_id
  AND r.before_version=CASE WHEN a.grant_id IS NULL THEN g.version ELSE 3 END
  AND r.after_version=r.before_version+1
  AND r.revoked_at>=g.requested_at AND isfinite(r.revoked_at)
  AND r.revoked_at<'10000-01-01 00:00:00+00'::timestamptz
  AND (a.grant_id IS NULL OR r.revoked_at>=a.started_at)
 END,
 s.grant_id IS NOT NULL,
 CASE WHEN s.grant_id IS NULL THEN true ELSE
  s.actor_id=g.requester_id AND s.target_id=g.target_id
  AND s.activation_command_id=a.activation_command_id
  AND s.command_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
  AND s.command_id<>'AAAAAAAAAAAAAAAAAAAAAA'
  AND s.command_id<>g.grant_id AND s.command_id<>a.activation_command_id AND s.command_id<>p.command_id
  AND s.stopped_at>=a.started_at AND s.stopped_at<a.expires_at
 END
 FROM identity_impersonation.grants g
 LEFT JOIN identity_impersonation.approvals p ON p.tenant_id=g.tenant_id AND p.grant_id=g.grant_id
 LEFT JOIN identity_impersonation.active_grants a ON a.tenant_id=g.tenant_id AND a.grant_id=g.grant_id
 LEFT JOIN identity_impersonation.denials d ON d.tenant_id=g.tenant_id AND d.grant_id=g.grant_id
 LEFT JOIN identity_impersonation.revocations r ON r.tenant_id=g.tenant_id AND r.grant_id=g.grant_id
 LEFT JOIN identity_impersonation.stops s ON s.tenant_id=g.tenant_id AND s.grant_id=g.grant_id
 WHERE g.tenant_id=$1 AND g.grant_id=$2`

type quorumSnapshot struct {
	requester, target          string
	requestedAt, expiresAt     time.Time
	state                      string
	version                    int16
	digestValid                bool
	approvalID, approver       sql.NullString
	decidedAt                  sql.NullTime
	approvalBound              bool
	activeState                sql.NullString
	activeVersion              sql.NullInt16
	startedAt, activeExpiresAt sql.NullTime
	activeBound                bool
	denied, denialBound        bool
	revoked, revocationBound   bool
	stopped, stopBound         bool
}

func loadQuorumSnapshot(ctx context.Context, pool *database.Pool, tenant identity.TenantID, grant impersonation.GrantID, now time.Time) (QuorumResult, error) {
	if ctx == nil || pool == nil || !validStoredGrantKey(tenant, grant) || now.IsZero() {
		return QuorumResult{}, invalidStorageInput()
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	rows, err := pool.Raw().Query(bounded, quorumSnapshotSQL, string(tenant), string(grant))
	if err != nil {
		return QuorumResult{}, storageReadError(bounded)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil || bounded.Err() != nil {
			return QuorumResult{}, storageReadError(bounded)
		}
		return QuorumResult{}, identity.ForbiddenError{}
	}
	var snapshot quorumSnapshot
	err = rows.Scan(&snapshot.requester, &snapshot.target, &snapshot.requestedAt, &snapshot.expiresAt,
		&snapshot.state, &snapshot.version, &snapshot.digestValid,
		&snapshot.approvalID, &snapshot.approver, &snapshot.decidedAt, &snapshot.approvalBound,
		&snapshot.activeState, &snapshot.activeVersion, &snapshot.startedAt, &snapshot.activeExpiresAt, &snapshot.activeBound,
		&snapshot.denied, &snapshot.denialBound, &snapshot.revoked, &snapshot.revocationBound, &snapshot.stopped, &snapshot.stopBound)
	if err != nil || rows.Next() || rows.Err() != nil || bounded.Err() != nil {
		return QuorumResult{}, storageReadError(bounded)
	}
	return snapshot.result(grant, now)
}

func (s quorumSnapshot) result(grant impersonation.GrantID, now time.Time) (QuorumResult, error) {
	s.requestedAt, s.expiresAt = s.requestedAt.UTC(), s.expiresAt.UTC()
	if !validStorageID(s.requester) || !validStorageID(s.target) || s.requester == s.target || !s.digestValid ||
		!storageExactTime(s.requestedAt) || !storageExactTime(s.expiresAt) || s.expiresAt.Sub(s.requestedAt) != impersonation.ApprovalLifetime ||
		!s.approvalBound || !s.activeBound || !s.denialBound || !s.revocationBound || !s.stopBound {
		return QuorumResult{}, identity.UnavailableError{}
	}
	approved := s.state == string(impersonation.StatusApproved) && s.version == 2
	pending := s.state == string(impersonation.StatusPendingApproval) && s.version == 1
	if !approved && !pending || s.approvalID.Valid != approved || s.approver.Valid != approved || s.decidedAt.Valid != approved {
		return QuorumResult{}, identity.UnavailableError{}
	}
	result := QuorumResult{GrantID: grant, Status: impersonation.Status(s.state), Approvals: []QuorumApproval{}}
	if approved {
		_, err := identity.ParseCommandID(s.approvalID.String)
		decidedAt := s.decidedAt.Time.UTC()
		if err != nil || s.approvalID.String == string(grant) || !validStorageID(s.approver.String) ||
			s.approver.String == s.requester || s.approver.String == s.target || !storageExactTime(decidedAt) ||
			decidedAt.Before(s.requestedAt) || !decidedAt.Before(s.expiresAt) {
			return QuorumResult{}, identity.UnavailableError{}
		}
		result.Approvals = []QuorumApproval{{ApproverID: identity.UserID(s.approver.String), DecidedAt: decidedAt}}
	}
	if s.denied {
		if !pending || s.activeState.Valid || s.revoked || s.stopped {
			return QuorumResult{}, identity.UnavailableError{}
		}
		result.Status = impersonation.StatusDenied
		return result, nil
	}
	if s.activeState.Valid {
		if !approved {
			return QuorumResult{}, identity.UnavailableError{}
		}
		return s.activeResult(result, now)
	}
	if s.activeVersion.Valid || s.startedAt.Valid || s.activeExpiresAt.Valid || s.stopped {
		return QuorumResult{}, identity.UnavailableError{}
	}
	if s.revoked {
		result.Status = impersonation.StatusRevoked
	} else if !now.Before(s.expiresAt) {
		result.Status = impersonation.StatusExpired
	}
	return result, nil
}

func (s quorumSnapshot) activeResult(result QuorumResult, now time.Time) (QuorumResult, error) {
	startedAt, expiresAt := s.startedAt.Time.UTC(), s.activeExpiresAt.Time.UTC()
	if !s.activeVersion.Valid || !s.startedAt.Valid || !s.activeExpiresAt.Valid ||
		!storageExactTime(startedAt) || !storageExactTime(expiresAt) || !expiresAt.After(startedAt) ||
		expiresAt.Sub(startedAt) > impersonation.MaximumDuration || startedAt.Before(s.decidedAt.Time) || !startedAt.Before(s.expiresAt) {
		return QuorumResult{}, identity.UnavailableError{}
	}
	result.Status = impersonation.Status(s.activeState.String)
	switch result.Status {
	case impersonation.StatusActive:
		if s.activeVersion.Int16 != 3 || s.revoked || s.stopped {
			return QuorumResult{}, identity.UnavailableError{}
		}
		// The request deadline only admits activation; once active, its own
		// exclusive deadline controls expiry (ActivationMigrationSource v2).
		if !now.Before(expiresAt) {
			result.Status = impersonation.StatusExpired
		}
	case impersonation.StatusRevoked:
		if s.activeVersion.Int16 != 4 || !s.revoked || s.stopped {
			return QuorumResult{}, identity.UnavailableError{}
		}
	case impersonation.StatusStopped:
		if s.activeVersion.Int16 != 4 || !s.stopped || s.revoked {
			return QuorumResult{}, identity.UnavailableError{}
		}
	case impersonation.StatusExpired:
		if s.activeVersion.Int16 != 4 || s.revoked || s.stopped {
			return QuorumResult{}, identity.UnavailableError{}
		}
	default:
		return QuorumResult{}, identity.UnavailableError{}
	}
	return result, nil
}
