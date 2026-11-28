package impersonationpostgres

import (
	"database/sql"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/impersonation"
)

func TestQuorumSnapshotUsesExactExpiryAndRetainsTerminalState(t *testing.T) {
	requested := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	expires := requested.Add(impersonation.ApprovalLifetime)
	activated := expires.Add(-time.Minute)
	activeExpiry := activated.Add(2 * time.Minute)
	approved := quorumSnapshot{
		requester: "requester", target: "target", requestedAt: requested, expiresAt: expires,
		state: "approved", version: 2, digestValid: true,
		approvalID:    sql.NullString{String: "AgICAgICAgICAgICAgICAg", Valid: true},
		approver:      sql.NullString{String: "approver", Valid: true},
		decidedAt:     sql.NullTime{Time: requested.Add(time.Minute), Valid: true},
		approvalBound: true, activeBound: true, denialBound: true, revocationBound: true, stopBound: true,
	}
	active := approved
	active.activeState = sql.NullString{String: "active", Valid: true}
	active.activeVersion = sql.NullInt16{Int16: 3, Valid: true}
	active.startedAt = sql.NullTime{Time: activated, Valid: true}
	active.activeExpiresAt = sql.NullTime{Time: activeExpiry, Valid: true}
	stopped := active
	stopped.activeState.String, stopped.activeVersion.Int16, stopped.stopped = "stopped", 4, true
	contradiction := stopped
	contradiction.revoked = true
	for _, tc := range []struct {
		name string
		row  quorumSnapshot
		at   time.Time
		want impersonation.Status
	}{
		{"approved immediately before deadline", approved, expires.Add(-time.Microsecond), impersonation.StatusApproved},
		{"approved at exclusive deadline", approved, expires, impersonation.StatusExpired},
		{"active outlives request deadline", active, expires, impersonation.StatusActive},
		{"active at exclusive deadline", active, activeExpiry, impersonation.StatusExpired},
		{"stopped retained after deadline", stopped, activeExpiry, impersonation.StatusStopped},
		{"contradictory terminal markers", contradiction, activeExpiry, impersonation.StatusUnspecified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.row.result("AAAAAAAAAAAAAAAAAAAAAQ", tc.at)
			if got.Status != tc.want || (err != nil) != (tc.want == impersonation.StatusUnspecified) {
				t.Fatalf("status=%q, error=%T; want %q", got.Status, err, tc.want)
			}
		})
	}
}
