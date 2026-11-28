//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationQuorumServiceDirectConsumerPostgres(t *testing.T) {
	for _, status := range []impersonation.Status{
		impersonation.StatusPendingApproval,
		impersonation.StatusApproved,
		impersonation.StatusDenied,
		impersonation.StatusRevoked,
	} {
		t.Run(string(status), func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			_, _, cfg, writes, requester, administrator, activation := newM24DenialFixture(t, ctx, pool)
			policy := &m24QuorumAuthorization{base: writes, revision: 1}
			cfg.Authorization = policy
			service := m24Must(NewServiceWithDenial(pool, cfg, activation))
			grantID := requestM24DenialGrant(t, ctx, service, writes, requester)
			policy.grantID = grantID
			var approvals []QuorumApproval
			switch status {
			case impersonation.StatusApproved:
				prepared := m24Must(service.PrepareApproval(ctx, ApproveInput{
					Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
					GrantID: grantID, ExpectedVersion: 1, Network: "192.0.2.12",
					Reason: m24Must(impersonation.NewReason("private distinct administrator approval")),
				}))
				if result := m24Must(service.Execute(ctx, prepared)); result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("approval did not commit", result.Outcome)
				}
				var approver identity.UserID
				var decidedAt time.Time
				if err := pool.Raw().QueryRow(ctx, `SELECT approver_id,decided_at FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, string(administrator.Tenant), string(grantID)).Scan(&approver, &decidedAt); err != nil {
					t.Fatal("read committed approval metadata", err)
				}
				if approver != "approve-admin" || approver == "request-admin" || approver == "target-user" || decidedAt.IsZero() {
					t.Fatal("fixture approval did not retain its distinct administrator and decision time")
				}
				approvals = []QuorumApproval{{ApproverID: approver, DecidedAt: decidedAt}}
			case impersonation.StatusDenied:
				prepared := m24Must(service.PrepareDenial(ctx, DenyInput{
					Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
					GrantID: grantID, ExpectedVersion: 1, Network: "192.0.2.12",
					Reason: m24Must(impersonation.NewReason("private distinct administrator denial")),
				}))
				if result := m24Must(service.Execute(ctx, prepared)); result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("denial did not commit", result.Outcome)
				}
			case impersonation.StatusRevoked:
				prepared := m24Must(service.PrepareRevoke(ctx, RevokeInput{
					Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
					GrantID: grantID, ExpectedVersion: 1, Network: "192.0.2.12",
					Reason: m24Must(impersonation.NewReason("private separate administrator revocation")),
				}))
				if result := m24Must(service.Execute(ctx, prepared)); result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("revocation did not commit", result.Outcome)
				}
			}

			before := snapshotM24QuorumState(t, ctx, pool)
			// The catalog selects a state-neutral read: the ordinary MFA bearer
			// is required, but no mutation synchronizer or command is supplied.
			input := QuorumInput{Tenant: administrator.Tenant, Bearer: administrator.Bearer, GrantID: grantID}
			for range 2 {
				result := m24Must(service.Quorum(ctx, input))
				if result.GrantID != grantID || result.RequiredApprovals != 1 || result.Status != status || len(result.Approvals) != len(approvals) {
					t.Fatal("quorum read lost the exact grant, fixed-one policy or current decision state")
				}
				for i, expected := range approvals {
					if result.Approvals[i].ApproverID != expected.ApproverID || !result.Approvals[i].DecidedAt.Equal(expected.DecidedAt) {
						t.Fatal("quorum read changed the distinct approver or committed decision time")
					}
				}
				assertM24QuorumSafeResult(t, result, administrator.Bearer)
			}
			if policy.checks < 2 {
				t.Fatal("quorum read omitted current explicit grant-read authorization")
			}
			if after := snapshotM24QuorumState(t, ctx, pool); !reflect.DeepEqual(after, before) {
				t.Fatal("quorum read changed persisted grants, sessions, commands, audit, lifecycle or risk state")
			}
			assertM24NoSessionIssuance(t, ctx, pool)
		})
	}
}

func TestImpersonationQuorumServiceFailsClosedPostgres(t *testing.T) {
	for _, variation := range []string{
		"permission", "decision-revision", "requester-without-read-permission", "foreign-tenant",
		"unknown-grant", "malformed-grant", "missing-bearer", "stale-mfa", "withdrawn-authorization", "unselected-profile",
	} {
		t.Run(variation, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			_, _, cfg, writes, requester, administrator, activation := newM24DenialFixture(t, ctx, pool)
			policy := &m24QuorumAuthorization{base: writes, revision: 1}
			cfg.Authorization = policy
			service := m24Must(NewServiceWithDenial(pool, cfg, activation))
			grantID := requestM24DenialGrant(t, ctx, service, writes, requester)
			policy.grantID = grantID
			input := QuorumInput{Tenant: administrator.Tenant, Bearer: administrator.Bearer, GrantID: grantID}
			switch variation {
			case "permission":
				policy.deny = true
			case "decision-revision":
				policy.revision++
			case "requester-without-read-permission":
				input.Bearer = requester.Bearer
			case "foreign-tenant":
				input.Tenant = "foreign-tenant"
			case "unknown-grant":
				input.GrantID = impersonation.GrantID(m24Must(identity.NewCommandID()))
				policy.grantID = input.GrantID
			case "malformed-grant":
				input.GrantID = "not-a-grant"
			case "missing-bearer":
				input.Bearer = authentication.BearerCredential{}
			case "stale-mfa":
				cfg.Session.Validation.Clock = m24QuorumClock{now: time.Now().Add(16 * time.Minute)}
				service = m24Must(NewServiceWithDenial(pool, cfg, activation))
			case "withdrawn-authorization":
				m24Exec(t, ctx, pool, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id='m24-tenant' AND subject_id='approve-admin'`)
			case "unselected-profile":
				service = m24Must(NewServiceWithSelfStop(pool, cfg, activation))
			}
			before := snapshotM24QuorumState(t, ctx, pool)
			result, err := service.Quorum(ctx, input)
			if err == nil || !reflect.DeepEqual(result, QuorumResult{}) {
				t.Fatal("quorum read disclosed metadata for invalid, stale or unauthorized input")
			}
			if after := snapshotM24QuorumState(t, ctx, pool); !reflect.DeepEqual(after, before) {
				t.Fatal("rejected quorum read changed persisted state")
			}
		})
	}
}

func TestImpersonationQuorumServiceConsistentPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	_, _, cfg, writes, requester, administrator, activation := newM24DenialFixture(t, ctx, pool)
	policy := &m24QuorumAuthorization{base: writes, revision: 1}
	cfg.Authorization = policy
	service := m24Must(NewServiceWithDenial(pool, cfg, activation))
	grantID := requestM24DenialGrant(t, ctx, service, writes, requester)
	policy.grantID = grantID
	approvalID := m24Must(identity.NewCommandID())
	prepared := m24Must(service.PrepareApproval(ctx, ApproveInput{
		Authentication: administrator, CommandID: approvalID,
		GrantID: grantID, ExpectedVersion: 1, Network: "192.0.2.12",
		Reason: m24Must(impersonation.NewReason("private distinct administrator approval")),
	}))
	approvalCommitted := false
	policy.beforeAllow = func() error {
		result, err := service.Execute(ctx, prepared)
		approvalCommitted = err == nil && result.Outcome == identity.CommitOutcomeCommitted
		return err
	}
	result := m24Must(service.Quorum(ctx, QuorumInput{Tenant: administrator.Tenant, Bearer: administrator.Bearer, GrantID: grantID}))
	if !approvalCommitted || policy.beforeAllow != nil || result.GrantID != grantID || result.RequiredApprovals != 1 {
		t.Fatal("quorum read did not observe the exact grant around a committed competing approval")
	}
	// Either side of the committed transition is a consistent observation;
	// mixing the earlier status with the later approval is not.
	switch result.Status {
	case impersonation.StatusPendingApproval:
		if len(result.Approvals) != 0 {
			t.Fatal("quorum read combined pending status with a later approval")
		}
	case impersonation.StatusApproved:
		var decidedAt time.Time
		if err := pool.Raw().QueryRow(ctx, `SELECT decided_at FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, string(administrator.Tenant), string(grantID)).Scan(&decidedAt); err != nil {
			t.Fatal("read competing approval time", err)
		}
		if len(result.Approvals) != 1 || result.Approvals[0].ApproverID != "approve-admin" || !result.Approvals[0].DecidedAt.Equal(decidedAt) {
			t.Fatal("quorum read combined approved status with absent or different approval metadata")
		}
	default:
		t.Fatal("quorum read fabricated a status during pending-to-approved transition")
	}
	assertM24QuorumSafeResult(t, result, administrator.Bearer)
	assertM24Grant(t, ctx, pool, identity.CommandID(grantID), "approved", 2, 1)
	assertM24CommandEffects(t, ctx, pool, approvalID, 1)
	assertM24NoSessionIssuance(t, ctx, pool)
}

type m24QuorumAuthorization struct {
	base        *m24DenialAuthorization
	grantID     impersonation.GrantID
	revision    authorization.Revision
	deny        bool
	checks      int
	beforeAllow func() error
}

func (p *m24QuorumAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	r := caller.Request
	if r.Action != "identity.impersonation.quorum" {
		return p.base.Decide(ctx, caller)
	}
	decision := authorization.Decision{Outcome: authorization.Deny, Revision: p.revision}
	if err := ctx.Err(); err != nil {
		return decision, err
	}
	if !p.deny && caller.PolicyRevision == p.base.base.activation.legacy.revision &&
		r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == "approve-admin" &&
		r.Resource.Type == "identity.impersonation.grant" && r.Resource.ID == authorization.ResourceID(p.grantID) {
		p.checks++
		if p.beforeAllow != nil {
			callback := p.beforeAllow
			p.beforeAllow = nil
			if err := callback(); err != nil {
				return decision, err
			}
		}
		decision.Outcome = authorization.Allow
	}
	return decision, nil
}

type m24QuorumClock struct{ now time.Time }

func (c m24QuorumClock) Now() time.Time { return c.now }

func assertM24QuorumSafeResult(t *testing.T, result QuorumResult, bearer authentication.BearerCredential) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("safe quorum metadata could not be serialized", err)
	}
	for _, secret := range []string{
		"private support case request", "private distinct administrator approval",
		"private distinct administrator denial", "private separate administrator revocation", bearer.Token(),
	} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("quorum metadata disclosed a private reason or administrator credential")
		}
	}
}

func snapshotM24QuorumState(t *testing.T, ctx context.Context, pool *database.Pool) []string {
	t.Helper()
	// Keep full fixture projections in memory, without logging credential rows.
	// Equal counts alone would miss session refreshes or grant rewrites.
	tables := []string{
		"identity_impersonation.grants", "identity_impersonation.approvals", "identity_impersonation.active_grants",
		"identity_impersonation.revocations", "identity_impersonation.denials", "identity_impersonation.stop_proofs", "identity_impersonation.stops",
		"session_store.sessions", "session_store.families", "session_store.session_issuances",
		"identity.identity_command_id_claims", "identity.commands",
		"audit.identity_command_bindings", "audit.records", "public.identity_outbox_bindings", "public.outbox_messages",
		"m24_risk.counter_windows", "m24_risk.counter_aliases", "m24_risk.counter_charges", "m24_risk.counter_snapshots",
	}
	state := make([]string, len(tables))
	for i, table := range tables {
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + table + ` r`
		if err := pool.Raw().QueryRow(ctx, query).Scan(&state[i]); err != nil {
			t.Fatal("read quorum fixture state", table, err)
		}
	}
	return state
}
