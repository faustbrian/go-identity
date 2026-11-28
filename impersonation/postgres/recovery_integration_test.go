//go:build integration

package impersonationpostgres

import (
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestImpersonationServiceExpiredReservationRecoveryPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	service, cfg, requester, _ := newM24ServiceFixture(t, ctx, pool)
	requestID := m24Must(identity.NewCommandID())
	request := m24Must(service.PrepareRequest(ctx, RequestInput{
		Authentication: requester,
		CommandID:      requestID,
		Target:         "target-user",
		Scope:          m24Must(impersonation.NewScope([]string{"address.read", "profile.read"})),
		Reason:         m24Must(impersonation.NewReason("private support case request")),
		Duration:       10 * time.Minute,
		Network:        "192.0.2.11",
	}))
	binding := m24Must(request.Binding())
	cfg.Authorization.(*m24Authorization).recovery[string(requestID)] = binding

	// Leave the original charged reservation without entering mutation Work.
	// Recovery must obtain each native owner's negative evidence, not execute
	// the retained prepared command or infer rollback from lease expiry alone.
	prepared := request.state
	reservation, pending, err := prepared.coordinator.ReserveCommand(ctx, binding, prepared.phase.command, prepared.plan)
	if err != nil || reservation == (kernel.Reservation{}) || pending.Outcome != identity.CommitOutcomeInProgress || pending.Binding != binding {
		t.Fatal("original request did not leave a charged pending reservation", pending.Outcome, err)
	}
	raw := m24Must(base64.RawURLEncoding.DecodeString(string(requestID)))
	readCounters := func() string {
		var retained string
		if err := pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object(
			'charge',(SELECT to_jsonb(c) FROM m24_risk.counter_charges c WHERE command_id=$1),
			'snapshots',(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb) FROM m24_risk.counter_snapshots s WHERE command_id=$1),
			'windows',(SELECT COALESCE(jsonb_agg(to_jsonb(w) ORDER BY to_jsonb(w)::text),'[]'::jsonb) FROM m24_risk.counter_windows w))::text`, raw).Scan(&retained); err != nil {
			t.Fatal("read original charged attempt", err)
		}
		return retained
	}
	originalCounters := readCounters()
	var grants, approvals, events, audits, charges, snapshots int
	if err := pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM identity_impersonation.grants),
		(SELECT count(*) FROM identity_impersonation.approvals),
		(SELECT count(*) FROM public.outbox_messages),
		(SELECT count(*) FROM audit.records),
		(SELECT count(*) FROM m24_risk.counter_charges WHERE command_id=$1),
		(SELECT count(*) FROM m24_risk.counter_snapshots WHERE command_id=$1)`, raw).Scan(&grants, &approvals, &events, &audits, &charges, &snapshots); err != nil || grants != 0 || approvals != 0 || events != 0 || audits != 0 || charges != 1 || snapshots != 4 {
		t.Fatal("reservation created effects beyond its original charged attempt", grants, approvals, events, audits, charges, snapshots, err)
	}

	// The shared fixture also seeds foundation commands with no lease. Restrict
	// expiry to this exact claimed pending command, preserving those null scopes.
	tag, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second'
		WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND state='pending' AND generation=1 AND command_plan IS NOT NULL`, raw, string(binding.TenantID), binding.OperationID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("did not expire exactly the original disposable reservation", err)
	}
	cfg.Policy = m24Must(impersonation.NewPolicy("m24-distinct-admin", 2))
	cfg.Authorization = &m24Authorization{revision: 2, recovery: map[string]identity.CommandBinding{string(requestID): binding}}
	restarted := m24Must(NewService(pool, cfg))
	altered := binding
	altered.PolicyVersion++
	if receipt, err := restarted.Recover(ctx, requester, altered); !errors.Is(err, identity.ForbiddenError{}) || receipt.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("recovery accepted substituted historical policy metadata", receipt.Outcome, err)
	}
	var state string
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.commands WHERE command_id=$1`, raw).Scan(&state); err != nil || state != "pending" {
		t.Fatal("substituted binding settled the original pending command", err)
	}
	recovered, err := restarted.Recover(ctx, requester, binding)
	operation, _ := approvalOperation(requestAction)
	want := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: operation}}
	if !errors.Is(err, identity.UnavailableError{}) || !reflect.DeepEqual(recovered, want) {
		t.Fatal("expired reservation was not authoritatively terminalized without mutation", recovered.Outcome, err)
	}
	assertM24DeniedEffects(t, ctx, pool, requestID)
	if readCounters() != originalCounters {
		t.Fatal("recovery transferred or recounted the original charged attempt")
	}
	repeated, err := restarted.Recover(ctx, requester, binding)
	if !errors.Is(err, identity.UnavailableError{}) || !reflect.DeepEqual(repeated, recovered) {
		t.Fatal("repeated recovery replaced the exact original non-commit receipt", repeated.Outcome, err)
	}
	assertM24DeniedEffects(t, ctx, pool, requestID)
	if readCounters() != originalCounters {
		t.Fatal("repeated recovery changed the original charged attempt")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM identity_impersonation.grants),
		(SELECT count(*) FROM identity_impersonation.approvals),
		(SELECT count(*) FROM public.outbox_messages)`).Scan(&grants, &approvals, &events); err != nil || grants != 0 || approvals != 0 || events != 0 {
		t.Fatal("recovery executed the pending request or emitted its lifecycle", grants, approvals, events, err)
	}
	assertM24NoSessionIssuance(t, ctx, pool)
}
