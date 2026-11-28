//go:build integration

package impersonationpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func TestImpersonationQuorumWithAdmissionPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	_, _, cfg, writes, requester, administrator, activation := newM24DenialFixture(t, ctx, pool)
	policy := &m24QuorumAuthorization{base: writes, revision: 1}
	cfg.Authorization = policy
	service := m24Must(NewServiceWithDenial(pool, cfg, activation))
	grant := requestM24DenialGrant(t, ctx, service, writes, requester)
	policy.grantID = grant
	input := QuorumInput{Tenant: administrator.Tenant, Bearer: administrator.Bearer, GrantID: grant}
	before := snapshotM24QuorumState(t, ctx, pool)

	calls := 0
	allowed := func(bounded context.Context, actor identity.UserID) error {
		calls++
		if _, ok := bounded.Deadline(); !ok || actor != "approve-admin" || policy.checks < calls {
			t.Error("quota ran without a bounded context and the already-authorized actor")
		}
		return nil
	}
	policy.deny = true
	result, err := service.QuorumWithAdmission(ctx, input, allowed)
	if err == nil || calls != 0 || !reflect.DeepEqual(result, QuorumResult{}) {
		t.Fatal("unauthorized input reached quota or returned grant metadata")
	}
	policy.deny = false
	result = m24Must(service.QuorumWithAdmission(ctx, input, allowed))
	if calls != 1 || result.GrantID != grant || result.Status != impersonation.StatusPendingApproval {
		t.Fatal("one admitted read did not return the exact retained grant")
	}
	if result, err := service.QuorumWithAdmission(ctx, input, nil); err == nil || !reflect.DeepEqual(result, QuorumResult{}) {
		t.Fatal("required admission could be omitted")
	}

	// Authorize a well-formed missing ID to distinguish quota ordering from
	// the snapshot's forbidden error. A rejected debit must stop at admission.
	input.GrantID = impersonation.GrantID(m24Must(identity.NewCommandID()))
	policy.grantID = input.GrantID
	rejected := errors.New("test quota rejected")
	result, err = service.QuorumWithAdmission(ctx, input, func(ctx context.Context, actor identity.UserID) error {
		if err := allowed(ctx, actor); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) || calls != 2 || !reflect.DeepEqual(result, QuorumResult{}) {
		t.Fatal("quota rejection was swallowed or returned grant metadata")
	}
	result, err = service.QuorumWithAdmission(ctx, input, func(context.Context, identity.UserID) error {
		panic("private quota diagnostic")
	})
	if !errors.Is(err, identity.UnavailableError{}) || !reflect.DeepEqual(result, QuorumResult{}) {
		t.Fatal("unavailable quota returned a result or its private diagnostics")
	}
	if after := snapshotM24QuorumState(t, ctx, pool); !reflect.DeepEqual(after, before) {
		t.Fatal("gating the quorum read mutated grant or protected workflow state")
	}
}
