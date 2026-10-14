//go:build integration

package reference_test

import (
	"context"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func proveReferenceFactorRemovalLocks(t *testing.T, ctx context.Context, f liveStores, owner mfa.FactorManagementService, original mfa.FactorUpdateRequest) {
	t.Helper()
	var identifier string
	var verifiedAt time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND verified AND kind='email'`, original.TenantID, original.FactorProof.Subject).Scan(&identifier, &verifiedAt); err != nil {
		t.Fatal("original verified recovery row unavailable", err)
	}
	// Observe only lock metadata on this unique owned database; never return
	// SQL argument values or credential material. Both native operations have
	// their normal bounded deadlines, and every test goroutine is joined.
	waitLock := func(stage, pattern string) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			var blocked bool
			if err := f.pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1)`, pattern).Scan(&blocked); err != nil {
				t.Fatal(stage, "bounded recovery lock observation failed")
			}
			if blocked {
				return
			}
			select {
			case <-tick.C:
			case <-bounded.Done():
				t.Fatal(stage, "recovery authority did not retain the required row lock")
			}
		}
	}
	type result struct {
		out mfa.FactorUpdateResult
		err error
	}
	work, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	// Loss wins serialization: SELECT's row-lock recheck must see the newly
	// unverified row, not bless its older MVCC image and erase the last factor.
	loss, err := f.pool.Raw().Begin(work)
	if err != nil {
		t.Fatal(err)
	}
	defer loss.Rollback(context.Background())
	if _, err := loss.Exec(work, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier); err != nil {
		t.Fatal("owned recovery-authority writer unavailable", err)
	}
	first := make(chan result, 1)
	request := original
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("removal-recovery-loss-first"))
	workers.Add(1)
	go func() {
		defer workers.Done()
		out, err := owner.FactorUpdate(work, request)
		first <- result{out, err}
	}()
	waitLock("loss-first", "SELECT i.identifier_id FROM identity.identifiers i%")
	if err := loss.Commit(work); err != nil {
		t.Fatal("owned recovery-authority loss did not commit", err)
	}
	select {
	case observed := <-first:
		if observed.err == nil || observed.out.Outcome == identity.CommitOutcomeCommitted || observed.out.Factor.ID != "" {
			t.Fatal("removal escaped a serialized recovery-path loss")
		}
	case <-work.Done():
		t.Fatal("removal did not finish after recovery lock release")
	}
	var intact bool
	var proofs, effects, active, sets int
	if err := f.pool.Raw().QueryRow(work, `SELECT t.state=2 AND t.encrypted_secret IS NOT NULL,
(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_command_id IS NOT NULL),
(SELECT count(*) FROM identity_mfa.factor_update_effects WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'),
(SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state=2)
FROM identity_mfa.totp_factors t WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, original.TenantID, original.FactorProof.Subject, string(original.FactorID)).Scan(&intact, &proofs, &effects, &active, &sets); err != nil || !intact || proofs != 0 || effects != 0 || active != 2 || sets != 1 {
		t.Fatal("serialized recovery denial changed protected factor/proof/code/session state", err)
	}
	if _, err := f.pool.Raw().Exec(work, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier, verifiedAt); err != nil {
		t.Fatal("owned recovery fixture restoration failed", err)
	}
	// Removal wins serialization: pause the actual protected transaction at its
	// lifecycle insert while it holds recovery share locks. A concurrent email
	// writer must wait until the whole removal commits; no permanent prohibition
	// on subsequent email changes is claimed or installed.
	gate, err := f.pool.Raw().Begin(work)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(context.Background())
	if _, err := gate.Exec(work, `SELECT pg_advisory_xact_lock(873431)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(work, `CREATE FUNCTION public.factor_removal_lock() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(873431); RETURN NEW; END $$; CREATE TRIGGER factor_removal_lock BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.factor_removal_lock()`); err != nil {
		t.Fatal("owned protected-transaction pause unavailable", err)
	}
	second := make(chan result, 1)
	request = original
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("removal-recovery-removal-first"))
	workers.Add(1)
	go func() {
		defer workers.Done()
		out, err := owner.FactorUpdate(work, request)
		second <- result{out, err}
	}()
	waitLock("removal-first lifecycle", "%INSERT INTO public.identity_outbox_bindings%")
	changed := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := f.pool.Raw().Exec(work, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier)
		changed <- err
	}()
	waitLock("removal-first email writer", "UPDATE identity.identifiers SET verified=false%")
	if err := gate.Commit(work); err != nil {
		t.Fatal("owned lifecycle pause release failed", err)
	}
	select {
	case observed := <-second:
		if observed.err != nil || observed.out.Outcome != identity.CommitOutcomeCommitted || observed.out.Factor.State != mfa.FactorRevoked {
			t.Fatal("protected removal failed before the serialized later email change", observed.err)
		}
	case <-work.Done():
		t.Fatal("protected removal did not finish after lifecycle release")
	}
	select {
	case err := <-changed:
		if err != nil {
			t.Fatal("serialized subsequent recovery writer failed", err)
		}
	case <-work.Done():
		t.Fatal("subsequent recovery writer remained blocked")
	}
	if _, err := f.pool.Raw().Exec(work, `DROP TRIGGER factor_removal_lock ON public.identity_outbox_bindings; DROP FUNCTION public.factor_removal_lock()`); err != nil {
		t.Fatal("owned lifecycle pause cleanup failed", err)
	}
}
