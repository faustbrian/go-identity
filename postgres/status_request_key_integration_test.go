//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

// This exercises primary status storage and native command ownership with the
// same typed SQL audit/outbox seams as testStatusLifecycle, not their adapters.
func TestAdminStatusRequestKeyRetainsOriginalVersionsPostgres(t *testing.T) {
	ctx, pool, repo := newAccountAuthorityStore(t)
	accounts := AccountMigrationSource{Base: CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	history := RequestKeyPreparationMigrationSource{Base: RequestKeyMigrationSource{Base: accounts, Version: 13}, Version: 14}
	installUnlinkPreparationHistory(t, ctx, pool, history)
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version) VALUES('tenant-a','status-key-user','active',41,7)`); err != nil {
		t.Fatal("status preparation fixture", err)
	}

	const userID identity.UserID = "status-key-user"
	const ban = "identity.admin.user-ban"
	const unban = "identity.admin.user-unban"
	denyTarget, denyAdmission := false, false
	targetChecks, admissionChecks := 0, 0
	policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(call context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if _, bounded := call.Deadline(); !bounded {
			t.Error("status permission callback has no deadline")
		}
		r := dc.Request
		if dc.PolicyRevision != 9 || r.Tenant != "tenant-a" || r.Subject.ID != "actor-a" || r.Subject.Kind != authorization.SubjectUser || string(r.Action) != ban && string(r.Action) != unban {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
		}
		denied := true
		switch r.Resource.Type {
		case "identity.user":
			targetChecks++
			denied = denyTarget || r.Resource.ID != authorization.ResourceID(userID)
		case "identity.request-admission":
			admissionChecks++
			denied = denyAdmission || r.Resource.ID != authorization.ResourceID(r.Action)
		}
		outcome := authorization.Allow
		if denied {
			outcome = authorization.Deny
		}
		return authorization.Decision{Outcome: outcome, Revision: 9}, nil
	})}
	requestKeys, err := NewRequestKeyConfig("admin-status-original", [32]byte{3}, policy)
	if err != nil {
		t.Fatal(err)
	}
	config := CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &policy}
	newOwner := func(config CoordinatorConfig) *StatusUnitOfWork {
		t.Helper()
		registry, err := NewContributorRegistry([]Contributor{repo, &domainAuditPhase{}, &domainLifecyclePhase{}})
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := NewCoordinatorWithRequestKeys(pool, registry, config, requestKeys)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := NewStatusUnitOfWork(coordinator, repo, statusFixtureConfig())
		if err != nil {
			t.Fatal(err)
		}
		return owner
	}
	caller := func(operation string) authorization.DecisionContext {
		return authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
			Subject: authorization.Subject{ID: "actor-a", Kind: authorization.SubjectUser}, Tenant: "tenant-a",
			Action: authorization.Action(operation), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(userID)},
		}}
	}
	key := func(raw string) identity.IdempotencyKey {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	assertEffects := func(mappings, commands, cascades, consumers int) {
		t.Helper()
		var gotMappings, gotCommands, gotClaims, gotCascades, gotConsumers, audits, events int
		if err := pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity.request_key_mappings),
(SELECT count(*) FROM identity.commands),
(SELECT count(*) FROM identity.identity_command_id_claims),
(SELECT count(*) FROM identity.status_cascades),
(SELECT count(*) FROM identity.status_consumers),
(SELECT count(*) FROM public.identity_test_audits),
(SELECT count(*) FROM public.identity_test_lifecycle)`).Scan(&gotMappings, &gotCommands, &gotClaims, &gotCascades, &gotConsumers, &audits, &events); err != nil {
			t.Fatal("status preparation effect readback", err)
		}
		if gotMappings != mappings || gotCommands != commands || gotClaims != commands || gotCascades != cascades || gotConsumers != consumers || audits != commands || events != commands {
			t.Fatal("preparation or replay duplicated native effects", gotMappings, gotCommands, gotClaims, gotCascades, gotConsumers, audits, events)
		}
	}
	assertStatus := func(version, authority uint64, status identity.Status) {
		t.Helper()
		state, err := repo.GetStatus(ctx, identity.UserStatusQuery{TenantID: "tenant-a", UserID: userID})
		if err != nil || state.User.Version != version || state.AuthorityVersion != authority || state.User.Status != status {
			t.Fatal("wrong independent current status versions", err)
		}
	}
	storedBan := func() [5]string {
		t.Helper()
		var row [5]string
		if err := pool.Raw().QueryRow(ctx, `SELECT encode(command_id,'hex'),fingerprint_key_version::text,encode(fingerprint,'hex'),encode(request_preparation_identity,'hex'),encode(request_preparation_ciphertext,'hex') FROM identity.request_key_mappings WHERE namespace=$1 AND route_id=$2`, requestKeys.Namespace, ban).Scan(&row[0], &row[1], &row[2], &row[3], &row[4]); err != nil {
			t.Fatal("original status custody readback", err)
		}
		return row
	}
	statusCommand := func(admission AdminStatusKeyAdmission, operation string) identity.Command {
		t.Helper()
		binding := codecBinding()
		binding.CommandID, binding.UserID, binding.OperationID = admission.CommandID, userID, operation
		binding.SchemaID, binding.SchemaVersion = "identity-lifecycle", 1
		target, reason := identity.StatusBanned, "security"
		if operation == unban {
			target, reason = identity.StatusActive, ""
		}
		command, err := identity.NewUserStatusCommand(identity.UserStatusCommand{Binding: binding, ExpectedVersion: admission.ExpectedVersion, ExpectedAuthorityVersion: admission.ExpectedAuthorityVersion, StatusPolicyVersion: 1, TargetStatus: target, Reason: reason})
		if err != nil {
			t.Fatal("native status command", err)
		}
		return command
	}

	owner := newOwner(config)
	banKey := key("status-ban-original")
	banInput := AdminStatusKeyRequest{UserID: userID, Reason: "security"}
	first, err := owner.ResolveAdminStatusKey(ctx, banKey, banInput, caller(ban))
	if err != nil || first.CommandID == "" || first.ExpectedVersion != 41 || first.ExpectedAuthorityVersion != 7 || targetChecks == 0 || admissionChecks == 0 {
		t.Fatal("ban did not preserve the distinct source versions under both permissions", err)
	}
	original := storedBan()
	if original[1] != "1" || original[3] == "" || original[4] == "" {
		t.Fatal("ban preparation lacks original retained-key custody")
	}
	assertEffects(1, 0, 0, 0)
	assertStatus(41, 7, identity.StatusActive)
	command := statusCommand(first, ban)
	committed, err := owner.Execute(ctx, command)
	if err != nil || committed.Outcome != identity.CommitOutcomeCommitted || committed.Revocation == nil || committed.Revocation.AuthorityVersion != 8 {
		t.Fatal("native ban did not advance status", err)
	}
	assertStatus(42, 8, identity.StatusBanned)
	assertEffects(1, 1, 1, 12)

	config.CurrentFingerprintKeyVersion = 2
	config.RetainedFingerprintKeys = map[uint32][32]byte{1: {1}, 2: {2}}
	restarted := newOwner(config)
	again, err := restarted.ResolveAdminStatusKey(ctx, banKey, banInput, caller(ban))
	if err != nil || again != first || storedBan() != original {
		t.Fatal("restart or key rotation recaptured current versions or replaced original custody", err)
	}
	if replay, err := restarted.Execute(ctx, command); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != committed.AuditEventID || replay.Revocation == nil || replay.Revocation.CascadeID != committed.Revocation.CascadeID {
		t.Fatal("native command replay changed the original receipt", err)
	}
	assertEffects(1, 1, 1, 12)

	changed := banInput
	changed.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(30 * time.Minute)
	var conflict identity.ConflictError
	if result, err := restarted.ResolveAdminStatusKey(ctx, banKey, changed, caller(ban)); !errors.As(err, &conflict) || result != (AdminStatusKeyAdmission{}) {
		t.Fatal("changed ban intent disclosed or replaced original preparation", err)
	}
	denyTarget = true
	beforeAdmission := admissionChecks
	for _, rejectedKey := range []identity.IdempotencyKey{banKey, key("status-denied-target")} {
		if result, err := restarted.ResolveAdminStatusKey(ctx, rejectedKey, banInput, caller(ban)); err == nil || result != (AdminStatusKeyAdmission{}) {
			t.Fatal("current target denial disclosed or allocated preparation")
		}
	}
	if admissionChecks != beforeAdmission {
		t.Fatal("request-key permission preceded the denied target permission")
	}
	denyTarget, denyAdmission = false, true
	for _, rejectedKey := range []identity.IdempotencyKey{banKey, key("status-denied-admission")} {
		if result, err := restarted.ResolveAdminStatusKey(ctx, rejectedKey, banInput, caller(ban)); err == nil || result != (AdminStatusKeyAdmission{}) {
			t.Fatal("request-admission denial disclosed or allocated preparation")
		}
	}
	denyAdmission = false
	assertEffects(1, 1, 1, 12)

	unbanKey := key("status-unban-original")
	stale := AdminStatusKeyRequest{UserID: userID, ExpectedVersion: 41}
	if result, err := restarted.ResolveAdminStatusKey(ctx, unbanKey, stale, caller(unban)); !errors.As(err, &conflict) || result != (AdminStatusKeyAdmission{}) {
		t.Fatal("stale unban allocated a mapping or inferred another version", err)
	}
	assertEffects(1, 1, 1, 12)
	unbanInput := AdminStatusKeyRequest{UserID: userID, ExpectedVersion: 42}
	accepted, err := restarted.ResolveAdminStatusKey(ctx, unbanKey, unbanInput, caller(unban))
	if err != nil || accepted.CommandID == "" || accepted.CommandID == first.CommandID || accepted.ExpectedVersion != 42 || accepted.ExpectedAuthorityVersion != 8 {
		t.Fatal("valid unban lost caller version or exact primary authority", err)
	}
	if repeat, err := restarted.ResolveAdminStatusKey(ctx, unbanKey, unbanInput, caller(unban)); err != nil || repeat != accepted {
		t.Fatal("exact unban repeat changed preparation", err)
	}
	assertEffects(2, 1, 1, 12)
	if result, err := restarted.Execute(ctx, statusCommand(accepted, unban)); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("prepared native unban did not commit", err)
	}
	assertStatus(43, 9, identity.StatusActive)
	if repeat, err := restarted.ResolveAdminStatusKey(ctx, unbanKey, unbanInput, caller(unban)); err != nil || repeat != accepted {
		t.Fatal("unban replay was revalidated against later aggregate state", err)
	}
	if repeat, err := restarted.ResolveAdminStatusKey(ctx, banKey, banInput, caller(ban)); err != nil || repeat != first || storedBan() != original {
		t.Fatal("later native status transition rewrote the original ban", err)
	}
	assertEffects(2, 2, 2, 21)
}
