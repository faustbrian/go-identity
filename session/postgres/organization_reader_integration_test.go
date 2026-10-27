//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Only the named organization-owner seam is controlled. Native session/token,
// kernel credential/user/directory and policy reads remain real PostgreSQL.
// Actual organization rows and membership enforcement are its adapter's tests.
type organizationReaderOwner struct {
	observation OrganizationSessionAuthorityObservation
	err         error
	calls       int
	requireErr  error
}

func (a *organizationReaderOwner) ObserveOrganizationSession(context.Context, session.Session) (OrganizationSessionAuthorityObservation, error) {
	a.calls++
	return a.observation, a.err
}
func (a *organizationReaderOwner) RequireOrganizationSession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, session.Session) error {
	return a.requireErr
}

func testOrganizationPasswordReader(t *testing.T, ctx context.Context, pool *database.Pool, c SessionServiceConfig, original session.Session, request session.GetRequest, now time.Time) {
	t.Helper()
	s, _ := original.Bindings()
	vector, _ := s.Authority.Bindings()
	vector.ActiveOrganizationID = "selected-a"
	vector.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:owner-seam-a", Version: 9}}
	s.Authority, _ = session.NewAuthoritySnapshot(vector)
	selected, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _, err := encodeRecord(selected)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	write := func(payload []byte) {
		t.Helper()
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1 WHERE tenant_id=$2 AND session_id=$3`, payload, string(s.TenantID), s.SessionID); err != nil {
			t.Fatal(err)
		}
	}
	write(encoded)
	defer write(before)
	owner := &organizationReaderOwner{observation: OrganizationSessionAuthorityObservation{OrganizationID: vector.ActiveOrganizationID, Authority: vector.Organization.Binding, ReadStartedAt: now.Add(-5 * time.Second), ValidUntil: now.Add(10 * time.Second)}}
	profile := OrganizationPasswordSessionAdmission{Profile: c.Profile, Authority: owner}
	reader, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{Repository: c.Repository, Validation: c.Validation, Admission: SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &c.Profile}, OrganizationPassword: &profile}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Get(ctx, request)
	if err != nil || !got.Authenticated || !got.ValidUntil().Equal(now.Add(10*time.Second-c.Validation.ClockUncertainty)) || owner.calls != 1 {
		t.Fatal("selected primary session lost organization or earlier owner deadline", err)
	}
	stored, _ := got.Session.Bindings()
	observed, _ := stored.Authority.Bindings()
	if observed.ActiveOrganizationID != vector.ActiveOrganizationID || observed.Organization != vector.Organization {
		t.Fatal("read changed original selected organization")
	}
	t.Run("selected caller public revocation", func(t *testing.T) {
		testOrganizationCallerRevocation(t, ctx, pool, c, reader, profile, owner, got, original)
	})
	for _, mode := range []string{"changed epoch", "different key", "different organization", "expired", "renewed", "membership removed", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			originalObservation := owner.observation
			defer func() { owner.observation, owner.err = originalObservation, nil }()
			switch mode {
			case "changed epoch":
				owner.observation.Authority.Version++
			case "different key":
				owner.observation.Authority.ScopeKey = "another"
			case "different organization":
				owner.observation.OrganizationID = "another"
			case "expired":
				owner.observation.ValidUntil = now
			case "renewed":
				owner.observation.ValidUntil = owner.observation.ReadStartedAt.Add(20*time.Second + time.Nanosecond)
			case "membership removed":
				owner.err = session.ErrUnauthenticated
			case "unavailable":
				owner.err = session.ErrUnavailable
			}
			got, err := reader.Get(ctx, request)
			if got.Authenticated || got.Session != (session.Session{}) || mode == "unavailable" && err == nil {
				t.Fatal("selected organization failure fell back or refreshed authority", err)
			}
		})
	}
	write(before)
	owner.err = session.ErrUnavailable
	prior := owner.calls
	if got, err := reader.Get(ctx, request); err != nil || !got.Authenticated || owner.calls != prior {
		t.Fatal("explicitly unselected password unexpectedly required an organization", err)
	}
}

func testOrganizationCallerRevocation(t *testing.T, ctx context.Context, pool *database.Pool, c SessionServiceConfig, reader *session.SessionService, profile OrganizationPasswordSessionAdmission, owner *organizationReaderOwner, caller session.GetResult, original session.Session) {
	t.Helper()
	targetSpec, _ := original.Bindings()
	targetSpec.SessionID = "organization-revocation-target"
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	targetSpec.Lookup, err = token.Digest(c.Validation.LookupKeys[0], string(targetSpec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := targetSpec.Authority.Bindings()
	keys, err := SessionAuthorityKeys(targetSpec.TenantID, targetSpec.UserID, targetSpec.FamilyID, targetSpec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	v.Session.ScopeKey = keys.Session
	targetSpec.Authority, _ = session.NewAuthoritySnapshot(v)
	target, err := session.NewSession(targetSpec)
	if err != nil {
		t.Fatal(err)
	}
	wire, expiry, err := encodeRecord(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,'active',$7,$8,$9,$10::jsonb)`, string(targetSpec.TenantID), targetSpec.SessionID, string(targetSpec.UserID), targetSpec.FamilyID, "1", "1", int64(targetSpec.Lookup.KeyVersion), targetSpec.Lookup.Sum[:], expiry, string(wire)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(targetSpec.TenantID), targetSpec.SessionID); err != nil {
			t.Error("owned target cleanup", err)
		}
	}()
	execution := IssueExecutorConfig{Repository: c.Repository, Profile: IssueAdmissionConfig(c.Profile), Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Authorization: revokeQueryPolicy{}, Clock: c.Validation.Clock, PolicyID: revokeBinding().PolicyID, PolicyVersion: 1, AuditRetentionVersion: 1}
	executor, err := NewRevokeOneExecutor(pool, RevokeOneExecutorConfig{Execution: execution, Sessions: reader, OrganizationPassword: &profile})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() session.RevokeOneRequest {
		t.Helper()
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.CommandID, _ = identity.NewCommandID()
		b.TenantID, b.UserID, b.ActorID, b.RecordID = targetSpec.TenantID, targetSpec.UserID, identity.ActorID(targetSpec.UserID), targetSpec.SessionID
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		command, err := session.NewRevokeOneCommand(b, target)
		if err != nil {
			t.Fatal(err)
		}
		request, err := reader.PrepareRevokeOne(caller, command)
		if err != nil {
			t.Fatal("selected caller preparation", err)
		}
		return request
	}
	// Withdrawal after Get must deny even while caller custody is unexpired.
	owner.requireErr = identity.ForbiddenError{}
	denied, err := executor.ExecuteRevokeOne(ctx, prepare())
	owner.requireErr = nil
	if err == nil || denied.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("late source membership denial was ignored", err)
	}
	stored, err := executor.owned.native.Get(ctx, targetSpec.TenantID, targetSpec.SessionID)
	if err != nil || stored.Revoked || stored.FamilyRevoked {
		t.Fatal("denied selected caller changed target", err)
	}
	result, err := executor.ExecuteRevokeOne(ctx, prepare())
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("selected caller could not revoke distinct target", err)
	}
	stored, err = executor.owned.native.Get(ctx, targetSpec.TenantID, targetSpec.SessionID)
	if err != nil || !stored.Revoked || stored.FamilyRevoked {
		t.Fatal("selected caller revocation missing", err)
	}
	callerSpec, _ := caller.Session.Bindings()
	survivor, err := executor.owned.native.Get(ctx, callerSpec.TenantID, callerSpec.SessionID)
	if err != nil || survivor.Revoked || survivor.FamilyRevoked {
		t.Fatal("distinct target revocation changed caller/family", err)
	}
}
