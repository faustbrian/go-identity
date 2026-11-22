//go:build integration

package passwordintegration_test

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestNativeUnlinkPrimaryIntegration(t *testing.T) {
	testPrimaryPasswordCredentialIntegration(t, "identity_test", "", "unlink-primary")
}

func testNativeUnlinkPrimary(t *testing.T, ctx context.Context, pool *database.Pool, config passwordpg.ReauthenticationConfig, verification passwordpg.ReauthenticationRequest) {
	t.Helper()
	target := passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.account.unlink", Audience: "unlink-management"}
	config.Targets = append(config.Targets, target)
	config.Verifier.Now = func() time.Time {
		now := time.Now().UTC()
		if now.Nanosecond() == 0 {
			return now.Add(-time.Nanosecond)
		}
		return now
	}
	service, err := passwordpg.NewReauthenticationService(pool, config)
	if err != nil {
		t.Fatal("compose actual password owner:", err)
	}
	verification.Target = target
	issued, err := service.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual unlink-bound password proof:", err)
	}
	origin := issued.Proof.Proof
	if origin.IssuedAt.Nanosecond() != 0 || origin.ExpiresAt.After(origin.IssuedAt.Add(config.TTL)) {
		t.Fatal("password proof is not aligned for immediate whole-second unlink issuance")
	}
	primaryConfig := passwordpg.AccountUnlinkPrimaryConfig{Audience: target.Audience, MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer}
	primary, err := passwordpg.NewAccountUnlinkPrimarySource(service, primaryConfig)
	if err != nil {
		t.Fatal("compose original unlink primary:", err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	user := identity.UserID(issued.Proof.Proof.Subject)
	// A social account ID is not an identifier ID. The typed account scope,
	// not the prior email/identifier transport, owns the record namespace.
	const accountID = "github-account"
	spec := identity.AccountUnlinkPreparationCommand{
		Binding: identity.CommandBinding{
			CommandID: id, TenantID: verification.TenantID, UserID: user,
			ActorID: identity.ActorID(user), ActorKind: verification.Caller.Request.Subject.Kind,
			OperationID: target.Action, SchemaID: "identity-account", SchemaVersion: 1,
			PolicyID: "users", PolicyVersion: 9, RecordID: accountID, CorrelationID: string(id),
		},
		Change: identity.AccountUnlinkChange{
			TenantID: verification.TenantID, UserID: user, AccountID: accountID,
			ExpectedUserVersion: 1, ExpectedAccountVersion: 1, ExpectedSocialLinkVersion: 1, ExpectedCredentialVersion: 1,
		},
		SessionID: issued.Proof.SessionID, SessionVersion: issued.Proof.SessionVersion, Primary: issued.Proof,
		FactorAuthorityVersion: 1,
		Counters: identity.AccountUnlinkCounterContext{
			Network: "192.0.2.1", PreparedAt: time.Now().UTC().Truncate(time.Microsecond), KeyVersions: []uint32{1},
		},
	}
	prepare := func(input identity.AccountUnlinkPreparationCommand) identity.Command {
		t.Helper()
		command, err := identity.NewAccountUnlinkPreparationCommand(input, verification.Session)
		if err != nil {
			t.Fatal("original typed unlink shape:", err)
		}
		return command
	}
	original := prepare(spec)
	admission, err := primary.Prepare(ctx, original, verification.Caller, session.CSRFToken{})
	if err != nil {
		t.Fatal("authentic unlink proof rejected:", err)
	}
	captured, err := admission.Original()
	bindings, bindingErr := captured.Bindings()
	deadline, deadlineErr := admission.Deadline()
	if err != nil || bindingErr != nil || deadlineErr != nil || bindings.SessionID != issued.Proof.SessionID || !deadline.Equal(issued.Proof.Proof.IssuedAt.Add(primaryConfig.MaximumAge)) {
		t.Fatal("original password or session authority changed")
	}

	modified := spec
	modified.Primary.Proof.ExpiresAt = modified.Primary.Proof.ExpiresAt.Add(time.Second)
	if _, err := primary.Prepare(ctx, prepare(modified), verification.Caller, session.CSRFToken{}); err == nil {
		t.Fatal("metadata not matching the signed primary record was admitted")
	}
	foreign := verification.Caller.Clone()
	foreign.Request.Subject.ID = "other-actor"
	if _, err := primary.Prepare(ctx, original, foreign, session.CSRFToken{}); err == nil {
		t.Fatal("proof crossed actor scope")
	}
	if _, err := primary.Prepare(ctx, identity.Command{}, verification.Caller, session.CSRFToken{}); err == nil {
		t.Fatal("missing typed preparation admitted")
	}
	if err := admission.AdmitPreparation(ctx, kernel.AccountUnlinkPreparationWork{}, nil); err == nil {
		t.Fatal("authentic original proof granted unconditional preparation authority")
	}
	if err := admission.RequireCurrent(ctx, kernel.AccountUnlinkWork{}, nil); err == nil {
		t.Fatal("authentic original proof granted unconditional transaction authority")
	}
	if err := admission.Consume(ctx, kernel.AccountUnlinkWork{}, nil); err == nil {
		t.Fatal("authentic original proof consumed outside its owned mutation")
	}
	var unused bool
	if err := pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NULL FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(issued.Proof.Proof.ID)).Scan(&unused); err != nil || !unused {
		t.Fatal("denied Work changed password proof custody", err)
	}
}
