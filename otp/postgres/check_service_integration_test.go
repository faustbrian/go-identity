//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/jackc/pgx/v5"
)

// CHECK-03/04/05/06: public Send issues the actual challenge; the delivered
// encrypted message is opened by the existing task-owned delivery boundary.
// No test-built challenge, continuation, authority or attempt bridges Check.
func testPublicCheckAndRecovery(t *testing.T, ctx context.Context, db *pgx.Conn, sender *SendService, config SendConfig, send otp.SendRequest) {
	t.Helper()
	issued, err := sender.Send(ctx, send)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(issued.CommandID))
	message := persistedSendMessage(t, ctx, db, raw)
	code, err := auth.NewOneTimeCode(message.Body)
	if err != nil {
		t.Fatal("delivered code unavailable")
	}
	queryPolicy := config.RequestKeys.Policy
	coordinator := config.Coordinator
	coordinator.QueryPolicy = &queryPolicy
	service, err := NewCheckService(sender, CheckConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7})
	if err != nil {
		t.Fatal("public check composition", err)
	}
	request := otp.CheckRequest{TenantID: send.TenantID, UserID: send.UserID, Caller: send.Caller, Flow: send.Flow, SendCommandID: issued.CommandID, Code: code}
	operationPolicy := queryPolicy
	operationPolicy.Authorization = checkDenyOperationPolicy{}
	operationCoordinator := coordinator
	operationCoordinator.QueryPolicy = &operationPolicy
	operationDenied, err := NewCheckService(sender, CheckConfig{Coordinator: operationCoordinator, CurrentAttemptKeyVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	if leaked, err := operationDenied.Check(ctx, request); err == nil || leaked.Valid || leaked.CommandID != "" {
		t.Fatal("Send custody read permission substituted for Check permission")
	}
	checked, err := service.Check(ctx, request)
	if err != nil || !checked.Valid || checked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("public correct check", err)
	}
	first, _ := checked.Recovery.Bindings()
	if checked.CommandID == issued.CommandID || first.Attempt.CommandID != checked.CommandID {
		t.Fatal("server attempt identity lost")
	}
	var used, failed, checks int
	var state string
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,checks,state FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(send.TenantID), string(issued.CommandID)).Scan(&used, &failed, &checks, &state); err != nil {
		t.Fatal(err)
	}
	if used != 1 || failed != 0 || checks != 1 || state != "issued" {
		t.Fatal("correct check bypassed metering or consumed challenge")
	}
	restarted, err := NewCheckService(sender, CheckConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	recovery := otp.CheckRecoveryRequest{TenantID: send.TenantID, UserID: send.UserID, Caller: send.Caller, Flow: send.Flow, Recovery: checked.Recovery}
	again, err := restarted.RecoverCheck(ctx, recovery)
	if err != nil || again != checked {
		t.Fatal("recovery changed original result", err)
	}
	var recoveryReaders sync.WaitGroup
	for range 8 {
		recoveryReaders.Go(func() {
			observed, err := restarted.RecoverCheck(ctx, recovery)
			if err != nil || observed != checked {
				t.Error("concurrent recovery changed original outcome")
			}
		})
	}
	recoveryReaders.Wait()
	wrong := request
	wrong.Code, _ = auth.NewOneTimeCode("000000")
	if message.Body == "000000" {
		wrong.Code, _ = auth.NewOneTimeCode("000001")
	}
	denied, err := service.Check(ctx, wrong)
	if err == nil || denied.Valid || denied.Outcome != identity.CommitOutcomeNotCommitted || denied.CommandID == checked.CommandID {
		t.Fatal("wrong submission bypassed metering")
	}
	recovery.Recovery = denied.Recovery
	again, err = restarted.RecoverCheck(ctx, recovery)
	if err == nil || again != denied {
		t.Fatal("denied recovery changed outcome")
	}
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,checks,state FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(send.TenantID), string(issued.CommandID)).Scan(&used, &failed, &checks, &state); err != nil {
		t.Fatal(err)
	}
	if used != 2 || failed != 1 || checks != 2 || state != "issued" {
		t.Fatal("recovery recharged or check consumed")
	}
	if capped, err := service.Check(ctx, request); err == nil || capped.Valid {
		t.Fatal("separate check allowance bypassed")
	}
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,checks,state FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(send.TenantID), string(issued.CommandID)).Scan(&used, &failed, &checks, &state); err != nil {
		t.Fatal(err)
	}
	if used != 2 || failed != 1 || checks != 2 || state != "issued" {
		t.Fatal("check-only cap consumed total allowance or challenge")
	}
	// The retained result is independent of today's challenge state. Revoke
	// through the genuine guarded transition; recovery must not compare anew.
	if _, err := db.Exec(ctx, `UPDATE otp_store.challenges SET state='revoked',version=version+1,terminal_at=clock_timestamp() WHERE tenant_id=$1 AND challenge_id=$2`, string(send.TenantID), string(issued.CommandID)); err != nil {
		t.Fatal(err)
	}
	recovery.Recovery = checked.Recovery
	if again, err := restarted.RecoverCheck(ctx, recovery); err != nil || again != checked {
		t.Fatal("historical result replaced with current challenge state", err)
	}
	denying := queryPolicy
	denying.Authorization = checkDenyPolicy{}
	denyingCoordinator := coordinator
	denyingCoordinator.QueryPolicy = &denying
	denyingService, err := NewCheckService(sender, CheckConfig{Coordinator: denyingCoordinator, CurrentAttemptKeyVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	if leaked, err := denyingService.RecoverCheck(ctx, recovery); err == nil || leaked.CommandID != "" || leaked.Valid {
		t.Fatal("current query denial disclosed receipt")
	}
	changed := recovery
	changed.Caller = recovery.Caller.Clone()
	changed.Caller.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAABA"
	if leaked, err := restarted.RecoverCheck(ctx, changed); err == nil || leaked.CommandID != "" || leaked.Valid {
		t.Fatal("changed actor disclosed receipt")
	}
	tampered := first
	tampered.ExpectedVersion++
	changed = recovery
	changed.Recovery, err = otp.NewCheckRecovery(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if leaked, err := restarted.RecoverCheck(ctx, changed); err == nil || leaked.CommandID != "" || leaked.Valid {
		t.Fatal("changed original plan disclosed receipt")
	}
	badBearer := auth.NewBearerCredential(strings.Repeat("A", 43))
	kind, id, _, _ := send.Flow.Bindings()
	if kind == otp.FlowAuthorizationAuthenticatedSession {
		recovery.Flow, _ = otp.NewSessionSendFlow(id, badBearer)
	} else {
		recovery.Flow, _ = otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(id), badBearer)
	}
	if leaked, err := restarted.RecoverCheck(ctx, recovery); err == nil || leaked.CommandID != "" || leaked.Valid {
		t.Fatal("wrong possession disclosed retained check")
	}
}

type checkDenyPolicy struct{}

func (checkDenyPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, nil
}

type checkDenyOperationPolicy struct{}

func (checkDenyOperationPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	outcome := authorization.Allow
	if c.Request.Action == "identity.otp.check" {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}
