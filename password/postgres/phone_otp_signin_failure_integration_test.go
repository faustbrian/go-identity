//go:build integration

package passwordpostgres

import (
	"context"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

func testPhoneOTPContention(t *testing.T, ctx context.Context, pool *database.Pool, service *otppg.PhoneSigninService, submission otp.SigninRequest, wrong auth.OneTimeCode, mixed bool) otp.SigninResult {
	t.Helper()
	type response struct {
		result otp.SigninResult
		err    error
		wrong  bool
	}
	results := make(chan response, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range 2 {
		workers.Go(func() {
			<-start
			r := submission
			incorrect := mixed && index == 1
			if incorrect {
				r.Code = wrong
			}
			result, err := service.Signin(ctx, r)
			results <- response{result, err, incorrect}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var winner otp.SigninResult
	winners := 0
	for r := range results {
		if r.err == nil && r.result.Issuance.CommitOutcome == identity.CommitOutcomeCommitted && !r.result.Issuance.Replayed {
			if r.wrong {
				t.Fatal("competing wrong phone code issued a session")
			}
			winners++
			winner = r.result
		} else if r.result.Issuance.Token != (session.Token{}) || r.result.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("losing phone submission disclosed credentials")
		}
	}
	_, flowID, _, err := submission.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	var used, failed, finalized, issuances, consumed int
	if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM phone_codes.challenges WHERE challenge_id=$1 AND state='finalized'),(SELECT count(*) FROM signin_sessions.session_issuances WHERE purpose='identity.phone.signin'),(SELECT count(*) FROM signin_sessions.preauth_transactions WHERE flow_id=$2 AND state='consumed') FROM phone_codes.challenges WHERE challenge_id=$1`, string(submission.SendCommandID), flowID).Scan(&used, &failed, &finalized, &issuances, &consumed); err != nil || winners > 1 || !mixed && winners != 1 || used != failed+winners || finalized != winners || issuances != winners || consumed != winners {
		t.Fatal("phone contention violated one-use or exact attempt accounting", winners, used, failed, finalized, issuances, consumed, err)
	}
	return winner
}

func testPhoneOTPLostCommit(t *testing.T, ctx context.Context, pool *database.Pool, config otppg.PhoneSigninConfig, crypto *envelope.Service, submission otp.SigninRequest, wrong auth.OneTimeCode, denial bool) {
	t.Helper()
	marker := ".session_issuances("
	if denial {
		marker = "failed_attempts=$9"
		submission.Code = wrong
	}
	fault := &signinCommitFault{marker: marker}
	faulted, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal("isolated phone OTP commit-fault connection", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := faulted.Close(cleanup); err != nil {
			t.Error("phone OTP fault pool cleanup")
		}
	}()
	service, err := otppg.NewPhoneSigninService(faulted, config, crypto)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := service.Signin(ctx, submission)
	if err == nil || !fault.hit.Load() || unknown.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || unknown.SessionID != "" || unknown.Issuance.Token != (session.Token{}) || unknown.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("real phone OTP commit loss did not preserve unknown credential-free outcome", err)
	}
	var original string
	if !denial {
		if err := pool.Raw().QueryRow(ctx, `SELECT session_id FROM signin_sessions.session_issuances WHERE purpose='identity.phone.signin'`).Scan(&original); err != nil {
			t.Fatal("phone OTP server COMMIT not independently proven", err)
		}
	}
	restarted, err := otppg.NewPhoneSigninService(pool, config, crypto)
	if err != nil {
		t.Fatal(err)
	}
	caller := submission.Caller.Clone()
	caller.Request.Action = "identity.phone.signin.recover"
	recovery := otp.SigninRecoveryRequest{TenantID: submission.TenantID, Caller: caller, Flow: submission.Flow, Recovery: unknown.Recovery}
	submission.Code = auth.OneTimeCode{}
	for range 2 {
		history, err := restarted.RecoverSignin(ctx, recovery)
		if denial {
			if err == nil || history.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || history.SessionID != "" {
				t.Fatal("lost denial acknowledgment changed original counted denial", err)
			}
		} else if err != nil || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || history.SessionID != original || !history.Issuance.Replayed {
			t.Fatal("lost phone commit did not recover its original session identity", err)
		}
		if history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("phone OTP reconciliation redelivered credentials")
		}
		var used, failed, issuances int
		wantFailed, wantIssuances := 0, 1
		if denial {
			wantFailed, wantIssuances = 1, 0
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM signin_sessions.session_issuances WHERE purpose='identity.phone.signin') FROM phone_codes.challenges WHERE challenge_id=$1`, string(submission.SendCommandID)).Scan(&used, &failed, &issuances); err != nil || used != 1 || failed != wantFailed || issuances != wantIssuances {
			t.Fatal("lost phone commit recovery recharged an attempt or duplicated issuance", used, failed, issuances, err)
		}
	}
}
