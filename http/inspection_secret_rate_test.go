package identityhttp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

type inspectionRatePort interface {
	AdmitInspectionIP(context.Context, identityhttp.NetworkFacts, string) (identityhttp.AuthRateResult, error)
	AdmitInspectionSubject(context.Context, identityhttp.NetworkFacts, identityhttp.ChallengeVerificationRateRequest) (identityhttp.AuthRateResult, error)
}

func TestRepeatedSecretRateChargesEachReadWithoutResettingSharedBudgets(t *testing.T) {
	limiter, backend := secretLimiter(t)
	inspection, ok := any(limiter).(inspectionRatePort)
	if !ok {
		t.Fatal("repeatable secret inspection has no bounded shared admission")
	}
	facts := safeFacts(t, "198.51.100.1")
	r := identityhttp.ChallengeVerificationRateRequest{OperationID: "identity.password.reset-inspect", UserID: "original-user", ChallengeID: "original-grant", ChallengeLifetime: time.Minute}
	var originalIP, originalSubject string
	var bucketKeys [3]string
	for range 2 {
		out, err := inspection.AdmitInspectionIP(t.Context(), facts, r.OperationID)
		if err != nil || !out.Allowed || len(backend.last.Requests) != 1 || backend.last.Requests[0].Policy.Capacity() != 10 || backend.last.Requests[0].Policy.Period() != 10*time.Minute {
			t.Fatal("inspection did not charge the canonical secret IP budget first")
		}
		if originalIP != "" && backend.last.CommandID == originalIP {
			t.Fatal("another inspection reused a prior debit")
		}
		originalIP = backend.last.CommandID
		key := backend.last.Requests[0].Key.String()
		if bucketKeys[0] != "" && key != bucketKeys[0] {
			t.Fatal("fresh inspection reset the shared IP budget")
		}
		bucketKeys[0] = key
		out, err = inspection.AdmitInspectionSubject(t.Context(), facts, r)
		if err != nil || !out.Allowed || len(backend.last.Requests) != 2 || backend.last.Requests[0].Policy.Capacity() != 10 || backend.last.Requests[1].Policy.Capacity() != 5 || backend.last.Requests[1].Policy.Period() != time.Minute {
			t.Fatal("inspection did not charge original subject and challenge")
		}
		if originalSubject != "" && backend.last.CommandID == originalSubject || backend.last.CommandID == originalIP {
			t.Fatal("inspection phases did not retain distinct fresh debit identities")
		}
		originalSubject = backend.last.CommandID
		for i, request := range backend.last.Requests {
			key := request.Key.String()
			if bucketKeys[i+1] != "" && bucketKeys[i+1] != key {
				t.Fatal("fresh inspection reset the shared subject/challenge budget")
			}
			bucketKeys[i+1] = key
		}
	}
	mutation := secretRequest(t)
	mutation.UserID, mutation.ChallengeID, mutation.ChallengeLifetime = r.UserID, r.ChallengeID, r.ChallengeLifetime
	if _, err := limiter.Admit(t.Context(), facts, mutation); err != nil || len(backend.last.Requests) != 3 {
		t.Fatal("existing secret admission changed")
	}
	for i, request := range backend.last.Requests {
		if request.Key.String() != bucketKeys[i] {
			t.Fatal("inspection created independent budgets from existing secret operations")
		}
	}
	before := backend.calls
	if _, err := inspection.AdmitInspectionIP(t.Context(), facts, "identity.password.reset-complete"); !errors.Is(err, identityhttp.ErrInvalidInput) || backend.calls != before {
		t.Fatal("inspection admission widened to a mutation")
	}
	for _, mode := range []int{1, 2, 3, 4, 5} {
		backend.mode = mode
		if out, err := inspection.AdmitInspectionSubject(t.Context(), facts, r); err == nil || out.Allowed {
			t.Fatal("failed inspection admission allowed source disclosure")
		}
	}
	backend.mode = 0
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if out, err := inspection.AdmitInspectionIP(cancelled, facts, r.OperationID); err == nil || out.Allowed {
		t.Fatal("cancelled inspection was admitted")
	}
	if err := limiter.Close(); err != nil {
		t.Fatal(err)
	}
	before = backend.calls
	if out, err := inspection.AdmitInspectionSubject(t.Context(), facts, r); err == nil || out.Allowed || backend.calls != before {
		t.Fatal("closed inspection owner performed admission")
	}
}
