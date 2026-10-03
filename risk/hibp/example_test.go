package hibp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	audit "github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	password "github.com/faustbrian/go-password"
)

// Offline fixtures make the example executable without a live provider or a
// real password. Production uses a trusted HTTPS transport and durable audit sink.
type exampleRangeTransport struct{}

func (exampleRangeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.pwnedpasswords.com" || r.URL.RawQuery != "" || len(r.URL.Path) != len("/range/")+5 || !strings.HasPrefix(r.URL.Path, "/range/") || r.Header.Get("Add-Padding") != "true" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength != 0 {
		return nil, errors.New("invalid example range request")
	}
	for _, b := range []byte(strings.TrimPrefix(r.URL.Path, "/range/")) {
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'F') {
			return nil, errors.New("invalid example prefix")
		}
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("00000000000000000000000000000000000:0\n")), Request: r}, nil
}

// This sink confirms fixture receipt only; it does not prove durable storage.
type exampleAuditSink struct{}

func (s exampleAuditSink) Append(ctx context.Context, record audit.Record) (audit.AppendResult, error) {
	result, err := s.AppendBatch(ctx, []audit.Record{record})
	if err != nil {
		return audit.AppendResult{}, err
	}
	return result.Results[0], nil
}

func (exampleAuditSink) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	if err := ctx.Err(); err != nil {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, err)
	}
	result := audit.BatchResult{}
	for _, record := range records {
		result.Results = append(result.Results, audit.AppendResult{RecordID: record.ID(), Status: audit.AppendAccepted})
	}
	return result, nil
}

func ExampleNewObservedChecker() {
	transport, err := httpclient.New(httpclient.Config{Transport: exampleRangeTransport{}})
	if err != nil {
		panic(err)
	}
	defer transport.Close()
	checker, err := hibp.New(hibp.Config{
		UserAgent:  "golib-identity-reference/example (+https://example.com/security)",
		AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour,
		ResponseBytes: 1024, MaxBreachCount: 1_000_000_000,
		OutboundConcurrency: 1, Timeout: 10 * time.Second, PolicyVersion: "v1",
		MaxWaiters: 8, MaxCandidateBytes: 1024, CacheBytes: 1 << 20,
	}, transport, clock.System{})
	if err != nil {
		panic(err)
	}
	client := checker.(*hibp.Client) // New documents its concrete lifecycle owner.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := client.Close(ctx); err != nil {
			panic(err)
		}
	}()
	observed, err := hibp.NewObservedChecker(client, hibp.ObservationConfig{
		Delivery:     audit.RecorderConfig{Sink: exampleAuditSink{}, Mode: audit.DeliveryFailClosed},
		AuditTimeout: time.Second, Telemetry: nil,
	})
	if err != nil {
		panic(err)
	}
	secret, err := password.NewSecret([]byte("synthetic-example-only"))
	if err != nil {
		panic(err)
	}
	defer secret.Destroy() // The checker only borrows; the caller owns destruction.
	command, err := identity.NewCommandID()
	if err != nil {
		panic(err)
	}
	attempt, err := identity.NewPreAuthTransactionID()
	if err != nil {
		panic(err)
	}
	// Real composition obtains attribution from trusted workflow state, never
	// from request headers, free-form subject scope or provider diagnostics.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := observed.Check(ctx, hibp.CheckRequest{
		OperationID: "identity.password.signup", Action: risk.Action("identity.password.signup"),
		TenantID: identity.TenantID(command), Purpose: "create", SubjectScope: "trusted-example-attempt",
		PolicyVersion: "v1", ReplayID: command, Candidate: secret,
		Attribution: &hibp.SecurityAttribution{CommandID: command, CorrelationID: command,
			Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, AttemptID: attempt,
			PolicyID: string(command), PolicyVersion: 1},
	})
	if err != nil {
		if errors.Is(err, hibp.ErrAuditUnavailable) {
			// Keep these same records for the audit adapter's reconciliation;
			// do not rebuild IDs by repeating Check and do not accept the password.
			fmt.Println("audit reconciliation required:", len(result.Events.Records()))
		}
		return // No error-accompanied result is usable password evidence.
	}
	fmt.Println("no match:", result.Outcome == hibp.OutcomeNoMatch)
	fmt.Println("submitted records:", len(result.Events.Records()))
	// Password acceptance still belongs to the consuming risk/password workflow.
	// Output:
	// no match: true
	// submitted records: 1
}
