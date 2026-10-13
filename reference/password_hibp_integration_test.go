//go:build integration

package reference_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

// This is observed consumer composition, not live provider interoperability.
// Provider IO and one post-commit acknowledgement are faulted deliberately;
// native audit records persist in PostgreSQL.
func referenceHIBPScreening(t *testing.T, policy risk.Policy, pool *database.Pool, expectedCalls ...int32) passwordpg.ResetScreeningCollector {
	t.Helper()
	type response struct{ suffix, mode string }
	responses := make(map[string]response)
	for _, mode := range []string{"breached", "malformed", "outage", "redirect", "audit-unknown", "new"} {
		// Synthetic fixtures only. Production derivation stays in the owned client.
		digest := sha1.Sum([]byte("synthetic-reference-" + mode + "-password"))
		encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
		responses[encoded[:5]] = response{encoded[5:], mode}
	}
	var calls atomic.Int32
	var lostAcknowledgement atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Host != "api.pwnedpasswords.com" || r.URL.RawQuery != "" || r.Header.Get("Add-Padding") != "true" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.ContentLength > 0 || !strings.HasPrefix(r.URL.Path, "/range/") {
			t.Error("HIBP request disclosed more than the padded prefix protocol")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		row, ok := responses[strings.TrimPrefix(r.URL.Path, "/range/")]
		if !ok {
			t.Error("HIBP request did not derive the exact synthetic candidate prefix")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch row.mode {
		case "breached":
			_, _ = fmt.Fprintf(w, "%s:17\r\n", row.suffix)
		case "malformed":
			_, _ = w.Write([]byte("not-a-range-row\n"))
		case "outage":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "redirect":
			w.Header().Set("Location", "https://api.pwnedpasswords.com/disallowed")
			w.WriteHeader(http.StatusFound)
		case "audit-unknown":
			lostAcknowledgement.Store(true)
			_, _ = fmt.Fprintf(w, "%s:0\r\n", row.suffix)
		default:
			// A matching zero-count padding row must not deny a clean candidate.
			_, _ = fmt.Fprintf(w, "%s:0\r\n", row.suffix)
		}
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	httpOwner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := httpOwner.Close(); err != nil {
			t.Error(err)
		}
	})
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-reference/synthetic-test", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1024, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: time.Second, PolicyVersion: "reference-reset-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 1024, DisableCache: true}, httpOwner, clock.System{})
	if err != nil {
		t.Fatal(err)
	}
	owner := checker.(*hibp.Client)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := owner.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	acknowledgements := &referenceHIBPAcknowledgements{store: sink, lost: &lostAcknowledgement}
	observed, err := hibp.NewObservedChecker(owner, hibp.ObservationConfig{Delivery: audit.RecorderConfig{Sink: acknowledgements, Mode: audit.DeliveryFailClosed}, AuditTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := hibp.NewObservedSignalProvider(observed, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		wantCalls, wantReconciliation := int32(6), int32(1)
		if len(expectedCalls) != 0 {
			if len(expectedCalls) != 1 || expectedCalls[0] < 0 || expectedCalls[0] > 1 {
				t.Error("invalid bounded HIBP fixture expectation")
				return
			}
			wantCalls, wantReconciliation = expectedCalls[0], 0
		}
		if calls.Load() != wantCalls || acknowledgements.reconciled.Load() != wantReconciliation {
			t.Error("native screening did not execute each provider case exactly once")
		}
	})
	return func(ctx context.Context, original identity.CommandBinding, challenge string, binding risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		attempt, err := identity.ParsePreAuthTransactionID(challenge)
		if err != nil {
			return nil, err
		}
		if original.ActorKind != authorization.SubjectServiceAccount || binding.Attempt != string(original.CommandID) || binding.Tenant != string(original.TenantID) || string(binding.Operation) != original.OperationID {
			return nil, hibp.ErrInvalidRequest
		}
		correlation, err := identity.ParseCommandID(original.CorrelationID)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: original.OperationID, Action: binding.Operation, TenantID: original.TenantID, ReplayID: original.CommandID, Purpose: "reset", SubjectScope: "password-reset", PolicyVersion: "reference-reset-v1", Candidate: candidate, Attribution: &hibp.SecurityAttribution{CommandID: original.CommandID, CorrelationID: correlation, Actor: audit.ActorInput{Kind: audit.ActorSystem, ID: string(original.ActorID)}, AttemptID: attempt, PolicyID: original.PolicyID, PolicyVersion: original.PolicyVersion}})
		if err != nil {
			var check *hibp.CheckError
			if errors.Is(err, hibp.ErrAuditUnavailable) && errors.As(err, &check) {
				// Preserve the exact original event IDs/bytes through the existing
				// idempotent audit adapter, never by screening again. Reconciliation
				// cannot make this failed screening attempt accept its password.
				reconcile, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				records := check.Events.Records()
				if check.Events.AppendOutcome() != audit.AppendUnknown || len(records) != 1 {
					t.Error("observed collection lost original unknown acknowledgement")
				}
				retried, retryErr := sink.AppendBatch(reconcile, records)
				cancel()
				if retryErr != nil || len(retried.Results) != len(records) {
					t.Error("original observed records were not reconciled", retryErr)
				}
				for i, result := range retried.Results {
					if result.RecordID != records[i].ID() || result.Status != audit.AppendDuplicate {
						t.Error("reconciliation regenerated or changed the original record")
					}
				}
				acknowledgements.reconciled.Add(1)
			}
			return nil, err
		}
		return []risk.Signal{signal}, nil
	}
}

// Only the acknowledgement boundary is faulted: the actual PostgreSQL batch
// commits first. Native idempotent reconciliation must retain its original IDs
// and canonical bytes. This is not a real network-disconnect qualification.
type referenceHIBPAcknowledgements struct {
	store      *auditpg.Store
	lost       *atomic.Bool
	reconciled atomic.Int32
}

func (s *referenceHIBPAcknowledgements) Append(ctx context.Context, record audit.Record) (audit.AppendResult, error) {
	batch, err := s.AppendBatch(ctx, []audit.Record{record})
	if err != nil {
		return audit.AppendResult{}, err
	}
	return batch.Results[0], nil
}

func (s *referenceHIBPAcknowledgements) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	result, err := s.store.AppendBatch(ctx, records)
	if err == nil && s.lost.Swap(false) {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendUnknown, errors.New("synthetic lost acknowledgement"))
	}
	return result, err
}
