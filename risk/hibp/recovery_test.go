package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	audit "github.com/faustbrian/go-audit"
)

// This finite in-memory acknowledgement fixture proves recovery composition,
// not process-crash durability. Production must supply a real durable adapter.
type recoveryBuffer struct {
	observationSink
	admission sync.Mutex
	bytes     int
}

func (*recoveryBuffer) BufferLimits() audit.BufferLimits {
	return audit.BufferLimits{MaxRecords: 4, MaxBytes: 64 << 10, MaxBatchRecords: 2}
}

func (b *recoveryBuffer) Append(ctx context.Context, record audit.Record) (audit.AppendResult, error) {
	result, err := b.AppendBatch(ctx, []audit.Record{record})
	if err != nil {
		return audit.AppendResult{}, err
	}
	return result.Results[0], nil
}

func (b *recoveryBuffer) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	b.admission.Lock()
	defer b.admission.Unlock()
	limits, size := b.BufferLimits(), 0
	for _, record := range records {
		encoded, err := audit.CanonicalJSON(record)
		if err != nil {
			return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, err)
		}
		size += len(encoded)
	}
	if len(records) > limits.MaxBatchRecords || len(b.snapshot())+len(records) > limits.MaxRecords || b.bytes+size > limits.MaxBytes {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, errors.New("finite fixture capacity exhausted"))
	}
	result, err := b.observationSink.AppendBatch(ctx, records)
	if err == nil && !b.invalid {
		b.bytes += size
	}
	return result, err
}

func assertSameRecordBytes(t *testing.T, want, got []audit.Record) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatal("record custody count changed")
	}
	for i := range want {
		a, err := audit.CanonicalJSON(want[i])
		if err != nil {
			t.Fatal(err)
		}
		b, err := audit.CanonicalJSON(got[i])
		if err != nil || string(a) != string(b) {
			t.Fatal("recovery rebuilt record identity or canonical bytes")
		}
	}
}

func TestObservedRecoveryRequiresConfirmedBufferAcknowledgement(t *testing.T) {
	for _, primaryOutcome := range []audit.AppendOutcome{audit.AppendRejected, audit.AppendUnknown} {
		for _, bufferState := range []string{"accepted", "rejected", "unknown", "invalid"} {
			for _, malformed := range []bool{false, true} {
				t.Run(fmt.Sprintf("primary-%d-buffer-%s-malformed-%t", primaryOutcome, bufferState, malformed), func(t *testing.T) {
					request := attributedRequest(t, "synthetic-buffered-candidate")
					derived, err := deriveCandidate(context.Background(), request.Candidate, 1024)
					if err != nil {
						t.Fatal(err)
					}
					defer derived.clear()
					client, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
						fmt.Fprintf(w, "%s:17\n", derived.suffix[:])
						if malformed {
							fmt.Fprint(w, "invalid\n")
						}
					})
					primary := &observationSink{fail: audit.NewAppendError(primaryOutcome, errors.New("synthetic primary diagnostic"))}
					buffer := &recoveryBuffer{}
					wantOutcome := audit.AppendCommitted
					switch bufferState {
					case "rejected":
						wantOutcome = audit.AppendRejected
						buffer.fail = audit.NewAppendError(wantOutcome, errors.New("synthetic buffer diagnostic"))
					case "unknown":
						wantOutcome = audit.AppendUnknown
						buffer.fail = audit.NewAppendError(wantOutcome, errors.New("synthetic buffer diagnostic"))
					case "invalid":
						wantOutcome = audit.AppendUnknown
						buffer.invalid = true
					}
					observed, err := NewObservedChecker(client, ObservationConfig{Delivery: audit.RecorderConfig{Sink: primary, Mode: audit.DeliveryDurableBuffer, Buffer: buffer, RecoveryTimeout: time.Second}, AuditTimeout: time.Second})
					if err != nil {
						t.Fatal(err)
					}
					result, err := observed.Check(context.Background(), request)
					if result.Events.AppendOutcome() != wantOutcome {
						t.Fatal("buffer acknowledgement classification lost")
					}
					if bufferState == "accepted" {
						if result.Events.Disposition() != audit.DeliveryBuffered {
							t.Fatal("confirmed recovery lost delivery disposition")
						}
						if !malformed && (err != nil || result.Outcome != OutcomeMatch || result.BreachCount != 17) {
							t.Fatal("confirmed buffering lost positive provider evidence", err)
						}
					} else if !errors.Is(err, ErrAuditUnavailable) || result.Events.Disposition() != 0 {
						t.Fatal("unconfirmed buffering became required delivery", err)
					}
					if malformed && !errors.Is(err, ErrMalformedRange) {
						t.Fatal("recovery erased original provider failure", err)
					}
					if err != nil {
						if result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() {
							t.Fatal("failed recovery exposed usable evidence")
						}
						assertErrorDelivery(t, result, err)
					}
					records := result.Events.Records()
					wantSecondary := "identity.hibp.detect_match"
					if malformed {
						wantSecondary = "identity.hibp.reject_range"
					}
					if len(records) != 2 || records[0].Action() != "identity.hibp.query_range" || records[1].Action() != wantSecondary || records[1].Context().CausationID() != records[0].ID() {
						t.Fatal("recovery lost required logical records or causation")
					}
					assertSameRecordBytes(t, records, primary.snapshot())
					assertSameRecordBytes(t, records, buffer.snapshot())
					// Reconcile by resubmitting retained records, never a new Check.
					retry := &observationSink{}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					_, retryErr := retry.AppendBatch(ctx, records)
					cancel()
					if retryErr != nil {
						t.Fatal(retryErr)
					}
					assertSameRecordBytes(t, records, retry.snapshot())
				})
			}
		}
	}
}

func TestObservedAlertedLossNeverRestoresPositiveOrMalformedEvidence(t *testing.T) {
	for _, alertState := range []string{"accepted", "failed", "timeout"} {
		for _, malformed := range []bool{false, true} {
			t.Run(fmt.Sprintf("alert-%s-malformed-%t", alertState, malformed), func(t *testing.T) {
				request := attributedRequest(t, "synthetic-alerted-candidate")
				derived, err := deriveCandidate(context.Background(), request.Candidate, 1024)
				if err != nil {
					t.Fatal(err)
				}
				defer derived.clear()
				client, _ := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprintf(w, "%s:17\n", derived.suffix[:])
					if malformed {
						fmt.Fprint(w, "invalid\n")
					}
				})
				primary := &observationSink{fail: audit.NewAppendError(audit.AppendUnknown, errors.New("synthetic uncertain delivery"))}
				alerts := 0
				alerter := audit.AlertFunc(func(ctx context.Context, alert audit.DeliveryAlert) error {
					alerts++
					if _, ok := ctx.Deadline(); !ok || alert.Outcome != audit.AppendUnknown {
						t.Error("alert lost bounded authoritative loss classification")
					}
					switch alertState {
					case "failed":
						return errors.New("synthetic alert rejection")
					case "timeout":
						<-ctx.Done()
						return ctx.Err()
					default:
						return nil
					}
				})
				observed, err := NewObservedChecker(client, ObservationConfig{Delivery: audit.RecorderConfig{Sink: primary, Mode: audit.DeliveryFailOpenWithAlert, Alerter: alerter, RecoveryTimeout: time.Millisecond}, AuditTimeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				result, err := observed.Check(context.Background(), request)
				if !errors.Is(err, ErrAuditUnavailable) || result.BreachCount != 0 || !result.ProviderValidUntil.IsZero() || result.Events.AppendOutcome() != audit.AppendUnknown || alerts != 1 {
					t.Fatal("alerted loss became usable evidence or retried privately", err)
				}
				if malformed && !errors.Is(err, ErrMalformedRange) {
					t.Fatal("alerting erased original provider failure", err)
				}
				wantDisposition := audit.DeliveryDisposition(0)
				if alertState == "accepted" {
					wantDisposition = audit.DeliveryProceededAfterAlert
				}
				if result.Events.Disposition() != wantDisposition || len(result.Events.Records()) != 2 {
					t.Fatal("loss receipt falsely confirmed delivery or lost records")
				}
				assertErrorDelivery(t, result, err)
				assertSameRecordBytes(t, result.Events.Records(), primary.snapshot())
			})
		}
	}
}
