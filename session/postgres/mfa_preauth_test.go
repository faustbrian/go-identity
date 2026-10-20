package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type consumedMFAFlowRows struct {
	record       []byte
	clock        *time.Time
	read, closed bool
}

func (r *consumedMFAFlowRows) Next() bool {
	if r.read {
		return false
	}
	r.read = true
	return true
}
func (r *consumedMFAFlowRows) Scan(dest ...any) error {
	if r.clock != nil {
		*dest[0].(*time.Time) = *r.clock
		return nil
	}
	*dest[0].(*[]byte) = bytes.Clone(r.record)
	return nil
}
func (*consumedMFAFlowRows) Err() error { return nil }
func (r *consumedMFAFlowRows) Close()   { r.closed = true }

type consumedMFAFlowQuery struct {
	rows    *consumedMFAFlowRows
	purpose string
	clock   *consumedMFAFlowRows
}

func (q *consumedMFAFlowQuery) Query(_ context.Context, _ string, args ...any) (*consumedMFAFlowRows, error) {
	if len(args) == 0 && q.clock != nil {
		return q.clock, nil
	}
	if len(args) != 10 || args[9] != q.purpose {
		return nil, identity.ForbiddenError{}
	}
	return q.rows, nil
}

func TestMFAOTPConsumedPrimaryUsesOriginalExpiryAndClosesRows(t *testing.T) {
	now := time.Now().UTC()
	s, _ := testPreAuth(t, now).Bindings()
	s.Binding.Intent.Action = "identity.password.signin"
	original, err := session.NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := encodePreAuth(original)
	b := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: s.Binding.Intent.TenantID, AnonymousFlowID: string(s.Binding.ID), ActorID: "actor", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-verify", SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: "correlation"}
	for _, expired := range []bool{false, true} {
		at := now
		if expired {
			at = s.Binding.ExpiresAt
		}
		rows := &consumedMFAFlowRows{record: wire}
		clock := &consumedMFAFlowRows{clock: &at}
		q := &consumedMFAFlowQuery{rows: rows, purpose: s.Binding.Intent.Action, clock: clock}
		err := RequireMFAOTPConsumedPreAuth(t.Context(), q, b, Config{Schema: "session_store", MaximumDuration: time.Second}, original, "AwMDAwMDAwMDAwMDAwMDAw")
		if expired != (err != nil) || !rows.closed || !clock.closed {
			t.Fatal("OTP primary read changed expiry or leaked cursors", err)
		}
	}
	q := &consumedMFAFlowQuery{rows: &consumedMFAFlowRows{record: wire}, purpose: s.Binding.Intent.Action}
	bad := b
	bad.OperationID = "identity.otp.consume"
	if RequireMFAOTPConsumedPreAuth(t.Context(), q, bad, Config{Schema: "session_store", MaximumDuration: time.Second}, original, "AwMDAwMDAwMDAwMDAwMDAw") == nil || q.rows.read {
		t.Fatal("unrelated operation reached consumed MFA primary")
	}
}

func TestMFAConsumedPreAuthPasswordAndMagicLinkOrigins(t *testing.T) {
	now := time.Now().UTC()
	original := testPreAuth(t, now)
	spec, _ := original.Bindings()
	for _, action := range []string{"identity.password.signin", "identity.username.signin", "identity.phone.password-signin", "identity.magic-link.consume", "identity.password.reset.complete"} {
		t.Run(action, func(t *testing.T) {
			spec.Binding.Intent.Action = action
			flow, err := session.NewPreAuthTransaction(spec)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encodePreAuth(flow)
			if err != nil {
				t.Fatal(err)
			}
			rows := &consumedMFAFlowRows{record: wire}
			query := &consumedMFAFlowQuery{rows: rows, purpose: action}
			binding := identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: spec.Binding.Intent.TenantID, AnonymousFlowID: string(spec.Binding.ID)}
			err = requireMFAConsumedPreAuth(context.Background(), query, func(context.Context) (time.Time, error) { return now, nil }, binding, Config{Schema: "session_store", MaximumDuration: time.Second}, flow, "AwMDAwMDAwMDAwMDAwMDAw")
			if action == "identity.password.reset.complete" {
				if err == nil || rows.read {
					t.Fatal("non-signin primary admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("committed signin primary denied", err)
			}
			if !rows.closed {
				t.Fatal("cursor leaked")
			}
		})
	}
}

func TestMFAConsumedPreAuthRequiresOriginalNativeCustody(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := RequireMFAConsumedPreAuth(ctx, kernel.Work{}, nil, identity.Command{}, Config{Schema: "session_store", MaximumDuration: time.Second}, session.PreAuthTransaction{}, "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned browser metadata admitted MFA")
		}
		if err := RequireMFAConsumedPreAuthAttempt(ctx, kernel.MFATOTPAttemptWork{}, nil, Config{Schema: "session_store", MaximumDuration: time.Second}, session.PreAuthTransaction{}, "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned counted attempt admitted browser metadata")
		}
		if err := RequireMFAConsumedPreAuthRecoveryAttempt(ctx, kernel.MFARecoveryAttemptWork{}, nil, Config{Schema: "session_store", MaximumDuration: time.Second}, session.PreAuthTransaction{}, "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned recovery attempt admitted browser metadata")
		}
	}
}
