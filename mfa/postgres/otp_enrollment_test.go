package mfapostgres

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

func pendingOTPFixture() PendingOTPMetadata {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	return PendingOTPMetadata{TenantID: "tenant-a", UserID: "user-a", FactorID: "AAAAAAAAAAAAAAAAAAAAAQ", IdentifierID: "verified-email", Channel: delivery.ChannelEmail, AuthorityVersion: 1, IdentifierVersion: 2, VerificationVersion: 3, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
}

func TestPendingOTPPreparationRetainsExactBoundedMetadata(t *testing.T) {
	base := pendingOTPFixture()
	p, err := NewPreparedOTPEnrollment(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Metadata()
	if err != nil || got != base {
		t.Fatal("OTP enrollment scope changed")
	}
	fields, err := p.Fields()
	if err != nil || len(fields) == 0 {
		t.Fatal("OTP static intent unavailable")
	}
	fields[0].Value.Text = "foreign"
	again, _ := p.Metadata()
	if again != base {
		t.Fatal("borrowed projection mutated enrollment")
	}
	if fmt.Sprintf("%#v", p) != "mfapostgres.PreparedOTPEnrollment(redacted)" {
		t.Fatal("OTP preparation disclosed identity custody")
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("OTP preparation exported implicitly")
	}
	for _, change := range []func(*PendingOTPMetadata){
		func(m *PendingOTPMetadata) { m.TenantID = "" },
		func(m *PendingOTPMetadata) { m.UserID = "" },
		func(m *PendingOTPMetadata) { m.FactorID = "invalid" },
		func(m *PendingOTPMetadata) { m.IdentifierID = "" },
		func(m *PendingOTPMetadata) { m.Channel = 0 },
		func(m *PendingOTPMetadata) { m.AuthorityVersion = 0 },
		func(m *PendingOTPMetadata) { m.AuthorityVersion = ^uint64(0) },
		func(m *PendingOTPMetadata) { m.IdentifierVersion = 0 },
		func(m *PendingOTPMetadata) { m.VerificationVersion = 0 },
		func(m *PendingOTPMetadata) { m.CreatedAt = m.CreatedAt.Add(time.Nanosecond) },
		func(m *PendingOTPMetadata) { m.ExpiresAt = m.CreatedAt },
		func(m *PendingOTPMetadata) { m.ExpiresAt = m.CreatedAt.Add(16 * time.Minute) },
	} {
		bad := base
		change(&bad)
		if _, err := NewPreparedOTPEnrollment(bad); err == nil {
			t.Fatal("unbounded or incomplete OTP scope accepted")
		}
	}
	if _, err := (PreparedOTPEnrollment{}).Metadata(); err == nil {
		t.Fatal("zero pending OTP custody accepted")
	}
}
