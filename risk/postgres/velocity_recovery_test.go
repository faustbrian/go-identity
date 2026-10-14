package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVelocityRecoveryRejectsZeroAndSensitiveSerialization(t *testing.T) {
	for _, cfg := range []VelocityRecoveryConfig{
		{},
		{Journal: VelocityJournal{state: &velocityJournal{}}, MaximumWindow: time.Minute, LeaseDuration: time.Second},
		{Journal: VelocityJournal{state: &velocityJournal{}}, MaximumWindow: time.Hour, LeaseDuration: time.Nanosecond},
		{Journal: VelocityJournal{state: &velocityJournal{}}, MaximumWindow: time.Hour, LeaseDuration: time.Minute + time.Microsecond},
	} {
		if _, err := NewVelocityRecovery(cfg); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	var owner VelocityRecovery
	if _, err := owner.Acquire(context.Background(), "tenant", [16]byte{1}); err == nil {
		t.Fatal("zero recovery admitted")
	}
	if err := owner.CheckLease(context.Background(), VelocityRecoveryLease{}); err == nil {
		t.Fatal("zero lease admitted")
	}
	if _, err := owner.Renew(context.Background(), VelocityRecoveryLease{}); err == nil {
		t.Fatal("zero lease renewed")
	}
	for _, value := range []any{VelocityRecoveryConfig{}, owner, VelocityRecoveryLease{state: &velocityRecoveryLease{tenant: "private-tenant", token: [16]byte{123}}}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("sensitive JSON exposed")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil {
			t.Fatal("sensitive text exposed")
		}
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(verb, value); !strings.Contains(got, "redacted") || strings.Contains(got, "private-tenant") {
				t.Fatal("recovery formatting exposed custody")
			}
		}
	}
}
