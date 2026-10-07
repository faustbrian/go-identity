package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestVelocityRecoveryPublicOwnerPairing(t *testing.T) {
	// Only construction is exercised; this private fixture never authorizes IO.
	journal := VelocityJournal{state: &velocityJournal{}}
	issuer, _, _, verifier := risk.NewVelocityRecoveryAuthorities()
	_, _, _, foreignVerifier := risk.NewVelocityRecoveryAuthorities()
	c := VelocityRecoveryConfig{Journal: journal, MaximumWindow: time.Hour, LeaseDuration: time.Second, JournalIssuer: issuer, NativeVerifier: verifier}
	if _, err := NewVelocityRecovery(c); err != nil {
		t.Fatal("paired public recovery owners rejected", err)
	}
	c.NativeVerifier = foreignVerifier
	if _, err := NewVelocityRecovery(c); err == nil {
		t.Fatal("crossed public recovery owners accepted")
	}
	c.NativeVerifier = risk.VelocityNativeVerifier{}
	if _, err := NewVelocityRecovery(c); err == nil {
		t.Fatal("partial public recovery ownership accepted")
	}
	c.JournalIssuer = risk.VelocityJournalIssuer{}
	if _, err := NewVelocityRecovery(c); err != nil {
		t.Fatal("legacy lease/page API construction changed", err)
	}
}

func TestVelocityRecoveryUnconfiguredOwnedReplayDeniesBeforeIO(t *testing.T) {
	r, err := NewVelocityRecovery(VelocityRecoveryConfig{Journal: VelocityJournal{state: &velocityJournal{}}, MaximumWindow: time.Hour, LeaseDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	l := VelocityRecoveryLease{state: &velocityRecoveryLease{owner: r.state}}
	if got, err := r.OwnedLease(context.Background(), l); err == nil || got != (risk.VelocityLease{}) {
		t.Fatal("unconfigured issuance reached primary IO")
	}
	if got, err := r.OwnedHistory(context.Background(), l, risk.VelocityLease{}, VelocityReplayRecord{state: &velocityReplayRecord{owner: r.state}}); err == nil || got != (risk.VelocityHistory{}) {
		t.Fatal("unconfigured history reached primary IO")
	}
	if err := r.RecordApplied(context.Background(), l, risk.VelocityLease{}, risk.VelocityAcknowledgement{}); err == nil {
		t.Fatal("unconfigured effect reached primary IO")
	}
}
