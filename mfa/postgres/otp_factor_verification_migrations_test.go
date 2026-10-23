package mfapostgres

import (
	"context"
	"testing"
	"time"
)

func TestOTPFactorVerificationHistoryIsAdditiveAndExplicit(t *testing.T) {
	base := MigrationSource{Version: 1}
	before, err := base.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source := OTPFactorVerificationMigrationSource{Base: base, Version: 2}
	history, err := source.Load(t.Context())
	if err != nil || len(history) != len(before)+1 {
		t.Fatal("OTP proof history did not append its owned step", err)
	}
	for i := range before {
		if before[i] != history[i] {
			t.Fatal("OTP proof history rewrote an installed predecessor")
		}
	}
	managed, err := (OTPFactorManagementMigrationSource{Base: source, Version: 3}).Load(t.Context())
	if err != nil || len(managed) != len(history)+1 {
		t.Fatal("OTP management history did not append its owned step", err)
	}
	for i := range history {
		if history[i] != managed[i] {
			t.Fatal("OTP management rewrote existing proof history")
		}
	}
	removed, err := (OTPFactorRemovalMigrationSource{Base: OTPFactorManagementMigrationSource{Base: source, Version: 3}, Version: 4}).Load(t.Context())
	if err != nil || len(removed) != len(managed)+1 {
		t.Fatal("OTP removal history did not append its owned step", err)
	}
	for i := range managed {
		if managed[i] != removed[i] {
			t.Fatal("OTP removal rewrote existing management/proof history")
		}
	}
	for _, bad := range []OTPFactorRemovalMigrationSource{{}, {Base: source, Version: 2}} {
		if _, err := bad.Load(t.Context()); err == nil {
			t.Fatal("missing/conflicting OTP removal history accepted")
		}
	}
	for _, bad := range []OTPFactorVerificationMigrationSource{{}, {Base: base, Version: 1}} {
		if _, err := bad.Load(t.Context()); err == nil {
			t.Fatal("missing/conflicting OTP history accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := source.Load(ctx); err == nil {
		t.Fatal("OTP history ignored cancellation")
	}
	if _, err := (OTPFactorRemovalMigrationSource{Base: source, Version: 4}).Load(ctx); err == nil {
		t.Fatal("OTP removal history ignored cancellation")
	}
}

func TestOTPFactorVerificationSourceRequiresActualPrimary(t *testing.T) {
	if source, err := NewOTPFactorVerificationSource(nil, time.Second); err == nil || source != nil {
		t.Fatal("missing actual primary admitted OTP evidence reads")
	}
}
