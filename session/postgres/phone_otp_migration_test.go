package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestPhoneOTPSigninMigrationRejectsInvalidHistory(t *testing.T) {
	for _, source := range []PhoneOTPSigninMigrationSource{
		{}, {Schema: "session_store", Version: 90, Predecessor: 2},
		{Schema: "session_store", Version: 90, Predecessor: 9},
		{Schema: "identity", Version: 90, Predecessor: UsernameSigninAfterPassword},
		{Schema: "session_store", Version: 90, Predecessor: UsernameSigninAfterPassword, MFASignin: true},
	} {
		if result, err := source.Load(context.Background()); err == nil || result != nil {
			t.Fatal("invalid installed phone OTP purpose history accepted")
		}
	}
	source := PhoneOTPSigninMigrationSource{Schema: "session_store", Version: 90, Predecessor: UsernameSigninAfterPassword}
	if result, err := source.Load(nil); err == nil || result != nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := source.Load(ctx); !errors.Is(err, context.Canceled) || result != nil {
		t.Fatal("phone OTP migration lost caller cancellation")
	}
}
