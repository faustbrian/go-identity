package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestUsernameSigninMigrationRetainsSelectedPurposeHistory(t *testing.T) {
	for _, profile := range []struct {
		prior UsernameSigninPredecessor
		mfa   bool
		mail  bool
	}{
		{UsernameSigninAfterPassword, false, false},
		{UsernameSigninAfterSignup, false, false},
		{UsernameSigninAfterMagicLink, false, false},
		{UsernameSigninAfterMFA, true, false},
		{UsernameSigninAfterVerification, false, true},
		{UsernameSigninAfterVerification, true, true},
		{UsernameSigninAfterVerificationMFA, true, true},
	} {
		source := UsernameSigninMigrationSource{Schema: "session_store", Version: 99, Predecessor: profile.prior, MFASignin: profile.prior == UsernameSigninAfterVerification && profile.mfa}
		history, err := source.Load(context.Background())
		if err != nil || len(history) != 1 || history[0].Version() != 99 || history[0].DownSQL() != "" || history[0].TransactionMode() != migrations.TransactionModeDefault {
			t.Fatal("invalid forward purpose allocation", err)
		}
		sql := history[0].UpSQL()
		for _, purpose := range []string{"identity.session.issue", "identity.otp.signin", "identity.password.signin", "identity.username.signin"} {
			if !strings.Contains(sql, "'"+purpose+"'") {
				t.Fatal("forward constraint drops an installed required purpose")
			}
		}
		if strings.Contains(sql, "'identity.mfa.totp-verify'") != profile.mfa || strings.Contains(sql, "'identity.email.verification-signin'") != profile.mail || strings.Contains(sql, "'identity.password.signup'") != (profile.prior >= UsernameSigninAfterSignup) || strings.Contains(sql, "'identity.magic-link.consume'") != (profile.prior >= UsernameSigninAfterMagicLink) {
			t.Fatal("forward constraint drops or invents selected predecessor purposes")
		}
		if strings.Contains(sql, "identity.username.signup") {
			t.Fatal("signin suffix unexpectedly enables username signup issuance")
		}
	}
	for _, source := range []UsernameSigninMigrationSource{
		{}, {Schema: "session_store", Version: 1, Predecessor: 2},
		{Schema: "session_store", Version: 1, Predecessor: 9},
		{Schema: "identity", Version: 1, Predecessor: 3},
		{Schema: "session_store", Version: 99, Predecessor: 3, MFASignin: true},
		{Schema: "session_store", Version: ^migrations.Version(0), Predecessor: 3},
	} {
		if history, err := source.Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid username purpose suffix accepted")
		}
	}
	source := UsernameSigninMigrationSource{Schema: "session_store", Version: 99, Predecessor: UsernameSigninAfterPassword}
	if history, err := source.Load(nil); err == nil || history != nil {
		t.Fatal("nil migration context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("purpose migration lost cancellation", err)
	}
}
