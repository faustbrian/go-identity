package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestAnonymousUpgradeMigrationPreservesSelectedInstalledHistories(t *testing.T) {
	for predecessor := AnonymousAfterBaseIssuance; predecessor <= AnonymousAfterVerificationMFA; predecessor++ {
		prior := AnonymousSigninMigrationSource{Schema: "session_store", Version: 70, Predecessor: predecessor}
		if predecessor >= AnonymousAfterPassword {
			prior.UsernameSignin, prior.PhonePasswordSignin, prior.PhoneOTPSignin = true, true, true
		}
		before, err := prior.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		source := AnonymousUpgradeMigrationSource{AnonymousSignin: prior, Version: 71}
		history, err := source.Load(t.Context())
		if err != nil || len(history) != 1 {
			t.Fatal("forward upgrade suffix", err)
		}
		sql := history[0].UpSQL()
		if history[0].DownSQL() != "" || !strings.Contains(sql, "DROP CONSTRAINT session_issuances_purpose_anonymous_v1") || !strings.Contains(sql, "DROP CONSTRAINT anonymous_disposals_purpose_check") || !strings.Contains(sql, "'identity.anonymous.delete','identity.anonymous.upgrade'") {
			t.Fatal("wrong installed history or destructive downgrade")
		}
		_, purposes, ok := strings.Cut(before[0].UpSQL(), "CHECK(purpose IN(")
		if !ok {
			t.Fatal("fixture predecessor missing purpose set")
		}
		purposes, _, _ = strings.Cut(purposes, "));")
		if !strings.Contains(sql, "CHECK(purpose IN("+purposes+",'identity.anonymous.upgrade'))") {
			t.Fatal("an installed issuance purpose was lost")
		}
		after, err := prior.Load(t.Context())
		if err != nil || after[0].UpSQL() != before[0].UpSQL() || after[0].Checksum() != before[0].Checksum() {
			t.Fatal("installed migration history changed")
		}
	}
	valid := AnonymousUpgradeMigrationSource{AnonymousSignin: AnonymousSigninMigrationSource{Schema: "session_store", Version: 70, Predecessor: AnonymousAfterPassword}, Version: 71}
	for _, invalid := range []AnonymousUpgradeMigrationSource{{}, {AnonymousSignin: valid.AnonymousSignin, Version: 70}, {AnonymousSignin: AnonymousSigninMigrationSource{Schema: "identity", Version: 70, Predecessor: AnonymousAfterPassword}, Version: 71}} {
		if result, err := invalid.Load(t.Context()); err == nil || result != nil {
			t.Fatal("invalid upgrade history admitted")
		}
	}
	if result, err := valid.Load(nil); err == nil || result != nil {
		t.Fatal("nil migration context admitted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := valid.Load(canceled); err == nil || result != nil {
		t.Fatal("canceled migration admitted")
	}
}
