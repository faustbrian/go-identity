package mfa_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestEmailRecoveryRequiresExplicitCurrentEmptyAuthority(t *testing.T) {
	if err := (mfa.FactorAuthority{}).RequireEmailRecovery("tenant", "user"); err == nil {
		t.Fatal("unknown factor state allowed email-only recovery")
	}
	for _, version := range []uint64{1, math.MaxUint64} {
		s, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: "tenant", UserID: "user", Version: version})
		if err != nil || s.Version() != version || s.RequireEmailRecovery("tenant", "user") != nil {
			t.Fatalf("explicit known-empty authority rejected: %v", err)
		}
		for _, scope := range [][2]string{{"foreign", "user"}, {"tenant", "foreign"}, {"", "user"}} {
			if s.RequireEmailRecovery(identity.TenantID(scope[0]), identity.UserID(scope[1])) == nil {
				t.Fatal("factor authority transferred across subjects")
			}
		}
	}
	for _, count := range []uint32{1, 64} {
		s, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: "tenant", UserID: "user", Version: 1, ActiveFactors: count})
		if err != nil || s.RequireEmailRecovery("tenant", "user") == nil {
			t.Fatalf("enrolled factors degraded to email recovery: %v", err)
		}
	}
}

func TestFactorAuthorityRejectsInvalidStateAndRedacts(t *testing.T) {
	for _, r := range []mfa.AuthorityRecord{
		{}, {TenantID: "tenant", UserID: "user"},
		{TenantID: "tenant", UserID: "user", Version: 1, ActiveFactors: 65},
		{TenantID: "tenant\n", UserID: "user", Version: 1},
		{TenantID: "tenant", UserID: "", Version: 1},
	} {
		s, err := mfa.NewFactorAuthority(r)
		if err == nil || s.Version() != 0 || s.RequireEmailRecovery("tenant", "user") == nil {
			t.Fatal("invalid record produced usable authority")
		}
	}
	r := mfa.AuthorityRecord{TenantID: "private-tenant", UserID: "private-user", Version: 1}
	s, err := mfa.NewFactorAuthority(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{r, s} {
		if strings.Contains(fmt.Sprintf("%+v", value), "private-") {
			t.Fatal("subject leaked through formatting")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("authority serialized as portable client evidence")
		}
	}
}
