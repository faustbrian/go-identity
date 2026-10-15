package emailhttp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestAddressWirePreservesNativeOmissionVersionsAndActiveSelfScope(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	user := identity.UserID("01K6TAM7DG1G04NMKXBPMVKPHG")
	for _, mode := range []string{"visible", "omitted", "retained-long-value", "tenant", "user", "future", "banned"} {
		t.Run(mode, func(t *testing.T) {
			s := identity.IdentifierProjectionSpec{TenantID: "tenant", UserID: user, IdentifierID: "address-one", ObservedAt: now, Values: identity.IdentifierValuesIncluded, State: identity.IdentifierState{User: identity.User{ID: user, TenantID: "tenant", Status: identity.StatusActive, Version: 11}, AuthorityVersion: 7, Identifiers: []identity.Identifier{{ID: "address-one", UserID: user, Kind: identity.IdentifierEmail, CanonicalValue: "one@example.test", DisplayValue: "One@example.test", Primary: true, Verified: true, Version: 3}}, Verifications: []identity.Verification{{IdentifierID: "address-one", State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Minute), Version: 5}}}}
			if mode == "omitted" {
				s.Values = identity.IdentifierValuesOmitted
			}
			if mode == "future" {
				s.ObservedAt = now.Add(time.Second)
			}
			if mode == "banned" {
				s.State.User.Status = identity.StatusBanned
			}
			if mode == "retained-long-value" {
				s.State.Identifiers[0].CanonicalValue = strings.Repeat("x", 512)
				s.State.Identifiers[0].DisplayValue = strings.Repeat("y", 512)
			}
			p, err := identity.NewIdentifierProjection(s)
			if err != nil {
				t.Fatal(err)
			}
			tenant, target := identity.TenantID("tenant"), user
			if mode == "tenant" {
				tenant = "other"
			}
			if mode == "user" {
				target = "other"
			}
			out, err := addressView(p, tenant, target, now)
			if mode == "banned" {
				admin, e := addressTargetView(p, tenant, target, now, true)
				if e != nil || admin.UserID != user || admin.IdentifierID != "address-one" {
					t.Fatal("administrative blocked-target inspection changed actor authority", e)
				}
			}
			if mode != "visible" && mode != "omitted" && mode != "retained-long-value" {
				if err == nil || out != (AddressView{}) {
					t.Fatal("wire accepted foreign, future or blocked self disclosure")
				}
				return
			}
			if err != nil || out.IdentifierVersion != 3 || out.VerificationVersion != 5 || !out.Primary || !out.Verified || out.UserID != user {
				t.Fatal("wire rewrote primary metadata", err)
			}
			wire, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(wire, []byte("authorityVersion")) || bytes.Contains(wire, []byte("userVersion")) || mode == "omitted" && bytes.Contains(wire, []byte("@example.test")) || mode == "visible" && (out.Canonical != "one@example.test" || out.Display != "One@example.test") {
				t.Fatal("wire bypassed native redaction or exposed authority generations")
			}
			if mode == "retained-long-value" && (out.Canonical != s.State.Identifiers[0].CanonicalValue || out.Display != s.State.Identifiers[0].DisplayValue) {
				t.Fatal("read transport truncated retained native values")
			}
		})
	}
}
