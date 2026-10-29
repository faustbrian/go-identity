package postgres

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func recordFixture(t testing.TB) (apikey.Configuration, apikey.Record) {
	t.Helper()
	c, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "automation", Revision: 1, State: apikey.ConfigurationActive, Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api", PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: time.Second, ClockUncertainty: time.Millisecond, DecisionRaceBudget: time.Millisecond, Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	o, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	r := apikey.Record{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Owner: o, Version: 3, AuthorityVersion: 4, ConfigurationID: "automation", ConfigurationRevision: 1, Name: "automation", Status: apikey.KeyActive, Grant: []string{"invoice.read"}, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), RootID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", RootVersion: 4, PreviousID: "previous-key", Issuer: "https://issuer.example", Environment: "test", Audience: "resource-api"}
	return c, r
}

func TestDurableRecordPreservesTypedRootAndCannotCarryRawKey(t *testing.T) {
	c, r := recordFixture(t)
	wire, err := encodeRecord(r, c)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeRecord(wire, c)
	if err != nil || restored.ID != r.ID || restored.Owner != r.Owner || restored.RootID != r.RootID || restored.RootVersion != r.RootVersion || restored.AuthorityVersion != r.AuthorityVersion || restored.PreviousID != r.PreviousID || len(restored.Grant) != 1 || restored.Grant[0] != "invoice.read" {
		t.Fatal("durable record changed credential/source bindings")
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(wire), []byte(" {}")...),
		append([]byte(" "), wire...),
		bytes.Replace(wire, []byte(`"Schema":1`), []byte(`"Schema":1,"Secret":"idk_forbidden"`), 1),
		bytes.Replace(wire, []byte(`"RootVersion":4`), []byte(`"RootVersion":5`), 1),
		bytes.Repeat([]byte("x"), maximumRecordBytes+1),
	} {
		if _, err := decodeRecord(bad, c); err == nil {
			t.Fatal("noncanonical, secret-bearing or foreign root record accepted")
		}
	}
}

func FuzzDurableKeyRecordCanonicalBound(f *testing.F) {
	c, record := recordFixture(f)
	wire, err := encodeRecord(record, c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	record.Owner, err = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", Version: 7})
	if err != nil {
		f.Fatal(err)
	}
	wire, err = encodeRecord(record, c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	record.Grant = nil
	for i := range 64 {
		record.Grant = append(record.Grant, fmt.Sprintf("%02d%s", i, strings.Repeat("&", 126)))
	}
	wire, err = encodeRecord(record, c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(`{"Schema":1,"Secret":"forbidden"}`))
	f.Add(bytes.Repeat([]byte("x"), maximumRecordBytes+1))
	f.Fuzz(func(t *testing.T, input []byte) {
		record, err := decodeRecord(input, c)
		if err != nil {
			return
		}
		canonical, err := encodeRecord(record, c)
		if err != nil || len(input) > maximumRecordBytes || !bytes.Equal(input, canonical) || record.Validate(c) != nil {
			t.Fatal("durable record accepted noncanonical, oversized or invalid authority")
		}
	})
}
