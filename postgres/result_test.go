package postgres

import (
	"bytes"
	identity "github.com/faustbrian/go-identity"
	"testing"
	"time"
)

func terminalCreation(t *testing.T) (claimRequest, identity.CommandResult) {
	t.Helper()
	c := codecCreation(t, nil)
	s, _ := c.CreateUser()
	q, e := prepareClaim(c, [32]byte{1})
	if e != nil {
		t.Fatal("terminal claim")
	}
	return q, identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, User: identity.User{ID: s.Binding.UserID, TenantID: s.Binding.TenantID, Status: identity.StatusActive, Version: 1}, AuditEventID: "audit-event"}
}

func TestJournalResultCodec(t *testing.T) {
	q, r := terminalCreation(t)
	encoded, e := encodeJournalResult(q, r)
	if e != nil {
		t.Fatal("valid result encode")
	}
	got, e := decodeJournalResult(q, encoded)
	if e != nil || got.User != r.User || got.Binding != r.Binding || got.AuditEventID != r.AuditEventID {
		t.Fatal("result changed")
	}
	for _, bad := range [][]byte{nil, []byte(`{}`), append(encoded, ' '), append(encoded, encoded...), bytes.Repeat([]byte{'x'}, maxJournalResultBytes+1)} {
		if _, e = decodeJournalResult(q, bad); e == nil {
			t.Fatal("malformed result decoded")
		}
	}
	r.Binding.ActorID = "foreign"
	if _, e = encodeJournalResult(q, r); e == nil {
		t.Fatal("foreign result binding persisted")
	}
	r.Binding = got.Binding
	r.Outcome = identity.CommitOutcomeUnknown
	r.User = identity.User{}
	r.AuditEventID = ""
	if _, e = encodeJournalResult(q, r); e == nil {
		t.Fatal("unknown persisted as terminal")
	}
	r.Outcome = identity.CommitOutcomeNotCommitted
	if _, e = encodeJournalResult(q, r); e != nil {
		t.Fatal("valid abort not encoded")
	}
}

func TestJournalResultFullWidthVersionAndProfile(t *testing.T) {
	_, r := terminalCreation(t)
	r.Binding.OperationID = "identity.user.update-admin"
	r.ExpectedVersion = ^uint64(0) - 1
	r.User.Version = ^uint64(0)
	q := claimRequest{safeFields: cborMap(commandScope(r.Binding))}
	b, e := encodeJournalResult(q, r)
	if e != nil {
		t.Fatal("full width version encode")
	}
	got, e := decodeJournalResult(q, b)
	if e != nil || got.User.Version != r.User.Version || got.ExpectedVersion != r.ExpectedVersion {
		t.Fatal("version lost precision")
	}
	r.Binding.OperationID = "identity.profile.update"
	r.Binding.ActorID = identity.ActorID(r.Binding.UserID)
	r.Profile = &identity.UserProfile{ID: r.User.ID, TenantID: r.User.TenantID, Version: r.User.Version, Name: "synthetic <name>", AdditionalFields: []identity.AttributeUpdate{{Name: "label", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "synthetic\nvalue"}}}}}
	q.safeFields = cborMap(commandScope(r.Binding))
	b, e = encodeJournalResult(q, r)
	if e != nil {
		t.Fatal("profile encode")
	}
	got, e = decodeJournalResult(q, b)
	if e != nil || got.Profile == nil || got.Profile.Name != r.Profile.Name || got.Profile.AdditionalFields[0].Value.Scalar.String != r.Profile.AdditionalFields[0].Value.Scalar.String {
		t.Fatal("profile representation changed")
	}
	// Case-insensitive aliases and duplicate keys are not the owned encoding.
	for _, bad := range [][]byte{bytes.Replace(b, []byte(`"Outcome":`), []byte(`"outcome":`), 1), bytes.Replace(b, []byte(`"Outcome":2`), []byte(`"Outcome":2,"Outcome":2`), 1)} {
		if _, e = decodeJournalResult(q, bad); e == nil {
			t.Fatal("alternate field spelling admitted")
		}
	}
}

func FuzzJournalResult(f *testing.F) {
	b := codecBinding()
	r := identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, User: identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}, AuditEventID: "audit-event"}
	q := claimRequest{safeFields: cborMap(commandScope(b))}
	seed, e := encodeJournalResult(q, r)
	if e != nil {
		f.Fatal("fuzz receipt seed")
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, e := decodeJournalResult(q, data)
		if e != nil {
			return
		}
		encoded, e := encodeJournalResult(q, r)
		if e != nil || !bytes.Equal(encoded, data) {
			t.Fatal("noncanonical successful decode")
		}
	})
}

func TestJournalResultPreservesSubminuteZoneInstant(t *testing.T) {
	_, r := terminalCreation(t)
	r.Binding.OperationID = "identity.profile.update"
	r.Binding.ActorID = identity.ActorID(r.Binding.UserID)
	r.ExpectedVersion = 1
	r.User.Version = 2
	instant := time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("synthetic-subminute", 1))
	r.Profile = &identity.UserProfile{ID: r.User.ID, TenantID: r.User.TenantID, Version: 2, AdditionalFields: []identity.AttributeUpdate{{Name: "instant", Value: identity.AttributeValue{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: instant}}}}}
	q := claimRequest{safeFields: cborMap(commandScope(r.Binding))}
	encoded, e := encodeJournalResult(q, r)
	if e != nil {
		t.Fatal("valid time encode")
	}
	got, e := decodeJournalResult(q, encoded)
	if e != nil || !got.Profile.AdditionalFields[0].Value.Scalar.Time.Equal(instant) {
		t.Fatal("retained instant changed during replay")
	}
	if r.Profile.AdditionalFields[0].Value.Scalar.Time != instant {
		t.Fatal("codec mutated caller-owned receipt")
	}
	for _, bad := range []time.Time{instant.Add(time.Nanosecond), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("synthetic-cross-boundary", -3600))} {
		r.Profile.AdditionalFields[0].Value.Scalar.Time = bad
		if _, e := encodeJournalResult(q, r); e == nil {
			t.Fatal("lossy or out-of-range receipt time encoded")
		}
	}
}
