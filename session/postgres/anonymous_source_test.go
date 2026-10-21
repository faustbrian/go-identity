package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestAnonymousSourceConservesExactOriginalAndRejectsOtherAuthority(t *testing.T) {
	_, record := anonymousSessionMappingFixture(t)
	s, _ := record.Bindings()
	fields, err := AnonymousSourceSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := AnonymousSourceSessionFromFields(s.TenantID, s.UserID, fields)
	if err != nil {
		t.Fatal("original anonymous source rejected", err)
	}
	want, _, _ := encodeRecord(record)
	got, _, _ := encodeRecord(restored)
	if !bytes.Equal(want, got) {
		t.Fatal("original session authority/remember/expiry changed")
	}
	for _, q := range []struct {
		tenant identity.TenantID
		user   identity.UserID
	}{{"other-tenant", s.UserID}, {s.TenantID, "other-user"}} {
		r, e := AnonymousSourceSessionFromFields(q.tenant, q.user, fields)
		if e == nil || r != (session.Session{}) {
			t.Fatal("anonymous source crossed scope")
		}
	}
	if f, e := AnonymousSourceSessionFields(testSession(t)); e == nil || f != nil {
		t.Fatal("verified source became anonymous")
	}
	if _, e := OriginalSessionFields(record); e == nil {
		t.Fatal("anonymous source widened verified profile")
	}
	for n := range fields {
		missing := append([]identity.FeatureField(nil), fields[:n]...)
		missing = append(missing, fields[n+1:]...)
		if _, err := AnonymousSourceSessionFromFields(s.TenantID, s.UserID, missing); err == nil {
			t.Fatal("incomplete source admitted", fields[n].Name)
		}
	}
	duplicate := append(append([]identity.FeatureField(nil), fields...), fields[0])
	if _, err := AnonymousSourceSessionFromFields(s.TenantID, s.UserID, duplicate); err == nil {
		t.Fatal("duplicate source field admitted")
	}
	unknown := append(append([]identity.FeatureField(nil), fields...), identity.FeatureField{Name: "anonymous.source-session.unowned", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "unowned"}})
	if _, err := AnonymousSourceSessionFromFields(s.TenantID, s.UserID, unknown); err == nil {
		t.Fatal("unknown source field admitted")
	}
}
