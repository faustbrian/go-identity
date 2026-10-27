package postgres

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOrganizationSelectionMappingRetainsExactSourceAndDeadline(t *testing.T) {
	source, _, _ := identifierSessionFixture(t)
	spec, _ := source.Bindings()
	b := revokeBinding()
	op := session.OrganizationSelectionOperation()
	b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID)
	b.ActorKind, b.RecordID = authorization.SubjectUser, spec.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	selection := session.ActiveOrganizationSelection{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: "organization", Authority: session.AuthorityBinding{ScopeKey: "organization:selected", Version: 9}}
	command, err := session.NewOrganizationSelectionCommand(b, source, selection)
	if err != nil {
		t.Fatal(err)
	}
	until := spec.LastActivityAt.Add(time.Second).UTC().Truncate(time.Microsecond)
	fields, err := OrganizationSelectionFields(command, until)
	if err != nil {
		t.Fatal(err)
	}
	restored, deadline, err := OrganizationSelectionFromFields(b, fields)
	if err != nil || deadline != until {
		t.Fatal("selection changed original deadline", err)
	}
	want, _ := command.Bindings()
	got, _ := restored.Bindings()
	if got.Binding != want.Binding || got.Selection != want.Selection {
		t.Fatal("selection scope changed")
	}
	for _, pair := range [][2]session.Session{{want.Source, got.Source}, {want.Successor, got.Successor}} {
		before, _, err := encodeRecord(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		after, _, err := encodeRecord(pair[1])
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("selection dropped original record/provenance", err)
		}
	}
	for _, bad := range []time.Time{{}, spec.LastActivityAt, until.Add(time.Nanosecond), spec.LastActivityAt.Add(400 * 24 * time.Hour)} {
		if _, err := OrganizationSelectionFields(command, bad); err == nil {
			t.Fatal("selection admitted an impossible deadline")
		}
	}
	for _, bad := range []identity.CommandBinding{
		{},
		func() identity.CommandBinding { copy := b; copy.RecordID = "another-session"; return copy }(),
		func() identity.CommandBinding { copy := b; copy.TenantID = "another-tenant"; return copy }(),
	} {
		if _, _, err := OrganizationSelectionFromFields(bad, fields); err == nil {
			t.Fatal("selection reconstruction crossed bound scope")
		}
	}
	for name, mutate := range map[string]func([]identity.FeatureField) []identity.FeatureField{
		"missing":   func(v []identity.FeatureField) []identity.FeatureField { return v[:len(v)-1] },
		"duplicate": func(v []identity.FeatureField) []identity.FeatureField { return append(v, v[0]) },
		"unknown owned": func(v []identity.FeatureField) []identity.FeatureField {
			return append(v, identity.FeatureField{Name: organizationSelectionPrefix + "permission", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
		"wrong kind": func(v []identity.FeatureField) []identity.FeatureField {
			for i := range v {
				if v[i].Name == organizationSelectionPrefix+"id" {
					v[i].Value = identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}
				}
			}
			return v
		},
		"incomplete clear": func(v []identity.FeatureField) []identity.FeatureField {
			for i := range v {
				if v[i].Name == organizationSelectionPrefix+"id" {
					v[i].Value.Text = ""
				}
			}
			return v
		},
		"inactive scalar": func(v []identity.FeatureField) []identity.FeatureField {
			for i := range v {
				if v[i].Name == organizationSelectionPrefix+"id" {
					v[i].Value.Bool = true
				}
			}
			return v
		},
		"zero epoch": func(v []identity.FeatureField) []identity.FeatureField {
			for i := range v {
				if v[i].Name == organizationSelectionPrefix+"authority-version" {
					v[i].Value.Uint64 = 0
				}
			}
			return v
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]identity.FeatureField(nil), fields...))
			if _, _, err := OrganizationSelectionFromFields(b, candidate); err == nil {
				t.Fatal("malformed selection fields admitted")
			}
		})
	}
}

func FuzzOrganizationSelectionFields(f *testing.F) {
	source, _, _ := identifierSessionFixture(f)
	spec, _ := source.Bindings()
	b := revokeBinding()
	op := session.OrganizationSelectionOperation()
	b.TenantID, b.UserID, b.ActorID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID)
	b.ActorKind, b.RecordID = authorization.SubjectUser, spec.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := session.NewOrganizationSelectionCommand(b, source, session.ActiveOrganizationSelection{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: "organization", Authority: session.AuthorityBinding{ScopeKey: "organization:selected", Version: 9}})
	if err != nil {
		f.Fatal(err)
	}
	until := spec.LastActivityAt.Add(time.Second).UTC().Truncate(time.Microsecond)
	fields, err := OrganizationSelectionFields(command, until)
	if err != nil {
		f.Fatal(err)
	}
	original, _, _ := encodeRecord(source)
	f.Add("id", "other-organization", uint8(0))
	f.Add("authority-key", "organization:other", uint8(0))
	f.Add("unknown", "invalid", uint8(1))
	f.Fuzz(func(t *testing.T, suffix, value string, mode uint8) {
		if len(suffix) > 128 || len(value) > 4096 {
			return
		}
		candidate := append([]identity.FeatureField(nil), fields...)
		for i := range candidate {
			if candidate[i].Name == organizationSelectionPrefix+"id" {
				candidate[i].Name = organizationSelectionPrefix + suffix
				candidate[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: value}
				if mode&1 != 0 {
					candidate[i].Value.Bytes = []byte("inactive")
				}
			}
		}
		restored, deadline, err := OrganizationSelectionFromFields(b, candidate)
		if err != nil {
			return
		}
		got, err := restored.Bindings()
		wire, _, encodeErr := encodeRecord(got.Source)
		if err != nil || encodeErr != nil || deadline != until || !bytes.Equal(wire, original) || got.Binding != b || strings.HasPrefix(suffix, "source-session.") {
			t.Fatal("accepted selection mutation changed its original source or deadline")
		}
	})
}
