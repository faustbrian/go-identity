package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOIDCEndSessionBindsExactOriginalSessionAndDeadline(t *testing.T) {
	record, _, profile := identifierSessionFixture(t)
	s, _ := record.Bindings()
	until := s.LastActivityAt.Add(time.Second).UTC().Truncate(time.Microsecond)
	fields, err := OIDCEndSessionFields(record, until)
	if err != nil {
		t.Fatal(err)
	}
	op := oidcEndSessionOperation()
	b := revokeBinding()
	b.TenantID, b.UserID, b.ActorID = s.TenantID, s.UserID, identity.ActorID(s.UserID)
	b.ActorKind, b.RecordID = authorization.SubjectUser, s.SessionID
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	f := identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}
	c, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal(err)
	}
	got, end, err := oidcEndSessionIntent(c)
	wire, _, _ := encodeRecord(record)
	actual, _, _ := encodeRecord(got)
	if err != nil || end != until || !reflect.DeepEqual(wire, actual) {
		t.Fatal("original session/deadline changed", err)
	}
	for name, change := range map[string]func(*identity.FeatureCommandSpec){
		"different session": func(f *identity.FeatureCommandSpec) { f.Binding.RecordID = "other-session" },
		"different user":    func(f *identity.FeatureCommandSpec) { f.Binding.UserID = "another" },
		"service actor":     func(f *identity.FeatureCommandSpec) { f.Binding.ActorKind = authorization.SubjectServiceAccount },
		"different schema":  func(f *identity.FeatureCommandSpec) { f.Binding.SchemaID, f.Operation.SchemaID = "generic", "generic" },
		"missing deadline":  func(f *identity.FeatureCommandSpec) { f.Fields = f.Fields[:len(f.Fields)-1] },
		"extra owned field": func(f *identity.FeatureCommandSpec) {
			f.Fields = append(f.Fields, identity.FeatureField{Name: "oidc.end-session.extra", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := f
			candidate.Fields = append([]identity.FeatureField(nil), f.Fields...)
			change(&candidate)
			command, err := identity.NewFeatureCommand(candidate)
			if err == nil {
				if _, _, err = oidcEndSessionIntent(command); err == nil {
					t.Fatal("rebound logout intent admitted")
				}
			}
		})
	}
	for _, deadline := range []time.Time{{}, s.LastActivityAt, until.Add(time.Nanosecond), s.LastActivityAt.Add(-time.Second), s.LastActivityAt.Add(400 * 24 * time.Hour)} {
		if _, err := OIDCEndSessionFields(record, deadline); err == nil {
			t.Fatal("impossible deadline admitted")
		}
	}
	if _, err := OIDCEndSessionFields(session.Session{}, until); err == nil {
		t.Fatal("missing source admitted")
	}
	e, err := NewOIDCEndSessionEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", e) != "postgres.OIDCEndSessionEffect(redacted)" {
		t.Fatal("configuration disclosed")
	}
	if _, err := json.Marshal(e); err == nil {
		t.Fatal("effect serialized")
	}
	for _, effect := range []*OIDCEndSessionEffect{nil, e} {
		if _, err := effect.Apply(context.Background(), kernel.Work{}, nil, c); err == nil {
			t.Fatal("unowned Apply admitted")
		}
		if err := effect.Check(context.Background(), kernel.Work{}, nil, c); err == nil {
			t.Fatal("unowned Check admitted")
		}
		if _, err := effect.Recover(context.Background(), kernel.RecoveryWork{}, nil, record); err == nil {
			t.Fatal("unowned recovery admitted")
		}
		if err := effect.RequireNotRevoked(context.Background(), kernel.Work{}, nil, record); err == nil {
			t.Fatal("unowned token fence admitted")
		}
	}
}
