package postgres

import (
	"bytes"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func preAuthIssueBinding(record session.PreAuthTransaction) identity.CommandBinding {
	s, _ := record.Bindings()
	op := preAuthIssueOperation()
	return identity.CommandBinding{CommandID: "AgICAgICAgICAgICAgICAg", TenantID: s.Binding.Intent.TenantID, AnonymousFlowID: string(s.Binding.ID), ActorID: "login-service", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, RecordID: string(s.Binding.ID), PolicyID: s.Binding.Intent.PolicyID, PolicyVersion: s.Binding.Intent.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, CorrelationID: "initiation"}
}

func TestPreAuthIssueCommandPreservesOriginalPrivateBinding(t *testing.T) {
	record := testPreAuth(t, time.Date(2026, 10, 7, 0, 0, 0, 123456789, time.UTC))
	binding := preAuthIssueBinding(record)
	command, err := mapPreAuthIssue(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	gotBinding, got, err := nativePreAuthIssue(command)
	if err != nil || gotBinding != binding {
		t.Fatal("original command scope lost", err)
	}
	wantBytes, _ := encodePreAuth(record)
	gotBytes, _ := encodePreAuth(got)
	if !bytes.Equal(wantBytes, gotBytes) {
		t.Fatal("original intent, cookie, timeline or remember policy changed")
	}
	projection, _ := command.Feature()
	for i := range projection.Fields {
		altered, _ := command.Feature()
		altered.Fields = append(altered.Fields[:i], altered.Fields[i+1:]...)
		missing, err := identity.NewFeatureCommand(altered)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = nativePreAuthIssue(missing); err == nil {
			t.Fatal("missing original field admitted", projection.Fields[i].Name)
		}
	}
	projection.Fields = append(projection.Fields, identity.FeatureField{Name: "unexpected", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	extra, err := identity.NewFeatureCommand(projection)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = nativePreAuthIssue(extra); err == nil {
		t.Fatal("unknown field admitted")
	}
}

func TestPreAuthIssueCommandRejectsScopeSubstitution(t *testing.T) {
	record := testPreAuth(t, time.Now().UTC())
	original := preAuthIssueBinding(record)
	for _, alter := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "other" },
		func(b *identity.CommandBinding) { b.AnonymousFlowID = "other" },
		func(b *identity.CommandBinding) { b.RecordID = "other" },
		func(b *identity.CommandBinding) { b.PolicyID = "other" },
		func(b *identity.CommandBinding) { b.PolicyVersion-- },
		func(b *identity.CommandBinding) { b.UserID = "user" },
	} {
		b := original
		alter(&b)
		if _, err := mapPreAuthIssue(b, record); err == nil {
			t.Fatal("substituted issuance scope admitted")
		}
		command, err := mapPreAuthIssue(original, record)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := command.Feature()
		p.Binding = b
		if changed, err := identity.NewFeatureCommand(p); err == nil {
			if _, _, err := nativePreAuthIssue(changed); err == nil {
				t.Fatal("decoded substituted scope admitted")
			}
		}
	}
	if _, err := mapPreAuthIssue(original, session.PreAuthTransaction{}); err == nil {
		t.Fatal("zero flow admitted")
	}
	spec, _ := record.Bindings()
	spec.Version = 2
	changed, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mapPreAuthIssue(original, changed); err == nil {
		t.Fatal("non-original version issued")
	}
	if _, _, err = nativePreAuthIssue(identity.Command{}); err == nil {
		t.Fatal("zero command reconstructed")
	}
}

func TestPreAuthIssueCommandRejectsMalformedOriginalScalars(t *testing.T) {
	flow := testPreAuth(t, time.Date(2026, 10, 7, 0, 0, 0, 123456789, time.UTC))
	command, err := mapPreAuthIssue(preAuthIssueBinding(flow), flow)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		name  string
		value identity.FeatureValue
	}{
		{"cookie.version", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1 << 32}},
		{"remember.choice", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 257}},
		{"flow.version", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 2}},
		{"flow.nonce", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}},
		{"cookie.digest", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: make([]byte, 33)}},
		{"flow.issued", identity.FeatureValue{Kind: identity.FeatureText, Text: "2026-10-07T01:00:00.123456789+01:00"}},
		{"flow.expires", identity.FeatureValue{Kind: identity.FeatureText, Text: "invalid"}},
		{"remember.idle", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
	} {
		p, _ := command.Feature()
		for i := range p.Fields {
			if p.Fields[i].Name == bad.name {
				p.Fields[i].Value = bad.value
			}
		}
		altered, err := identity.NewFeatureCommand(p)
		if err != nil {
			t.Fatal("malformed scalar did not reach native decoder", bad.name, err)
		}
		if _, _, err := nativePreAuthIssue(altered); err == nil {
			t.Fatal("malformed original scalar admitted", bad.name)
		}
	}
}
