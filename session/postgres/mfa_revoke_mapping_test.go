package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestMFARevocationMappingRetainsCompletionAndPrimary(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		_, record := mfaCompletionMappingFixture(t, csrf)
		s, _ := record.Bindings()
		b := revokeBinding()
		b.CommandID = "CQkJCQkJCQkJCQkJCQkJCQ"
		b.RecordID = s.SessionID
		b.TenantID, b.UserID = s.TenantID, s.UserID
		b.OperationID, b.SchemaID, b.SchemaVersion = session.RevokeOneOperation().OperationID, session.RevokeOneOperation().SchemaID, session.RevokeOneOperation().SchemaVersion
		one, err := session.NewRevokeOneCommand(b, record)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := MapCommand(one)
		if err != nil {
			t.Fatal(err)
		}
		got, err := nativeRevokeOne(mapped)
		if err != nil {
			t.Fatal("MFA revoke reconstruction", err)
		}
		restored, _ := got.RevokeOne()
		a, _, _ := encodeRecord(record)
		z, _, _ := encodeRecord(restored.Session)
		if !bytes.Equal(a, z) {
			t.Fatal("MFA revoke changed primary/completion provenance")
		}
		projection, _ := mapped.Feature()
		projection.Fields = append(projection.Fields, identity.FeatureField{Name: "caller.same-target", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}}, identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: s.LastActivityAt.Add(time.Second).Format(storedTimeLayout)}})
		aliased, err := identity.NewFeatureCommand(projection)
		if err != nil {
			t.Fatal(err)
		}
		_, source, err := nativeRevokeIntent(aliased)
		if err != nil || source == nil {
			t.Fatal("MFA self-target source absent", err)
		}
		z, _, _ = encodeRecord(source.record)
		if !bytes.Equal(a, z) {
			t.Fatal("self-target reference lost original source")
		}
		for _, mode := range []string{"false", "missing-deadline", "mixed-source"} {
			bad := projection
			bad.Fields = append([]identity.FeatureField(nil), projection.Fields...)
			switch mode {
			case "false":
				bad.Fields[len(bad.Fields)-2].Value.Bool = false
			case "missing-deadline":
				bad.Fields = bad.Fields[:len(bad.Fields)-1]
			case "mixed-source":
				f := projection.Fields[0]
				f.Name = "caller." + f.Name
				bad.Fields = append(bad.Fields, f)
			}
			c, err := identity.NewFeatureCommand(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := nativeRevokeIntent(c); err == nil {
				t.Fatal("ambiguous self-target source admitted", mode)
			}
		}
	}
}
