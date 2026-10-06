package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type revokeTestReader struct{ observed session.SessionObservation }

func (r revokeTestReader) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	return r.observed, nil
}

func revokeRequestFixture(t *testing.T) (session.RevokeOneRequest, *session.SessionService) {
	t.Helper()
	original, _, _ := identifierSessionFixture(t)
	spec, _ := original.Bindings()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, _ := session.NewToken(32)
	spec.Lookup, _ = token.Digest(key, string(spec.TenantID))
	source, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := spec.IssuedAt.Add(time.Second)
	reader := revokeTestReader{session.SessionObservation{Session: source, Current: spec.Authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}}
	service, err := session.NewSessionService(reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: issueTestClock{now: now}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	caller, err := service.Get(context.Background(), session.GetRequest{TenantID: spec.TenantID, Credential: credential})
	if err != nil || !caller.Authenticated {
		t.Fatal("caller fixture", err)
	}
	b := revokeBinding()
	op := session.RevokeOneOperation()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
	command, err := session.NewRevokeOneCommand(b, source)
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.PrepareRevokeOne(caller, command)
	if err != nil {
		t.Fatal(err)
	}
	return request, service
}

func TestNativeRevokeSourceMappingRetainsOriginalAdmission(t *testing.T) {
	request, _ := revokeRequestFixture(t)
	mapped, err := MapRevokeOneRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	target, source, err := nativeRevokeIntent(mapped)
	if err != nil || source == nil || !source.until.Equal(request.ValidUntil()) {
		t.Fatal("source lost", err)
	}
	want, _ := request.Command()
	wp, _ := want.RevokeOne()
	got, _ := target.RevokeOne()
	a, _, _ := encodeRecord(source.record)
	b, _, _ := encodeRecord(request.Caller())
	if string(a) != string(b) || got.Binding != wp.Binding {
		t.Fatal("original source or target changed")
	}
	projection, _ := mapped.Feature()
	for _, mode := range []string{"missing-deadline", "bad-time", "missing-source", "unknown-source"} {
		bad := projection
		bad.Fields = append([]identity.FeatureField(nil), projection.Fields...)
		switch mode {
		case "missing-deadline":
			for i, f := range bad.Fields {
				if f.Name == "caller.valid-until" {
					bad.Fields = append(bad.Fields[:i], bad.Fields[i+1:]...)
					break
				}
			}
		case "bad-time":
			for i, f := range bad.Fields {
				if f.Name == "caller.valid-until" {
					bad.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "not-time"}
				}
			}
		case "missing-source":
			for i, f := range bad.Fields {
				if f.Name == "caller.session.id" {
					bad.Fields = append(bad.Fields[:i], bad.Fields[i+1:]...)
					break
				}
			}
		case "unknown-source":
			bad.Fields = append(bad.Fields, identity.FeatureField{Name: "caller.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		}
		command, e := identity.NewFeatureCommand(bad)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = nativeRevokeIntent(command); e == nil {
			t.Fatal("partial source accepted", mode)
		}
	}
	if _, err := MapRevokeOneRequest(session.RevokeOneRequest{}); err == nil {
		t.Fatal("zero opaque request accepted")
	}
}
