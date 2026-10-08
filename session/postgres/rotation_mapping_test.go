package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type rotationObservation session.SessionObservation

func (o rotationObservation) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	return session.SessionObservation(o), nil
}

func TestRotationIntentDigestBindsOriginalDeadlineAndTransport(t *testing.T) {
	request := rotationMappingFixture(t)
	command, err := MapRotationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	want, err := rotationIntentDigest(command)
	if err != nil || want == ([32]byte{}) {
		t.Fatal(err)
	}
	for _, name := range []string{"caller.valid-until", "caller.transport"} {
		projection, _ := command.Feature()
		for i := range projection.Fields {
			f := &projection.Fields[i]
			if f.Name == name {
				if name == "caller.transport" {
					f.Value.Uint64 = uint64(session.CredentialCookie)
				} else {
					f.Value.Text = request.ValidUntil().Add(-time.Nanosecond).Format(storedTimeLayout)
				}
			}
		}
		changed, err := identity.NewFeatureCommand(projection)
		if err != nil {
			t.Fatal(err)
		}
		got, err := rotationIntentDigest(changed)
		if err != nil || got == want {
			t.Fatal("original admission omitted from retained intent", name, err)
		}
	}
}

func TestRotationPlanRequiresExactLifecycleAndAudit(t *testing.T) {
	request := rotationMappingFixture(t)
	command, _ := request.Command()
	r, _ := command.Rotation()
	s, _ := r.Source.Bindings()
	_, _, profile := identifierSessionFixture(t)
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	mapped, err := MapRotationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	op := session.RotateOperation()
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: op}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.rotated.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.refresh", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err := repo.ValidateFeatureCommand(mapped, plan); err != nil {
		t.Fatal("rotation effects not supported", err)
	}
	for _, mode := range []string{"family", "version", "missing-audit", "wrong-audit", "not-required", "unconfigured"} {
		bad := plan
		lifecycle := *plan.Lifecycle
		bad.Lifecycle = &lifecycle
		bad.Audits = append([]kernel.AuditPlan(nil), plan.Audits...)
		owner := repo
		switch mode {
		case "family":
			bad.Lifecycle.EventType = "session_family.revoked.v1"
		case "version":
			bad.Lifecycle.AfterVersion++
		case "missing-audit":
			bad.Audits = nil
		case "wrong-audit":
			bad.Audits[0].EventType = "identity.session.create"
		case "not-required":
			bad.Audits[0].Required = false
		case "unconfigured":
			owner = &Repository{schema: "session_store"}
		}
		if owner.ValidateFeatureCommand(mapped, bad) == nil {
			t.Fatal("misdeclared rotation admitted", mode)
		}
	}
}

func rotationMappingFixture(t *testing.T) session.RotationRequest {
	return rotationMappingCSRFFixture(t, false, false)
}

func rotationMappingCSRFFixture(t *testing.T, sourceCSRF, successorCSRF bool) session.RotationRequest {
	t.Helper()
	source, _, _ := identifierSessionFixture(t)
	spec, _ := source.Bindings()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	spec.Lookup, _ = token.Digest(key, string(spec.TenantID))
	source, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	if sourceCSRF {
		source = withCSRFState(t, source, 9)
	}
	now := spec.LastActivityAt.Add(2 * time.Minute)
	reader, err := session.NewSessionService(rotationObservation{Session: source, Current: spec.Authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: sessionReadClock(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	kind := session.CredentialBearer
	if successorCSRF {
		kind = session.CredentialCookie
	}
	credential, _ := session.NewCredential(kind, token)
	caller, err := reader.Get(context.Background(), session.GetRequest{TenantID: spec.TenantID, Credential: credential})
	if err != nil || !caller.Authenticated {
		t.Fatal("original admission", err)
	}
	next := spec
	next.Version++
	next.LastActivityAt = now
	next.Lookup.Sum[0] ^= 1
	vector, _ := spec.Authority.Bindings()
	vector.Session.Version = next.Version
	next.Authority, _ = session.NewAuthoritySnapshot(vector)
	successor, err := session.NewSession(next)
	if err != nil {
		t.Fatal(err)
	}
	if successorCSRF {
		successor = withCSRFState(t, successor, 10)
	}
	b := revokeBinding()
	op := session.RotateOperation()
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
	command, err := session.NewRotateCommand(b, source, successor)
	if err != nil {
		t.Fatal(err)
	}
	request, err := reader.PrepareRotation(caller, command)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestRotationMappingPreservesExactTransitionAndOriginalDeadline(t *testing.T) {
	request := rotationMappingFixture(t)
	command, _ := request.Command()
	want, _ := command.Rotation()
	if _, err := MapCommand(command); err == nil {
		t.Fatal("structural command replaced original request")
	}
	mapped, err := MapRotationRequest(request)
	if err != nil {
		t.Fatal("rotation intent missing", err)
	}
	restored, until, transport, err := nativeRotationIntent(mapped)
	if err != nil || !until.Equal(request.ValidUntil()) || transport != session.CredentialBearer {
		t.Fatal("original deadline or transport lost", err)
	}
	got, ok := restored.Rotation()
	if !ok || got.Binding != want.Binding {
		t.Fatal("exact command lost")
	}
	for _, pair := range [][2]session.Session{{want.Source, got.Source}, {want.Successor, got.Successor}} {
		a, _, _ := encodeRecord(pair[0])
		b, _, _ := encodeRecord(pair[1])
		if !bytes.Equal(a, b) {
			t.Fatal("exact source/successor altered")
		}
	}
	for _, mode := range []string{"missing", "unknown", "same-digest", "transport", "deadline", "version"} {
		t.Run(mode, func(t *testing.T) {
			bad, _ := mapped.Feature()
			switch mode {
			case "missing":
				bad.Fields = bad.Fields[1:]
			case "unknown":
				bad.Fields = append(bad.Fields, identity.FeatureField{Name: "successor.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "foreign"}})
			default:
				for i := range bad.Fields {
					f := &bad.Fields[i]
					if mode == "same-digest" && f.Name == "successor.lookup.digest" {
						s, _ := want.Source.Bindings()
						f.Value.Bytes = append([]byte(nil), s.Lookup.Sum[:]...)
					}
					if mode == "transport" && f.Name == "caller.transport" {
						f.Value.Uint64 = 99
					}
					if mode == "deadline" && f.Name == "caller.valid-until" {
						s, _ := want.Successor.Bindings()
						f.Value.Text = s.LastActivityAt.Add(21 * time.Second).Format(storedTimeLayout)
					}
					if mode == "version" && f.Name == "successor.version" {
						f.Value.Uint64++
					}
				}
			}
			altered, err := identity.NewFeatureCommand(bad)
			if err == nil {
				if _, _, _, err = nativeRotationIntent(altered); err == nil {
					t.Fatal("malformed transition admitted")
				}
			}
		})
	}
	if _, err = MapRotationRequest(session.RotationRequest{}); err == nil {
		t.Fatal("zero custody mapped")
	}
}
