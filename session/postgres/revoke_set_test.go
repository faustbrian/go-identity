package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func setRequestFixture(t *testing.T, all, include bool) session.RevokeSetRequest {
	t.Helper()
	original, _, _ := identifierSessionFixture(t)
	spec, _ := original.Bindings()
	b := revokeBinding()
	op := session.RevokeOtherOperation()
	if all {
		op = session.RevokeAllOperation()
	}
	b.OperationID, b.SchemaID, b.RecordID = op.OperationID, op.SchemaID, spec.SessionID
	var command session.SessionCommand
	var err error
	// Original Get provenance must be supplied, not reconstructed metadata.
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
		t.Fatal(err)
	}
	if all {
		command, err = session.NewRevokeAllCommand(b, source, include, 100)
	} else {
		command, err = session.NewRevokeOtherCommand(b, source, 100)
	}
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.PrepareRevokeSet(caller, command)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestNativeRevokeSetMappingRetainsClosedSourceAndDisposition(t *testing.T) {
	for _, mode := range []string{"other", "all-preserve", "all-include"} {
		t.Run(mode, func(t *testing.T) {
			request := setRequestFixture(t, mode != "other", mode == "all-include")
			mapped, err := MapRevokeSetRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			native, until, err := nativeRevokeSet(mapped)
			if err != nil || !until.Equal(request.ValidUntil()) {
				t.Fatal("lost original deadline", err)
			}
			got, ok := native.RevokeSet()
			original, _ := request.Command()
			want, _ := original.RevokeSet()
			a, _, _ := encodeRecord(got.Caller)
			z, _, _ := encodeRecord(want.Caller)
			if !ok || got.Binding != want.Binding || string(a) != string(z) || got.MaximumSessions != 100 || got.IncludeCurrent != want.IncludeCurrent {
				t.Fatal("lost set input")
			}
			if _, err = MapCommand(original); err == nil {
				t.Fatal("structural bulk command bypassed caller custody")
			}
			projection, _ := mapped.Feature()
			for _, field := range []string{"set.maximum", "set.include-current", "caller.valid-until", "session.id"} {
				bad := projection
				bad.Fields = nil
				for _, f := range projection.Fields {
					if f.Name != field {
						bad.Fields = append(bad.Fields, f)
					}
				}
				c, e := identity.NewFeatureCommand(bad)
				if e != nil {
					t.Fatal(e)
				}
				if _, _, e = nativeRevokeSet(c); e == nil {
					t.Fatal("partial intent accepted", field)
				}
			}
		})
	}
	if _, err := MapRevokeSetRequest(session.RevokeSetRequest{}); err == nil {
		t.Fatal("zero custody admitted")
	}
}

func TestNativeRevokeSetForwardMigration(t *testing.T) {
	source := RevokeSetMigrationSource{Schema: "session_store", Version: migrations.Version(20)}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 {
		t.Fatal("owned forward migration missing", err)
	}
	if _, err = (RevokeSetMigrationSource{}).Load(context.Background()); err == nil {
		t.Fatal("zero source")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err = source.Load(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestNativeRevokeSetPlanRequiresCompleteEffectsAndOwnedSource(t *testing.T) {
	request := setRequestFixture(t, false, false)
	mapped, err := MapRevokeSetRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	native, _ := request.Command()
	set, _ := native.RevokeSet()
	spec, _ := set.Caller.Bindings()
	_, _, profile := identifierSessionFixture(t)
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	p := kernel.CommandPlan{SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: session.RevokeOtherOperation()}, Lifecycle: &kernel.LifecyclePlan{EventType: "session.set-revoked.v1", BeforeVersion: spec.Version, AfterVersion: spec.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.revoke", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err = repo.ValidateFeatureCommand(mapped, p); err != nil {
		t.Fatal("native bulk owner cannot execute complete plan", err)
	}
	for _, change := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.SubjectType = "user" },
		func(p *kernel.CommandPlan) { p.Feature.Operation = session.RevokeAllOperation() },
		func(p *kernel.CommandPlan) { p.Lifecycle.EventType = "session.revoked.v1" },
		func(p *kernel.CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *kernel.CommandPlan) { p.Audits[0].Required = false },
		func(p *kernel.CommandPlan) { p.Audits[0].EventType = "identity.session.create" },
	} {
		bad := p
		feature, lifecycle := *p.Feature, *p.Lifecycle
		bad.Feature, bad.Lifecycle = &feature, &lifecycle
		bad.Audits = append([]kernel.AuditPlan(nil), p.Audits...)
		change(&bad)
		if repo.ValidateFeatureCommand(mapped, bad) == nil {
			t.Fatal("incomplete bulk effects admitted")
		}
	}
	if (&Repository{schema: "session_store"}).ValidateFeatureCommand(mapped, p) == nil {
		t.Fatal("unconfigured source owner admitted")
	}
}
