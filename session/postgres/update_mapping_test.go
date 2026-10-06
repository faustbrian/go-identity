package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/faustbrian/go-authorization"
	"math"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func updateMappingFixture(t *testing.T) session.UpdateCommandRequest {
	t.Helper()
	r := rotationMappingFixture(t)
	command, _ := r.Command()
	rotation, _ := command.Rotation()
	spec, _ := rotation.Source.Bindings()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, _ := session.NewToken(32)
	spec.Lookup, _ = token.Digest(key, string(spec.TenantID))
	source, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := spec.LastActivityAt.Add(2 * time.Minute)
	reader, err := session.NewSessionService(rotationObservation{Session: source, Current: spec.Authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: spec.Audience, Clock: sessionReadClock(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialBearer, token)
	caller, err := reader.Get(context.Background(), session.GetRequest{TenantID: spec.TenantID, Credential: credential})
	if err != nil || !caller.Authenticated {
		t.Fatal(err)
	}
	b := rotation.Binding
	op := session.UpdateOperation()
	b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
	u, err := session.NewUpdateCommand(b, source, "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	request, err := reader.PrepareUpdate(caller, u)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestUpdateMappingConservesSourceAndOriginalAdmission(t *testing.T) {
	request := updateMappingFixture(t)
	command, _ := request.Command()
	want, _ := command.Update()
	if _, err := MapCommand(command); err == nil {
		t.Fatal("structural update replaced opaque custody")
	}
	mapped, err := MapUpdateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	native, until, kind, err := nativeUpdateIntent(mapped)
	got, ok := native.Update()
	if err != nil || !ok || got.Binding != want.Binding || got.DeviceLabel != want.DeviceLabel || !until.Equal(request.ValidUntil()) || kind != request.Transport() {
		t.Fatal("update intent changed", err)
	}
	for _, pair := range [][2]session.Session{{want.Source, got.Source}, {want.Successor, got.Successor}} {
		a, _, _ := encodeRecord(pair[0])
		b, _, _ := encodeRecord(pair[1])
		if !bytes.Equal(a, b) {
			t.Fatal("complete security record changed")
		}
	}
	digest, err := updateIntentDigest(mapped)
	if err != nil || digest == ([32]byte{}) {
		t.Fatal(err)
	}
	for _, mode := range []string{"label", "deadline", "transport", "unknown", "missing", "bad-label", "bad-deadline", "bad-transport"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := mapped.Feature()
			switch mode {
			case "unknown":
				p.Fields = append(p.Fields, identity.FeatureField{Name: "metadata.trusted", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
			case "missing":
				p.Fields = p.Fields[1:]
			default:
				for i := range p.Fields {
					f := &p.Fields[i]
					switch {
					case f.Name == "metadata.label" && mode == "label":
						f.Value.Text = "Other"
					case f.Name == "metadata.label" && mode == "bad-label":
						f.Value.Text = "control\x7f"
					case f.Name == "caller.valid-until" && mode == "deadline":
						f.Value.Text = request.ValidUntil().Add(-time.Nanosecond).Format(storedTimeLayout)
					case f.Name == "caller.valid-until" && mode == "bad-deadline":
						f.Value.Text = "not-time"
					case f.Name == "caller.transport" && mode == "transport":
						f.Value.Uint64 = uint64(session.CredentialCookie)
					case f.Name == "caller.transport" && mode == "bad-transport":
						f.Value.Uint64 = 99
					}
				}
			}
			changed, e := identity.NewFeatureCommand(p)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "label" || mode == "deadline" || mode == "transport" {
				other, e := updateIntentDigest(changed)
				if e != nil || other == digest {
					t.Fatal("behavior input not fingerprinted", e)
				}
			} else if _, _, _, e = nativeUpdateIntent(changed); e == nil {
				t.Fatal("malformed command admitted")
			}
		})
	}
	if _, err = MapUpdateRequest(session.UpdateCommandRequest{}); err == nil {
		t.Fatal("zero mapped")
	}
}

func TestUpdatePlanOwnsExactAuditAndLifecycle(t *testing.T) {
	r := updateMappingFixture(t)
	command, _ := r.Command()
	u, _ := command.Update()
	s, _ := u.Source.Bindings()
	_, _, profile := identifierSessionFixture(t)
	repo := &Repository{schema: "session_store", issueAdmission: (*IssueAdmissionConfig)(&profile)}
	mapped, _ := MapUpdateRequest(r)
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: repo.Descriptor(), Operation: session.UpdateOperation()}, SubjectType: "session", Lifecycle: &kernel.LifecyclePlan{EventType: "session.updated.v1", BeforeVersion: s.Version, AfterVersion: s.Version + 1}, Audits: []kernel.AuditPlan{{EventType: "identity.session.update", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, RetentionClass: "standard"}}}
	if err := repo.ValidateFeatureCommand(mapped, plan); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"lifecycle", "version", "audit", "optional", "unconfigured"} {
		p := plan
		l := *plan.Lifecycle
		p.Lifecycle = &l
		p.Audits = append([]kernel.AuditPlan(nil), plan.Audits...)
		owner := repo
		switch mode {
		case "lifecycle":
			l.EventType = "session.rotated.v1"
		case "version":
			l.AfterVersion++
		case "audit":
			p.Audits[0].EventType = "identity.session.refresh"
		case "optional":
			p.Audits[0].Required = false
		case "unconfigured":
			owner = &Repository{}
		}
		if owner.ValidateFeatureCommand(mapped, p) == nil {
			t.Fatal("misdeclared effects accepted", mode)
		}
	}
}

func TestUpdateRejectsZeroCompositionAndRedactsRuntime(t *testing.T) {
	if _, err := NewUpdateExecutor(nil, UpdateExecutorConfig{}); err == nil {
		t.Fatal("zero composition")
	}
	for _, e := range []*UpdateExecutor{nil, {}} {
		if out, err := e.ExecuteUpdate(context.Background(), session.UpdateCommandRequest{}); err == nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("zero execution")
		}
		if _, err := e.RecoverUpdate(context.Background(), session.UpdateCommandRequest{}); err == nil {
			t.Fatal("zero recovery")
		}
		if _, err := e.RecoverUpdateCommand(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
			t.Fatal("zero restart recovery")
		}
	}
	for _, value := range []any{UpdateExecutor{}, UpdateExecutorConfig{Execution: IssueExecutorConfig{PolicyID: "private-policy"}}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit export")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), "private-policy") {
			t.Fatal("diagnostic leak")
		}
	}
	for _, s := range []UpdateMigrationSource{{}, {Schema: "public", Version: 23}, {Schema: "session_store", Version: migrations.Version(math.MaxInt64) + 1}} {
		if _, err := s.Load(context.Background()); err == nil {
			t.Fatal("invalid migration")
		}
	}
	valid := UpdateMigrationSource{Schema: "session_store", Version: 23}
	if _, err := valid.Load(nil); err == nil {
		t.Fatal("nil context")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := valid.Load(ctx); err != context.Canceled {
		t.Fatal("cancelled migration")
	}
}
