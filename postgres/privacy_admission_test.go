package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// These tests exercise invocation custody, not native session SQL or complete
// export admission. Real allocation/storage rollback has separate PG evidence.
type privacyAdmissionProbe struct {
	retained PrivacyExportAdmissionWork
	inspect  func(context.Context, PrivacyExportAdmissionWork) error
}

func (*privacyAdmissionProbe) Descriptor() ContributorDescriptor {
	return identifierAdmissionDescriptor()
}
func (p *privacyAdmissionProbe) CheckPrivacyExport(ctx context.Context, h PrivacyExportAdmissionWork) error {
	p.retained = h
	if p.inspect != nil {
		return p.inspect(ctx, h)
	}
	_, _, err := h.Command(p)
	return err
}
func privacyAdmissionFixture(t *testing.T, p *privacyAdmissionProbe) (Work, identity.PrivacyExportRequestCommand) {
	t.Helper()
	const id = "AQEBAQEBAQEBAQEBAQEBAQ"
	c := identity.PrivacyExportRequestCommand{Binding: identity.CommandBinding{CommandID: identity.CommandID(id), TenantID: identity.TenantID(id), UserID: identity.UserID(id), ActorID: identity.ActorID(id), ActorKind: authorization.SubjectUser, OperationID: "identity.privacy-export.request", PolicyID: "privacy", PolicyVersion: 1, SchemaID: "identity-privacy-export", SchemaVersion: 1, CorrelationID: id}, ExpectedIdentityVersion: 3, ExpectedAuthorityVersion: 4, ExpectedPrivacyEpoch: 1, SessionID: "session", SessionVersion: 1, MaximumBytes: 256 << 20, ArtifactTTL: 24 * time.Hour}
	for _, owner := range identity.PrivacyExportContributorsV1() {
		c.Projections = append(c.Projections, identity.PrivacyExportProjectionSpecV1{ContributorID: owner, ProjectionID: identity.PrivacyExportStagedSubjectV1})
	}
	registry, err := NewContributorRegistry([]Contributor{p})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: c.Binding, generation: 1, registry: registry.state}}
	return w, c
}
func privacyAdmissionStoredFixture(t *testing.T, w Work, c identity.PrivacyExportRequestCommand) {
	t.Helper()
	digest, err := identity.PrivacyExportIntentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	w.state.privacyAllocation = &privacyAllocation{exportID: "AgICAgICAgICAgICAgICAg", identityVersion: 3, authorityVersion: 4, privacyEpoch: 2, requestedAtMicroseconds: 1, intentDigest: digest}
	w.state.privacyReceipt = &identity.PrivacyExportRequestReceipt{Status: identity.PrivacyExportQueued, IntentDigest: digest, Snapshot: identity.PrivacyExportSnapshotRecordV1{ExportID: w.state.privacyAllocation.exportID, TenantID: c.Binding.TenantID, SubjectID: c.Binding.UserID, CommandID: c.Binding.CommandID, IdentityVersion: 3, PrivacyEpoch: 2, RequestedAtMicroseconds: 1}}
}
func TestPrivacyAdmissionExactOwnerCopyAndLifetime(t *testing.T) {
	p := &privacyAdmissionProbe{}
	w, c := privacyAdmissionFixture(t, p)
	for _, final := range []bool{false, true} {
		if final {
			privacyAdmissionStoredFixture(t, w, c)
		}
		p.inspect = func(_ context.Context, h PrivacyExportAdmissionWork) error {
			got, phase, err := h.Command(p)
			if err != nil || phase != final || got.Binding != c.Binding || got.SessionID != c.SessionID || got.SessionVersion != c.SessionVersion {
				t.Fatal("frozen command changed", err)
			}
			got.Projections[0].ProjectionID = identity.PrivacyExportSubjectJournalV1
			again, _, err := h.Command(p)
			if err != nil || again.Projections[0] != c.Projections[0] {
				t.Fatal("projection alias widened command")
			}
			if strings.Contains(fmt.Sprintf("%+v", h), c.SessionID) {
				t.Fatal("handle exposed correlation")
			}
			if _, err := json.Marshal(h); err == nil {
				t.Fatal("handle serialized")
			}
			return nil
		}
		if err := runPrivacyExportAdmission(w.state.ctx, w, c, final); err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.retained.Command(p); err == nil {
			t.Fatal("retained command authority")
		}
		if _, err := p.retained.Query(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("retained SQL authority")
		}
	}
	if err := runPrivacyExportAdmission(w.state.ctx, w, c, true); err == nil || w.usable() == nil {
		t.Fatal("terminal phase renewed")
	}
}
func TestPrivacyAdmissionIgnoredDenialsPoisonOriginalWork(t *testing.T) {
	for name, check := range map[string]func(*privacyAdmissionProbe, PrivacyExportAdmissionWork){
		"foreign": func(_ *privacyAdmissionProbe, h PrivacyExportAdmissionWork) {
			_, _, _ = h.Command(&privacyAdmissionProbe{})
		},
		"nil":       func(_ *privacyAdmissionProbe, h PrivacyExportAdmissionWork) { _, _, _ = h.Command(nil) },
		"nil query": func(_ *privacyAdmissionProbe, h PrivacyExportAdmissionWork) { _, _ = h.Query(nil, "SELECT 1") },
		"bad credential": func(p *privacyAdmissionProbe, h PrivacyExportAdmissionWork) {
			_, _ = h.RequireActiveCredential(context.Background(), p, CredentialAdmission{})
		},
		"bad directory": func(p *privacyAdmissionProbe, h PrivacyExportAdmissionWork) {
			_ = h.RequireActiveDirectoryAuthority(context.Background(), p, DirectoryAuthorityAdmission{})
		},
		"bad authorization": func(p *privacyAdmissionProbe, h PrivacyExportAdmissionWork) {
			_ = h.RequireActiveUserAuthorization(context.Background(), p, UserAuthorizationAdmission{})
		},
		"active cursor": func(_ *privacyAdmissionProbe, h PrivacyExportAdmissionWork) {
			h.state.work.state.rows = &WorkRows{}
			_, _ = h.Query(context.Background(), "SELECT 1")
			h.state.work.state.rows = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &privacyAdmissionProbe{}
			w, c := privacyAdmissionFixture(t, p)
			p.inspect = func(_ context.Context, h PrivacyExportAdmissionWork) error { check(p, h); return nil }
			if err := runPrivacyExportAdmission(w.state.ctx, w, c, false); err == nil || w.usable() == nil || w.state.sqlStarted {
				t.Fatal("ignored failure admitted")
			}
		})
	}
}
func TestPrivacyAdmissionFailureAndOrdering(t *testing.T) {
	for _, name := range []string{"panic", "cancel", "duplicate initial", "early final", "changed final", "missing storage", "missing registry"} {
		t.Run(name, func(t *testing.T) {
			p := &privacyAdmissionProbe{}
			w, c := privacyAdmissionFixture(t, p)
			final := false
			switch name {
			case "panic":
				p.inspect = func(context.Context, PrivacyExportAdmissionWork) error { panic("private diagnostic") }
			case "cancel":
				p.inspect = func(context.Context, PrivacyExportAdmissionWork) error { w.state.cancel(); return nil }
			case "early final":
				final = true
			case "missing registry":
				w.state.registry = nil
			default:
				if err := runPrivacyExportAdmission(w.state.ctx, w, c, false); err != nil {
					t.Fatal(err)
				}
				if name != "duplicate initial" {
					final = true
					privacyAdmissionStoredFixture(t, w, c)
				}
				if name == "changed final" {
					c.MaximumBytes++
				}
				if name == "missing storage" {
					w.state.privacyReceipt = nil
				}
			}
			if err := runPrivacyExportAdmission(w.state.ctx, w, c, final); err == nil || w.usable() == nil {
				t.Fatal("failure or unordered phase admitted")
			}
			if _, _, err := p.retained.Command(p); err == nil {
				t.Fatal("failed invocation retained authority")
			}
		})
	}
}
