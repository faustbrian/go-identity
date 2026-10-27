package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func TestOrganizationSelectionChangesOnlyExactSessionAndOrganization(t *testing.T) {
	original := sessionSpec(t)
	source, err := session.NewSession(original)
	if err != nil {
		t.Fatal(err)
	}
	binding := issueBinding(original)
	op := session.OrganizationSelectionOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	selection := session.ActiveOrganizationSelection{
		SessionID: original.SessionID, TenantID: original.TenantID,
		SessionVersion: session.SessionVersion(original.Version), OrganizationID: "organization-a",
		Authority: session.AuthorityBinding{ScopeKey: "organization:tenant-a:organization-a", Version: 12},
	}
	command, err := session.NewOrganizationSelectionCommand(binding, source, selection)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := command.Bindings()
	if err != nil || transition.Binding != binding || transition.Source != source || transition.Selection != selection {
		t.Fatal("selection transition lost exact input", err)
	}
	next, err := transition.Successor.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := next.Authority.Bindings()
	oldVector, _ := original.Authority.Bindings()
	if next.Version != original.Version+1 || vector.Session.Version != next.Version || vector.ActiveOrganizationID != "organization-a" || !vector.Organization.Present || vector.Organization.Binding != selection.Authority {
		t.Fatal("selection did not advance the exact session/vector")
	}
	vector.Session.Version = oldVector.Session.Version
	vector.ActiveOrganizationID, vector.Organization = oldVector.ActiveOrganizationID, oldVector.Organization
	if vector != oldVector {
		t.Fatal("selection changed unrelated authority")
	}
	next.Version, next.Authority = original.Version, original.Authority
	if next != original {
		t.Fatal("selection changed authentication, activity, lookup or lifetime")
	}
	clear := session.ActiveOrganizationSelection{SessionID: original.SessionID, TenantID: original.TenantID, SessionVersion: session.SessionVersion(original.Version + 1)}
	clearCommand, err := session.NewOrganizationSelectionCommand(binding, transition.Successor, clear)
	if err != nil {
		t.Fatal("explicit absence did not clear", err)
	}
	cleared, err := clearCommand.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	clearedSpec, _ := cleared.Successor.Bindings()
	clearedVector, _ := clearedSpec.Authority.Bindings()
	if clearedSpec.Version != original.Version+2 || clearedVector.Session.Version != clearedSpec.Version || clearedVector.ActiveOrganizationID != "" || clearedVector.Organization != (session.OptionalAuthorityBinding{}) {
		t.Fatal("clear retained selected authority or lost its session CAS")
	}
	unchanged, _ := source.Bindings()
	if unchanged != original {
		t.Fatal("command mutated source session")
	}
}

func TestOrganizationSelectionRejectsForeignScopeMalformedAbsenceAndOverflow(t *testing.T) {
	spec := sessionSpec(t)
	source, _ := session.NewSession(spec)
	binding := issueBinding(spec)
	op := session.OrganizationSelectionOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	valid := session.ActiveOrganizationSelection{SessionID: spec.SessionID, TenantID: spec.TenantID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: "org", Authority: session.AuthorityBinding{ScopeKey: "organization:tenant-a:org", Version: 1}}
	for _, change := range []func(*session.ActiveOrganizationSelection){
		func(s *session.ActiveOrganizationSelection) { s.SessionID = "another-session" },
		func(s *session.ActiveOrganizationSelection) { s.TenantID = "another-tenant" },
		func(s *session.ActiveOrganizationSelection) { s.SessionVersion = 0 },
		func(s *session.ActiveOrganizationSelection) { s.SessionVersion++ },
		func(s *session.ActiveOrganizationSelection) { s.OrganizationID = "" },
		func(s *session.ActiveOrganizationSelection) { s.OrganizationID = strings.Repeat("x", 129) },
		func(s *session.ActiveOrganizationSelection) { s.OrganizationID = "bad organization" },
		func(s *session.ActiveOrganizationSelection) { s.Authority.Version = 0 },
		func(s *session.ActiveOrganizationSelection) { s.Authority.ScopeKey = "" },
		func(s *session.ActiveOrganizationSelection) { s.Authority.ScopeKey = strings.Repeat("x", 257) },
		func(s *session.ActiveOrganizationSelection) { s.Authority.ScopeKey = "bad\nscope" },
		func(s *session.ActiveOrganizationSelection) { s.Authority.ScopeKey = "global:deployment" },
	} {
		bad := valid
		change(&bad)
		if got, err := session.NewOrganizationSelectionCommand(binding, source, bad); !errors.Is(err, session.ErrInvalidSessionCommand) || got != (session.OrganizationSelectionCommand{}) {
			t.Fatal("invalid selection escaped", err)
		}
	}
	for _, change := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectServiceAccount },
		func(b *identity.CommandBinding) { b.RecordID = "another-session" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.session.update" },
		func(b *identity.CommandBinding) { b.SchemaID = "session-update" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
		func(b *identity.CommandBinding) { b.CommandID = "invalid" },
	} {
		bad := binding
		change(&bad)
		if _, err := session.NewOrganizationSelectionCommand(bad, source, valid); !errors.Is(err, session.ErrInvalidSessionCommand) {
			t.Fatal("foreign command admitted", err)
		}
	}
	vector, _ := spec.Authority.Bindings()
	spec.Version, vector.Session.Version = ^uint64(0), ^uint64(0)
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	overflow, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	valid.SessionVersion = session.SessionVersion(spec.Version)
	if _, err := session.NewOrganizationSelectionCommand(binding, overflow, valid); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("session version wrapped", err)
	}
}

func TestOrganizationSelectionCopiesProjectionAndRetainsOriginalLifetime(t *testing.T) {
	spec := sessionSpec(t)
	source, _ := session.NewSession(spec)
	binding := issueBinding(spec)
	op := session.OrganizationSelectionOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	selection := session.ActiveOrganizationSelection{SessionID: spec.SessionID, TenantID: spec.TenantID, SessionVersion: session.SessionVersion(spec.Version)}
	c, err := session.NewOrganizationSelectionCommand(binding, source, selection)
	if err != nil {
		t.Fatal(err)
	}
	projection, _ := c.Bindings()
	projection.Selection.SessionID, projection.Binding.UserID, projection.Successor = "foreign", "foreign", session.Session{}
	retained, err := c.Bindings()
	if err != nil || retained.Selection != selection || retained.Binding != binding || retained.Successor == (session.Session{}) {
		t.Fatal("projection mutated retained command", err)
	}
	lifetime, _ := source.Lifetime(spec.IssuedAt)
	if c.ValidateAt(spec.IssuedAt) != nil || c.ValidateAt(lifetime.ExpiresAt) == nil || c.ValidateAt(time.Time{}) == nil {
		t.Fatal("command renewed or ignored original session lifetime")
	}
	if _, err := (session.OrganizationSelectionCommand{}).Bindings(); !errors.Is(err, session.ErrInvalidSessionCommand) {
		t.Fatal("zero command projected")
	}
	if (session.OrganizationSelectionCommand{}).ValidateAt(spec.IssuedAt) == nil {
		t.Fatal("zero command validated")
	}
	for _, value := range []any{c, &c} {
		if !strings.Contains(fmt.Sprintf("%+v", value), "redacted") {
			t.Fatal("command exposed correlated scope")
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("command serialized", err)
		}
	}
}

func TestOrganizationSelectionPreservesContinuationAndDropsObsoleteCSRF(t *testing.T) {
	spec := sessionSpec(t)
	source, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewCSRFKey(1, []byte(strings.Repeat("c", 32)))
	source, token := csrfRecord(t, source, key)
	state := source.CSRFState()
	csrf, _ := state.Bindings()
	vector, _ := spec.Authority.Bindings()
	id, _ := identity.NewCommandID()
	continuation := session.CredentialContinuationSpec{CommandID: id, BeforeAuthorityVersion: vector.Credential.Version, BeforeCredentialVersion: spec.Authentication.CredentialVersion}
	source, err = session.ContinuePasswordSession(source, continuation)
	if err != nil {
		t.Fatal(err)
	}
	binding := issueBinding(spec)
	op := session.OrganizationSelectionOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	c, err := session.NewOrganizationSelectionCommand(binding, source, session.ActiveOrganizationSelection{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: "org", Authority: session.AuthorityBinding{ScopeKey: "organization:tenant-a:org", Version: 1}})
	if err != nil {
		t.Fatal(err)
	}
	transition, _ := c.Bindings()
	if retained, ok := transition.Successor.CredentialContinuation(); !ok || retained != continuation || transition.Successor.EffectiveCredentialVersion() != source.EffectiveCredentialVersion() {
		t.Fatal("selection stripped password-change provenance")
	}
	if _, err := transition.Successor.CSRFState().Bindings(); !errors.Is(err, session.ErrInvalidCSRF) {
		t.Fatal("version change retained obsolete synchronizer", err)
	}
	if err := source.CSRFState().Check(csrf.Binding, token, key); err != nil {
		t.Fatal("source synchronizer was mutated", err)
	}
}
