package postgres

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	"github.com/faustbrian/go-identity/session"
)

// Structural command mapping only. Genuine session/primary admission belongs
// to the separate PostgreSQL consumer, never to this deliberately pure fixture.
func creationFixture(t *testing.T) creationInput {
	t.Helper()
	c, record := recordFixture(t)
	record.Version, record.AuthorityVersion, record.RootVersion, record.PreviousID = 1, 1, 1, ""
	at := record.CreatedAt
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind("global"), Tenant: bind("tenant"), User: bind("user"), Identifier: bind("identifier"), Credential: bind("credential"), SessionFamily: bind("family"), Session: bind("session"), Authorization: bind("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	issued := at.Add(-time.Second)
	original, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "api-key-management", Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, IssuedAt: issued, LastActivityAt: issued, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "api-key-management", IssuedAt: issued.Add(-time.Second), ExpiresAt: issued.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := createOperation()
	return creationInput{Configuration: c, Record: record, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(record.ID), SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "api-key-policy", PolicyVersion: 9, CorrelationID: "create-a"}, Session: original, Bearer: auth.NewBearerCredential(wire), OwnerStatus: identity.UserStatusRecord{User: identity.User{ID: "user-a", TenantID: "tenant-a", Version: 5, Status: identity.StatusActive}, AuthorityVersion: 2}, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: "tenant-a", ConfigurationID: "automation", Version: 7}, ReadStartedAt: at, VerifiedAt: at, ValidUntil: at.Add(20 * time.Second), Network: "192.0.2.1"}
}

func TestCreationIntentPreservesFullGrantCeilingWithoutRawBearerFields(t *testing.T) {
	x := creationFixture(t)
	x.Record.Grant = make([]string, 64)
	for i := range x.Record.Grant {
		x.Record.Grant[i] = fmt.Sprintf("permission.%02d.%s", i, strings.Repeat("x", 114))
	}
	c, err := mapCreation(x)
	if err != nil {
		t.Fatal("full root permission ceiling was truncated or rejected", err)
	}
	spec, _ := c.Feature()
	if len(spec.Fields) > 128 {
		t.Fatal("native mapping exceeded shared command bounds")
	}
	for _, f := range spec.Fields {
		if strings.Contains(f.Value.Text, x.Bearer.Token()) || strings.Contains(string(f.Value.Bytes), x.Bearer.Token()) {
			t.Fatal("recoverable bearer entered retained command metadata")
		}
	}
	changed := x
	changed.Record.Grant = append([]string(nil), x.Record.Grant...)
	changed.Record.Grant[63] = "permission.63." + strings.Repeat("y", 114)
	other, err := mapCreation(changed)
	if err != nil {
		t.Fatal(err)
	}
	projection, _ := other.Feature()
	if reflect.DeepEqual(spec, projection) {
		t.Fatal("last permission escaped original intent binding")
	}
}

func TestCreationIntentRetainsOriginalAuthorityAndBindsEveryGrant(t *testing.T) {
	x := creationFixture(t)
	command, err := mapCreation(x)
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := command.Feature()
	if !ok {
		t.Fatal("creation lost typed feature input")
	}
	if spec.Binding != x.Binding || spec.Operation != createOperation() {
		t.Fatal("creation changed target human/tenant/key")
	}
	borrowed, ok := command.SessionToken()
	if !ok || borrowed.Token() != x.Bearer.Token() {
		t.Fatal("separate bearer custody was dropped")
	}
	copy := x
	copy.Record.Grant = []string{"invoice.read", "invoice.write"}
	changed, err := mapCreation(copy)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := changed.Feature()
	if reflect.DeepEqual(spec, other) {
		t.Fatal("changed grant did not change original intent")
	}
	for _, mutate := range []func(*creationInput){
		func(v *creationInput) { v.Binding.ActorID = "other" },
		func(v *creationInput) { v.Binding.UserID = "other" },
		func(v *creationInput) { v.OwnerStatus.AuthorityVersion++ },
		func(v *creationInput) { v.ConfigurationAuthority.TenantID = "other" },
		func(v *creationInput) { v.ValidUntil = v.ReadStartedAt.Add(20*time.Second + time.Microsecond) },
		func(v *creationInput) { v.VerifiedAt = v.ReadStartedAt.Add(-time.Microsecond) },
		func(v *creationInput) { v.Record.PreviousID = "unselected-lineage" },
		func(v *creationInput) { v.Record.ExpiresAt = v.Record.CreatedAt.Add(23 * time.Hour) },
	} {
		bad := x
		mutate(&bad)
		if _, err := mapCreation(bad); err == nil {
			t.Fatal("foreign owner, renewed admission or unselected issuance accepted")
		}
	}
}

func TestManagementMappingBoundsOriginalPrimaryFreshnessNotRecentSessionRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		age    time.Duration
		clamp  bool
		accept bool
	}{
		{"before-boundary", 15*time.Minute - time.Second, true, true},
		{"exact-boundary", 15 * time.Minute, false, false},
		{"after-boundary", 15*time.Minute + time.Microsecond, false, false},
		{"execution-window-crosses-boundary", 15*time.Minute - time.Second, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := creationFixture(t)
			spec, _ := x.Session.Bindings()
			spec.Authentication.Proof.IssuedAt = x.VerifiedAt.Add(-tc.age)
			spec.Authentication.Proof.ExpiresAt = spec.Authentication.Proof.IssuedAt.Add(time.Minute)
			// The session itself is recent and remains ordinarily usable. Its
			// original primary proof, not refresh or read time, owns freshness.
			spec.IssuedAt, spec.LastActivityAt = x.VerifiedAt.Add(-time.Second), x.VerifiedAt
			var err error
			x.Session, err = session.NewSession(spec)
			if err != nil {
				t.Fatal("historical primary fixture invalid", err)
			}
			if lifetime, err := x.Session.Lifetime(x.VerifiedAt); err != nil || !lifetime.Fresh {
				t.Fatal("fixture did not retain ordinary session freshness", err)
			}
			if tc.clamp {
				x.ValidUntil = spec.Authentication.Proof.IssuedAt.Add(15 * time.Minute)
			}
			_, err = mapCreation(x)
			if (err == nil) != tc.accept {
				t.Fatal("management mapping confused current read with sensitive authentication freshness", err)
			}
		})
	}
}

func TestMutationIntentBindsOriginalKeyAndZeroOverlapSuccessor(t *testing.T) {
	x := creationFixture(t)
	prior := x.Record
	prior.CreatedAt = prior.CreatedAt.Add(-time.Hour)
	id, err := apikey.NewKeyID()
	if err != nil {
		t.Fatal(err)
	}
	x.Record.ID, x.Record.RootID, x.Record.PreviousID = id, id, prior.ID
	x.PreviousRecord = &prior
	op := rotateOperation()
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion, x.Binding.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(id)
	command, err := mapCreation(x)
	if err != nil {
		t.Fatal("valid traceable zero-overlap successor rejected", err)
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != op {
		t.Fatal("rotation became a fresh unlinked creation")
	}
	for _, mutate := range []func(*creationInput){
		func(v *creationInput) { v.Record.PreviousID = "other-key" },
		func(v *creationInput) { v.Record.ExpiresAt = v.Record.ExpiresAt.Add(time.Microsecond) },
		func(v *creationInput) { v.Record.Grant = []string{"invoice.read", "invoice.write"} },
		func(v *creationInput) { v.Record.Owner = apikey.Owner{} },
	} {
		bad := x
		mutate(&bad)
		if _, err := mapCreation(bad); err == nil {
			t.Fatal("rotation broadened or detached original authority")
		}
	}
}

func TestRevocationIntentRetainsTerminalTombstoneAndExactVersion(t *testing.T) {
	x := creationFixture(t)
	prior := x.Record
	prior.CreatedAt = prior.CreatedAt.Add(-time.Hour)
	x.PreviousRecord = &prior
	x.Record = prior
	x.Record.Version++
	x.Record.AuthorityVersion++
	x.Record.RootVersion++
	x.Record.Status, x.Record.Grant = apikey.KeyRevoked, []string{}
	op := revokeOperation()
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	command, err := mapCreation(x)
	if err != nil {
		t.Fatal("exact deny-all tombstone rejected", err)
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != op {
		t.Fatal("revocation lost its owning operation")
	}
	for _, mutate := range []func(*creationInput){
		func(v *creationInput) { v.Record.Version++ },
		func(v *creationInput) { v.Record.AuthorityVersion-- },
		func(v *creationInput) { v.Record.Status = apikey.KeyActive },
		func(v *creationInput) { v.Record.Grant = []string{"invoice.read"} },
	} {
		bad := x
		mutate(&bad)
		if _, err := mapCreation(bad); err == nil {
			t.Fatal("revocation widened or detached terminal transition")
		}
	}
}

func TestHumanBearerMappingRejectsCookieSessionState(t *testing.T) {
	x := creationFixture(t)
	spec, err := x.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, KeyVersion: 1, Digest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	x.Session, err = session.NewSessionWithCSRF(spec, csrf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mapCreation(x); err == nil {
		t.Fatal("cookie-issued session accepted as a bearer-only management profile")
	}
}
