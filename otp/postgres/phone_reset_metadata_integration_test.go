//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// Actual OTP/MFA generation and original encrypted SMS custody are exercised;
// the anonymous representation is a deliberate projection of that original
// source, not live recipient/factor authority or full native rate acceptance.
func TestPhoneResetMetadataAuthenticatesOriginalArtifactWithoutCurrentFactor(t *testing.T) {
	ctx, db, _, issuer, root, input := phoneResetIssuanceNativeFixture(t)
	wire, err := issuer.Generate(ctx, root, input, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	i := input.state()
	continuation, _ := i.record.continuation.Bindings()
	flow, _ := continuation.Authorization.PreAuthTransaction()
	factor, err := i.factor.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := i.factor.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	factorWire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(factorWire)
	recipient := *i.record.recipient
	smsObservedAt := recipient.ObservedAt
	recipient.Query.UserID = ""
	metadata, err := NewPhonePasswordResetMetadataInput(flow, recipient, i.record.authority, factor, factorWire, i.record.issuedAt, i.record.expiresAt, smsObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	// Input construction owns its bounded ciphertext copy, not caller storage.
	factorWire[len(factorWire)-1] ^= 1
	assertOriginal := func() {
		t.Helper()
		id, at, until, err := issuer.ReadOriginalMetadata(ctx, root, metadata, 1, wire)
		if err != nil || id != string(i.binding.CommandID) || !at.Equal(i.record.issuedAt) || !until.Equal(i.record.expiresAt) {
			t.Fatal("historical OTP metadata lost actual original interval", err)
		}
	}
	assertOriginal()
	for name, change := range map[string]func(*phonePasswordResetIssuer){
		"configuration": func(p *phonePasswordResetIssuer) { p.configuration[0] ^= 1 },
		"issuer": func(p *phonePasswordResetIssuer) {
			store := *p.store
			store.global = "foreign"
			p.store = &store
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *issuer.state()
			change(&changed)
			foreign := &PhonePasswordResetIssuer{read: func() *phonePasswordResetIssuer { return &changed }}
			id, at, until, err := foreign.ReadOriginalMetadata(ctx, root, metadata, 1, wire)
			if err == nil || id != "" || !at.IsZero() || !until.IsZero() {
				t.Fatal("foreign issuer/configuration acquired historical metadata")
			}
		})
	}
	// Original metadata cannot require today's confirmed/unconsumed snapshot.
	if _, err := db.Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL,row_version=row_version+1`); err != nil {
		t.Fatal(err)
	}
	assertOriginal()
	for name, change := range map[string]func(*phonePasswordResetMetadataInput){
		"observed-at":      func(m *phonePasswordResetMetadataInput) { m.smsObservedAt = m.smsObservedAt.Add(time.Microsecond) },
		"factor-row":       func(m *phonePasswordResetMetadataInput) { m.factor.RowVersion++ },
		"factor-authority": func(m *phonePasswordResetMetadataInput) { m.factor.FactorAuthorityVersion++ },
		"factor-ciphertext": func(m *phonePasswordResetMetadataInput) {
			m.factorEnvelope = bytes.Clone(m.factorEnvelope)
			m.factorEnvelope[len(m.factorEnvelope)-1] ^= 1
		},
		"recipient":         func(m *phonePasswordResetMetadataInput) { m.recipient.Query.CanonicalValue = "+358401234568" },
		"known-user-source": func(m *phonePasswordResetMetadataInput) { m.recipient.Query.UserID = i.binding.UserID },
		"authority":         func(m *phonePasswordResetMetadataInput) { m.authority.CredentialAuthorityVersion++ },
		"timeline":          func(m *phonePasswordResetMetadataInput) { m.expiresAt = m.expiresAt.Add(-time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := metadata.state()
			change(&changed)
			candidate := PhonePasswordResetMetadataInput{read: func() phonePasswordResetMetadataInput { return changed }}
			id, at, until, err := issuer.ReadOriginalMetadata(ctx, root, candidate, 1, wire)
			if err == nil || id != "" || !at.IsZero() || !until.IsZero() {
				t.Fatal("different original encoding acquired metadata")
			}
		})
	}
	wrong, err := identity.NewFeaturePreAuthCommand(mustPhoneResetMetadataFeature(t, root), auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []identity.Command{{}, wrong} {
		id, at, until, err := issuer.ReadOriginalMetadata(ctx, command, metadata, 1, wire)
		if err == nil || id != "" || !at.IsZero() || !until.IsZero() {
			t.Fatal("wrong original cookie/root exposed metadata")
		}
	}
	for _, generation := range []uint64{0, 2} {
		id, at, until, err := issuer.ReadOriginalMetadata(ctx, root, metadata, generation, wire)
		if err == nil || id != "" || !at.IsZero() || !until.IsZero() {
			t.Fatal("other generation exposed metadata")
		}
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 1
	if id, at, until, err := issuer.ReadOriginalMetadata(ctx, root, metadata, 1, tampered); err == nil || id != "" || !at.IsZero() || !until.IsZero() {
		t.Fatal("tampered artifact exposed metadata")
	}
	clear(tampered)
	canceled, stop := context.WithCancel(ctx)
	stop()
	if id, at, until, err := issuer.ReadOriginalMetadata(canceled, root, metadata, 1, wire); !errors.Is(err, context.Canceled) || id != "" || !at.IsZero() || !until.IsZero() {
		t.Fatal("metadata cancellation lost", err)
	}
	for _, value := range []any{metadata, &metadata, struct{ Value any }{metadata}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, string(i.binding.UserID)) {
				t.Fatal("historical input diagnostics disclosed scope")
			}
		}
		if _, err := json.Marshal(metadata); !errors.Is(err, otp.ErrSensitiveSerialization) {
			t.Fatal("historical input allowed JSON")
		}
	}
}

func mustPhoneResetMetadataFeature(t *testing.T, command identity.Command) identity.FeatureCommandSpec {
	t.Helper()
	spec, ok := command.Feature()
	if !ok {
		t.Fatal("fixture lost native root")
	}
	return spec
}
