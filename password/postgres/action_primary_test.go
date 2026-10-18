package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestActionPrimaryZeroDeniesCustody(t *testing.T) {
	for _, source := range []*ActionPrimarySource{nil, {}} {
		if source.Matches("identity.username.update", "audience") {
			t.Fatal("zero source advertised selection")
		}
		if _, err := source.Prepare(context.Background(), ActionPrimaryRequest{}); err == nil {
			t.Fatal("unconfigured primary admitted proof")
		}
		if _, err := source.Restore(context.Background(), ActionPrimaryRequest{}, nil); err == nil {
			t.Fatal("unconfigured primary restored authority")
		}
		if _, err := source.RestoreCommand(context.Background(), identity.Command{}, authorization.DecisionContext{}, session.CSRFToken{}); err == nil {
			t.Fatal("zero source restored command")
		}
		if result, err := source.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil || result != kernel.RecoveryUnknown {
			t.Fatal("unconfigured primary claimed recovery")
		}
	}
	if source, err := NewActionPrimarySource(nil, ActionPrimaryConfig{Action: "identity.organization.owner-transfer", Audience: "organization-action", MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer}); err == nil || source != nil {
		t.Fatal("missing proof owner enabled operation")
	}
	var admission ActionPrimaryAdmission
	if _, err := admission.Original(); err == nil {
		t.Fatal("zero custody supplied source session")
	}
	if _, err := admission.Deadline(); err == nil {
		t.Fatal("zero custody supplied freshness")
	}
	if _, err := admission.Command(identity.CommandBinding{}, nil); err == nil {
		t.Fatal("zero custody supplied command")
	}
	for _, check := range []func(context.Context, kernel.Work, kernel.FeatureExecutionContributor, identity.Command) error{admission.Admit, admission.Consume, admission.Check} {
		if err := check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("zero custody used protected Work")
		}
	}
}

func TestActionPrimaryRecordFieldsPreserveSignedOriginal(t *testing.T) {
	record := originalReauthenticationFixture(t)
	fields, err := actionPrimaryRecordFields(record)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := actionPrimaryRecord(fields)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := record.SigningBytes()
	got, _ := restored.SigningBytes()
	if !bytes.Equal(want, got) || !bytes.Equal(record.Signature, restored.Signature) || restored.ProofVersion != ^uint64(0) || restored.Proof.Proof.IssuedAt.Nanosecond() != 123456789 {
		t.Fatal("signed original was truncated or changed")
	}
	for _, mutate := range []func([]identity.FeatureField) []identity.FeatureField{
		func(f []identity.FeatureField) []identity.FeatureField { return f[:len(f)-1] },
		func(f []identity.FeatureField) []identity.FeatureField { return append(f, f[0]) },
		func(f []identity.FeatureField) []identity.FeatureField { f[0].Value.Uint64 = 1; return f },
		func(f []identity.FeatureField) []identity.FeatureField {
			f[0].Value.Text = strings.Repeat("x", 1025)
			return f
		},
		func(f []identity.FeatureField) []identity.FeatureField {
			f[0].Name = actionPrimaryRecordPrefix + "unknown"
			return f
		},
		func(f []identity.FeatureField) []identity.FeatureField { f[11].Value.Uint64 += 256; return f },
	} {
		if original, err := actionPrimaryRecord(mutate(slices.Clone(fields))); err == nil || original.Proof.Proof.ID != "" {
			t.Fatal("malformed fields supplied partial proof")
		}
	}
	restored.Signature[0] ^= 1
	if bytes.Equal(record.Signature, restored.Signature) {
		t.Fatal("restoration borrowed signature storage")
	}
}

func TestActionReauthenticationMigrationPreservesSelectedHistory(t *testing.T) {
	base := UsernameSigninMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 10}
	original, err := base.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	source := ActionReauthenticationMigrationSource{Base: base, Version: 11}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != len(original)+1 {
		t.Fatal("missing action consumption suffix", err)
	}
	for i, previous := range original {
		if history[i] != previous {
			t.Fatal("installed history rewritten")
		}
	}
	if history[len(original)].Version() != 11 || history[len(original)].DownSQL() != "" {
		t.Fatal("incorrect or destructive suffix")
	}
	var missing *usernameSigninNilSource
	for _, invalid := range []ActionReauthenticationMigrationSource{{}, {Base: missing, Version: 11}, {Base: base, Version: 10}, {Base: base, Version: migrations.Version(^uint64(0))}} {
		if result, err := invalid.Load(context.Background()); err == nil || result != nil {
			t.Fatal("invalid migration composition admitted")
		}
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := source.Load(ctx); err != context.Canceled {
		t.Fatal("migration cancellation lost", err)
	}
}

func TestActionPrimaryDiagnosticsRedactBorrowedEvidence(t *testing.T) {
	for _, value := range []any{ActionPrimaryRequest{RecordID: "private-record"}, ActionPrimarySource{}, ActionPrimaryAdmission{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			got := fmt.Sprintf(verb, value)
			if !strings.Contains(got, "redacted") || strings.Contains(got, "private-record") {
				t.Fatal("primary custody traversed by diagnostics")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit custody export permitted")
		}
	}
}
