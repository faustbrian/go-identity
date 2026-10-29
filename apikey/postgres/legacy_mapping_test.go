package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestModernCommitmentPreservesHistoricalPreimage(t *testing.T) {
	for _, op := range []identity.FeatureOperation{createOperation(), rotateOperation(), revokeOperation()} {
		t.Run(op.OperationID, func(t *testing.T) {
			x := creationFixture(t)
			x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			if op != createOperation() {
				prior := x.Record
				prior.CreatedAt = prior.CreatedAt.Add(-time.Hour)
				x.PreviousRecord = &prior
				if op == rotateOperation() {
					x.Record.ID, x.Record.RootID, x.Binding.RecordID = "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
					x.Record.PreviousID = prior.ID
				} else {
					x.Record = prior
					x.Record.Version++
					x.Record.AuthorityVersion++
					x.Record.RootVersion++
					x.Record.Status, x.Record.Grant = apikey.KeyRevoked, []string{}
				}
			}
			record, err := encodeRecord(x.Record, x.Configuration)
			if err != nil {
				t.Fatal(err)
			}
			var previous []byte
			if x.PreviousRecord != nil {
				previous, err = encodeRecord(*x.PreviousRecord, x.Configuration)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Preserve the exact field preimage from committed native predecessor
			// 9a96661599f9:create_mapping.go, before legacy optional fields existed.
			a := x.ConfigurationAuthority
			preimage, err := json.Marshal(struct {
				Profile                               string
				Record                                []byte
				Previous                              []byte
				Configuration                         apikey.ConfigurationSpec
				StatusVersion, SecurityVersion        uint64
				ConfigurationTenant                   identity.TenantID
				ConfigurationID                       string
				ConfigurationVersion                  uint64
				ReadStartedAt, VerifiedAt, ValidUntil time.Time
				Network                               string
			}{x.Binding.OperationID, record, previous, x.Configuration.Spec(), x.OwnerStatus.User.Version, x.OwnerStatus.AuthorityVersion, a.TenantID, a.ConfigurationID, a.Version, x.ReadStartedAt.UTC(), x.VerifiedAt.UTC(), x.ValidUntil.UTC(), x.Network})
			if err != nil {
				t.Fatal(err)
			}
			got, err := x.commitment()
			if err != nil || got != sha256.Sum256(preimage) {
				t.Fatal("modern original preparation bytes changed", err)
			}
		})
	}
}

func TestNativeLegacyConfigurationRejectsUnsupportedRevoke(t *testing.T) {
	x := creationFixture(t)
	legacy := legacyInput(t)
	c := ServiceConfig{Configuration: x.Configuration, LegacyConfiguration: legacy.Configuration, ValidateCanonicalKeyID: func(context.Context, apikey.KeyID) error { return nil }}
	if err := validateServiceConfigurations(c); err != nil {
		t.Fatal("selected Narrow profile rejected", err)
	}
	spec := legacy.Configuration.Spec()
	spec.PermissionReduction = apikey.PermissionReductionRevoke
	var err error
	c.LegacyConfiguration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateServiceConfigurations(c); !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("native legacy Revoke policy reached Narrow-only verification")
	}
}

func legacyInput(t *testing.T) creationInput {
	t.Helper()
	x := creationFixture(t)
	spec := x.Configuration.Spec()
	spec.ID, spec.Algorithm, spec.State = "legacy", apikey.AlgorithmLegacySHA256V1, apikey.ConfigurationVerifyOnly
	var err error
	x.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	x.Record.ConfigurationID = spec.ID
	x.ConfigurationAuthority.ConfigurationID = spec.ID
	x.Record.ID, x.Record.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	x.Record.Version, x.Record.AuthorityVersion, x.Record.RootVersion = 3, 2, 2
	x.Record.CreatedAt, x.Record.ExpiresAt = x.VerifiedAt.Add(-500*24*time.Hour), x.VerifiedAt.Add(500*24*time.Hour)
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion, x.Binding.RecordID = importOperation().OperationID, importOperation().SchemaID, importOperation().SchemaVersion, string(x.Record.ID)
	x.Import = &legacyImportBinding{SourceID: "source", SourceVersion: 7, Digest: [32]byte{1}}
	return x
}

func TestLegacySnapshotMappingPreservesDistinctRecordAndSourceVersions(t *testing.T) {
	x := legacyInput(t)
	if err := x.validate(); err != nil {
		t.Fatal(err)
	}
	command, err := mapCreation(x)
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != importOperation() || spec.Operation.ValidateRecordVersions(0, x.Record.Version) != nil || x.Record.Version != 3 || x.Import.SourceVersion != 7 {
		t.Fatal("import fabricated sequential history or conflated source versions")
	}
	original, err := x.commitment()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*creationInput){
		func(x *creationInput) { x.Import.SourceVersion++ },
		func(x *creationInput) { x.Import.SourceID = "other-source" },
		func(x *creationInput) { x.Import.Digest[1]++ },
		func(x *creationInput) { x.Record.ExpiresAt = x.Record.ExpiresAt.Add(-time.Hour) },
		func(x *creationInput) { x.Record.Status = apikey.KeyRevoked },
	} {
		changed := x
		source := *x.Import
		changed.Import = &source
		change(&changed)
		digest, err := changed.commitment()
		if err != nil || digest == original {
			t.Fatal("import preparation dropped source metadata or restrictions", err)
		}
	}
}

func TestLegacyTerminalFullWidthSnapshotNeverFabricatesAnIncrement(t *testing.T) {
	x := legacyInput(t)
	x.Record.Version, x.Record.AuthorityVersion, x.Record.RootVersion, x.Import.SourceVersion = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
	x.Record.Status = apikey.KeyRevoked
	if _, err := mapCreation(x); err != nil {
		t.Fatal("terminal source metadata was truncated", err)
	}
	if err := importOperation().ValidateRecordVersions(0, x.Record.Version); err != nil {
		t.Fatal(err)
	}
	x.Record.Status = apikey.KeyActive
	if _, err := mapCreation(x); err == nil {
		t.Fatal("active exhausted source metadata could become usable authority")
	}
}

func TestLegacyModernSuccessorKeepsOldAbsoluteTimesAndNarrowsExpiry(t *testing.T) {
	x := creationFixture(t)
	prior := legacyInput(t)
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion = rotateOperation().OperationID, rotateOperation().SchemaID, rotateOperation().SchemaVersion
	x.PreviousRecord, x.PreviousConfiguration, x.PreviousConfigurationAuthority = &prior.Record, &prior.Configuration, &prior.ConfigurationAuthority
	x.Record.ID, x.Record.RootID, x.Binding.RecordID = "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	x.Record.PreviousID = prior.Record.ID
	x.Record.Grant = append([]string(nil), prior.Record.Grant...)
	x.Record.ExpiresAt = x.Record.CreatedAt.Add(x.Configuration.Spec().MaximumLifetime).Truncate(time.Microsecond)
	if err := x.validate(); err != nil {
		t.Fatal(err)
	}
	if !x.PreviousRecord.CreatedAt.Equal(prior.Record.CreatedAt) || !x.PreviousRecord.ExpiresAt.Equal(prior.Record.ExpiresAt) {
		t.Fatal("rotation rewrote source absolute times")
	}
	x.Record.ExpiresAt = x.Record.ExpiresAt.Add(time.Microsecond)
	if err := x.validate(); err == nil {
		t.Fatal("migration rotation exceeded modern issuance expiry policy")
	}
}

func TestUnnamedImportedKeyCanRotateAndRevokeWithoutRenaming(t *testing.T) {
	create := creationFixture(t)
	create.Record.Name = ""
	if _, err := mapCreation(create); err == nil {
		t.Fatal("new modern issuance accepted an empty name")
	}
	for _, revoke := range []bool{false, true} {
		name := "rotate"
		if revoke {
			name = "revoke"
		}
		t.Run(name, func(t *testing.T) {
			prior := legacyInput(t)
			prior.Record.Name = ""
			x := creationFixture(t)
			op := rotateOperation()
			x.PreviousRecord, x.PreviousConfiguration, x.PreviousConfigurationAuthority = &prior.Record, &prior.Configuration, &prior.ConfigurationAuthority
			x.Record.Name = ""
			x.Record.ID, x.Record.RootID = "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			x.Record.PreviousID = prior.Record.ID
			x.Record.ExpiresAt = x.Record.CreatedAt.Add(x.Configuration.Spec().MaximumLifetime).Truncate(time.Microsecond)
			if revoke {
				op = revokeOperation()
				x.Configuration, x.ConfigurationAuthority = prior.Configuration, prior.ConfigurationAuthority
				x.Record = prior.Record
				x.Record.Version++
				x.Record.AuthorityVersion++
				x.Record.RootVersion++
				x.Record.Status, x.Record.Grant = apikey.KeyRevoked, []string{}
				x.PreviousConfiguration, x.PreviousConfigurationAuthority = nil, nil
			}
			x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion, x.Binding.RecordID = op.OperationID, op.SchemaID, op.SchemaVersion, string(x.Record.ID)
			if _, err := mapCreation(x); err != nil {
				t.Fatal("valid unnamed imported credential cannot transition", err)
			}
			if x.Record.Name != "" || x.PreviousRecord.Name != "" {
				t.Fatal("lifecycle invented a credential name")
			}
		})
	}
}
