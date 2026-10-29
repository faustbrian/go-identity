package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
)

func updateFixture(t *testing.T) creationInput {
	t.Helper()
	x := creationFixture(t)
	prior := x.Record
	prior.Grant = []string{"invoice.read", "invoice.write"}
	x.PreviousRecord = &prior
	x.Record, _ = updatedRecord(prior, "renamed", []string{"invoice.read"})
	op := updateOperation()
	x.Binding.OperationID, x.Binding.SchemaID, x.Binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	return x
}

func TestUpdateMappingPreservesCredentialAndBindsEveryReplacement(t *testing.T) {
	x := updateFixture(t)
	original, err := x.commitment()
	if err != nil {
		t.Fatal("valid non-expanding update mapping", err)
	}
	if _, err := mapCreation(x); err != nil {
		t.Fatal("Update failed original-session command mapping", err)
	}
	for _, mutate := range []func(*creationInput){
		func(x *creationInput) { x.Record.ID, x.Record.RootID, x.Binding.RecordID = "other", "other", "other" },
		func(x *creationInput) { x.Record.PreviousID = "other" },
		func(x *creationInput) { x.Record.ExpiresAt = x.Record.ExpiresAt.Add(time.Hour) },
		func(x *creationInput) { x.Record.AuthorityVersion--; x.Record.RootVersion-- },
		func(x *creationInput) { x.Record.Grant = []string{"invoice.new"} },
		func(x *creationInput) { x.ConfigurationAuthority.Version = ^uint64(0) },
		func(x *creationInput) {
			spec, _ := x.Session.Bindings()
			x.ValidUntil = managementProofDeadline(spec).Add(time.Microsecond)
		},
	} {
		bad := x
		bad.Record.Grant = append([]string{}, x.Record.Grant...)
		mutate(&bad)
		if _, err := bad.commitment(); err == nil {
			t.Fatal("malformed Update changed credential identity, expanded grant or renewed original authority")
		}
	}
	changed := x
	changed.Record.Name = "another name"
	if digest, err := changed.commitment(); err != nil || digest == original {
		t.Fatal("Update commitment omitted its name", err)
	}
	x.Record = *x.PreviousRecord
	x.Record.Name, x.Record.Version = "name only", x.Record.Version+1
	x.Record.AuthorityVersion, x.Record.RootVersion = ^uint64(0), ^uint64(0)
	x.PreviousRecord.AuthorityVersion, x.PreviousRecord.RootVersion = ^uint64(0), ^uint64(0)
	x.ConfigurationAuthority.Version = ^uint64(0)
	if _, err := x.commitment(); err != nil {
		t.Fatal("name-only Update incorrectly consumed an exhausted security epoch", err)
	}
}

func TestUpdateRejectsAbsentNativeOwners(t *testing.T) {
	for _, service := range []*Service{nil, {}} {
		out, err := service.Update(context.Background(), apikey.UpdateRequest{})
		if !errors.Is(err, apikey.ErrInvalid) || out.Record != nil || out.Receipt.Binding.CommandID != "" {
			t.Fatal("absent Update owner fabricated a command")
		}
	}
}

func TestUpdateSnapshotPreservesOriginalConfigurationEpoch(t *testing.T) {
	x := updateFixture(t)
	p := &creationPhase{service: &Service{update: &apikey.UpdateRequest{}}, input: x, mutation: &apikey.Rotation{}}
	record, err := encodeRecord(x.Record, x.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := p.effectRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	restored, authority, err := decodeEffectRecord(wire, x.Configuration, "identity.apikey.update")
	if err != nil || !reflect.DeepEqual(restored, x.Record) || authority == nil || authority.Version != x.ConfigurationAuthority.Version+1 {
		t.Fatal("original narrowing outcome lost its exact configuration epoch", err)
	}
	for _, malformed := range [][]byte{nil, []byte("{}"), append(bytes.Clone(wire), ' '), bytes.Replace(wire, []byte(`"Schema":1`), []byte(`"Schema":2`), 1), bytes.Repeat([]byte("x"), maximumCommandEffectBytes+1)} {
		if _, _, err := decodeEffectRecord(malformed, x.Configuration, "identity.apikey.update"); err == nil {
			t.Fatal("ambiguous, unbounded or foreign Update snapshot accepted")
		}
	}
	if _, _, err := decodeEffectRecord(wire, x.Configuration, "identity.apikey.rotate"); err == nil {
		t.Fatal("Update snapshot was reinterpreted as historical issuance")
	}
	if legacy, _, err := decodeEffectRecord(record, x.Configuration, "identity.apikey.create"); err != nil || !reflect.DeepEqual(legacy, x.Record) {
		t.Fatal("Update changed existing issuance record encoding", err)
	}
}

func FuzzUpdateSnapshotCanonicalBound(f *testing.F) {
	c, r := recordFixture(f)
	record, err := encodeRecord(r, c)
	if err != nil {
		f.Fatal(err)
	}
	wire, err := json.Marshal(updateSnapshot{Schema: 1, Record: record, ConfigurationVersion: 9})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte("{}"))
	f.Add(bytes.Repeat([]byte("x"), maximumCommandEffectBytes+1))
	f.Fuzz(func(t *testing.T, input []byte) {
		restored, authority, err := decodeEffectRecord(input, c, "identity.apikey.update")
		if err != nil {
			return
		}
		encoded, err := encodeRecord(restored, c)
		if err != nil || authority == nil || authority.Validate(restored.Owner.Spec().TenantID, c.Spec().ID) != nil {
			t.Fatal("accepted invalid Update record/epoch", err)
		}
		canonical, err := json.Marshal(updateSnapshot{Schema: 1, Record: encoded, ConfigurationVersion: authority.Version})
		if err != nil || !bytes.Equal(input, canonical) || len(input) > maximumCommandEffectBytes {
			t.Fatal("accepted noncanonical or unbounded original Update snapshot")
		}
	})
}
