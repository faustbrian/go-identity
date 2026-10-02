package postgres

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type registryContributor struct{ descriptor ContributorDescriptor }

func (c *registryContributor) Descriptor() ContributorDescriptor { return c.descriptor }

func TestContributorRegistrySnapshotsAdmission(t *testing.T) {
	d := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	c := &registryContributor{d}
	inputs := []Contributor{c}
	r, err := NewContributorRegistry(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inputs[0] = nil
	c.descriptor.Version = 2
	got := r.Descriptors()
	if len(got) != 1 || got[0] != d {
		t.Fatalf("registration changed: %v", got)
	}
	got[0].Version = 9
	if r.Descriptors()[0] != d {
		t.Fatal("caller mutated registry snapshot")
	}
	entries, err := r.selectContributors([]ContributorDescriptor{d})
	if err != nil || len(entries) != 1 || entries[0].contributor != c || entries[0].descriptor != d || entries[0].registry != r.state {
		t.Fatalf("admission lost exact contributor: %v", err)
	}
}

func TestContributorRegistryRejectsInvalidComposition(t *testing.T) {
	good := ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}
	for _, d := range []ContributorDescriptor{
		{}, {Owner: "", ContractID: "x", Version: 1},
		{Owner: "Identity", ContractID: "x", Version: 1},
		{Owner: "bad owner", ContractID: "x", Version: 1},
		{Owner: "\x00", ContractID: "x", Version: 1},
		{Owner: strings.Repeat("a", 129), ContractID: "x", Version: 1},
		{Owner: "ok", ContractID: "", Version: 1},
		{Owner: "ok", ContractID: "a\n", Version: 1},
		{Owner: "ok", ContractID: "é", Version: 1},
		{Owner: "ok", ContractID: strings.Repeat("a", 257), Version: 1},
		{Owner: "ok", ContractID: "x", Version: 0},
	} {
		r, err := NewContributorRegistry([]Contributor{&registryContributor{d}})
		var invalid identity.InvalidInputError
		if r != nil || !errors.As(err, &invalid) || invalid.Field != "contributor_registry" {
			t.Fatalf("accepted invalid descriptor: %v", err)
		}
	}
	var typedNil *registryContributor
	for _, cs := range [][]Contributor{
		nil, {}, {nil}, {typedNil},
		{&registryContributor{good}, &registryContributor{good}},
		{&registryContributor{good}, &registryContributor{ContributorDescriptor{Owner: good.Owner, ContractID: good.ContractID, Version: 2}}},
		{&registryContributor{good}, &registryContributor{ContributorDescriptor{Owner: "other", ContractID: good.ContractID, Version: 1}}},
		make([]Contributor, 65),
	} {
		if r, err := NewContributorRegistry(cs); r != nil || err == nil {
			t.Fatal("accepted invalid registry")
		}
	}
}

func TestContributorRegistryBoundsAndSelection(t *testing.T) {
	d := ContributorDescriptor{Owner: strings.Repeat("a", 128), ContractID: strings.Repeat("X", 256), Version: ^uint32(0)}
	r, err := NewContributorRegistry([]Contributor{&registryContributor{d}})
	if err != nil {
		t.Fatal(err)
	}
	unknown := d
	unknown.Version--
	for _, ds := range [][]ContributorDescriptor{nil, {}, {unknown}, {d, d}, make([]ContributorDescriptor, 65)} {
		if entries, err := r.selectContributors(ds); entries != nil || err == nil {
			t.Fatal("invalid selection admitted")
		}
	}
	for _, zero := range []*ContributorRegistry{nil, {}} {
		if len(zero.Descriptors()) != 0 {
			t.Fatal("zero registry has descriptors")
		}
		if entries, err := zero.selectContributors([]ContributorDescriptor{d}); entries != nil || err == nil {
			t.Fatal("zero registry admitted a plan")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if r.Descriptors()[0] != d {
					t.Error("concurrent snapshot changed")
				}
				if _, err := r.selectContributors([]ContributorDescriptor{d}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestContributorRegistryPreservesCommandOrder(t *testing.T) {
	cs := make([]Contributor, 64)
	ds := make([]ContributorDescriptor, 64)
	for i := range cs {
		ds[i] = ContributorDescriptor{Owner: "identity/postgres", ContractID: fmt.Sprintf("domain.%d", i), Version: 1}
		cs[i] = &registryContributor{ds[i]}
	}
	r, err := NewContributorRegistry(cs)
	if err != nil {
		t.Fatal(err)
	}
	selection := []ContributorDescriptor{ds[63], ds[0], ds[32]}
	entries, err := r.selectContributors(selection)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range entries {
		if entry.descriptor != selection[i] {
			t.Fatal("command order changed")
		}
	}
	other, err := NewContributorRegistry(cs)
	if err != nil {
		t.Fatal(err)
	}
	copyRegistry := *r
	copyEntries, err := copyRegistry.selectContributors(selection)
	if err != nil || copyEntries[0].registry != entries[0].registry {
		t.Fatal("registry copy lost identity")
	}
	otherEntries, err := other.selectContributors(selection)
	if err != nil || otherEntries[0].registry == entries[0].registry {
		t.Fatal("independent registry has same identity")
	}
}

func FuzzContributorDescriptor(f *testing.F) {
	f.Add("identity/postgres", "identity.domain", uint32(1))
	f.Add("", "", uint32(0))
	f.Add("bad\x00", "bad\xff", ^uint32(0))
	f.Fuzz(func(t *testing.T, owner, contract string, version uint32) {
		d := ContributorDescriptor{Owner: owner, ContractID: contract, Version: version}
		r, err := NewContributorRegistry([]Contributor{&registryContributor{d}})
		if err != nil {
			var invalid identity.InvalidInputError
			if r != nil || !errors.As(err, &invalid) || invalid.Field != "contributor_registry" {
				t.Fatal("unredacted failure")
			}
			return
		}
		if len(owner) < 1 || len(owner) > 128 || len(contract) < 1 || len(contract) > 256 || version == 0 {
			t.Fatal("accepted invalid bounds")
		}
		for _, b := range []byte(owner) {
			if b < 33 || b > 126 || (b >= 65 && b <= 90) {
				t.Fatal("accepted invalid owner")
			}
		}
		for _, b := range []byte(contract) {
			if b < 33 || b > 126 {
				t.Fatal("accepted invalid contract")
			}
		}
		if r.Descriptors()[0] != d {
			t.Fatal("descriptor normalized")
		}
	})
}
