package postgres

import (
	"fmt"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type featureRegistryContributor struct {
	descriptor ContributorDescriptor
	operations []identity.FeatureOperation
	calls      int
}

func (c *featureRegistryContributor) Descriptor() ContributorDescriptor { return c.descriptor }
func (c *featureRegistryContributor) FeatureOperations() []identity.FeatureOperation {
	c.calls++
	return c.operations
}

func featureRegistryInput() *featureRegistryContributor {
	return &featureRegistryContributor{
		descriptor: ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session", Version: 1},
		operations: []identity.FeatureOperation{{Owner: "identity/session", OperationID: "identity.session.issue", SchemaID: "session-issue", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}},
	}
}

func TestFeatureRegistryFreezesExactOwnerAndSupportedSchemas(t *testing.T) {
	c := featureRegistryInput()
	second := c.operations[0]
	second.SchemaVersion = 2
	c.operations = append(c.operations, second)
	want := []FeatureRegistration{{Contributor: c.descriptor, Operation: c.operations[0]}, {Contributor: c.descriptor, Operation: second}}
	r, err := NewContributorRegistry([]Contributor{c})
	if err != nil || c.calls != 1 {
		t.Fatal("feature composition not captured exactly once", err)
	}
	c.operations[0].SchemaVersion = 99
	c.descriptor.Version = 99
	got := r.FeatureOperations()
	if len(got) != len(want) {
		t.Fatal("supported schemas lost")
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("feature registration changed")
		}
		entry, err := r.selectFeatureOperation(want[i])
		if err != nil || entry.contributor != c || entry.registry != r.state || entry.descriptor != want[i].Contributor {
			t.Fatal("exact feature owner lost", err)
		}
	}
	copyRegistry := *r
	copyEntry, err := copyRegistry.selectFeatureOperation(want[0])
	if err != nil || copyEntry.registry != r.state {
		t.Fatal("registry copy lost exact composition identity")
	}
	otherInput := featureRegistryInput()
	otherInput.operations = append(otherInput.operations, second)
	other, err := NewContributorRegistry([]Contributor{otherInput})
	if err != nil {
		t.Fatal(err)
	}
	otherEntry, err := other.selectFeatureOperation(want[0])
	if err != nil || otherEntry.registry == r.state || otherEntry.contributor == c {
		t.Fatal("independent registry adopted foreign composition")
	}
	got[0].Operation.SchemaVersion = 88
	got[0].Contributor.Version = 88
	if r.FeatureOperations()[0] != want[0] || c.calls != 1 {
		t.Fatal("projection mutation or lookup reevaluated contributor")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if r.FeatureOperations()[0] != want[0] {
					t.Error("concurrent projection changed")
				}
				if _, e := r.selectFeatureOperation(want[1]); e != nil {
					t.Error(e)
				}
			}
		})
	}
	wg.Wait()
}

func TestFeatureRegistryRejectsIncompleteConflictingAndForeignOwners(t *testing.T) {
	for _, mutate := range []func(*featureRegistryContributor){
		func(c *featureRegistryContributor) { c.operations = nil },
		func(c *featureRegistryContributor) { c.operations = make([]identity.FeatureOperation, 65) },
		func(c *featureRegistryContributor) { c.operations[0].SchemaVersion = 0 },
		func(c *featureRegistryContributor) { c.operations[0].Owner = "identity/password" },
		func(c *featureRegistryContributor) { c.operations[0].OperationID = "identity.user.create" },
		func(c *featureRegistryContributor) { c.operations = append(c.operations, c.operations[0]) },
		func(c *featureRegistryContributor) {
			conflict := c.operations[0]
			conflict.RecordRequirement = identity.FeatureRecordOmitted
			c.operations = append(c.operations, conflict)
		},
	} {
		c := featureRegistryInput()
		mutate(c)
		if r, e := NewContributorRegistry([]Contributor{c}); r != nil || e == nil {
			t.Fatal("invalid feature composition accepted")
		}
	}
	a, b := featureRegistryInput(), featureRegistryInput()
	b.descriptor.ContractID = "identity.session.alternate"
	b.operations[0].SchemaVersion = 2
	if r, e := NewContributorRegistry([]Contributor{a, b}); r != nil || e == nil {
		t.Fatal("operation assigned to two contributor identities")
	}
	b = featureRegistryInput()
	b.descriptor.Owner = "identity/password/postgres"
	b.descriptor.ContractID = "identity.password"
	b.operations[0].Owner = "identity/password"
	if r, e := NewContributorRegistry([]Contributor{a, b}); r != nil || e == nil {
		t.Fatal("operation assigned to two package owners")
	}
}

func TestFeatureRegistrySelectionRequiresEveryFrozenField(t *testing.T) {
	c := featureRegistryInput()
	r, e := NewContributorRegistry([]Contributor{c})
	if e != nil {
		t.Fatal(e)
	}
	want := r.FeatureOperations()[0]
	for _, change := range []func(*FeatureRegistration){
		func(p *FeatureRegistration) { p.Contributor.Owner = "identity/password/postgres" },
		func(p *FeatureRegistration) { p.Contributor.ContractID += ".other" },
		func(p *FeatureRegistration) { p.Contributor.Version++ },
		func(p *FeatureRegistration) { p.Operation.Owner = "identity/password" },
		func(p *FeatureRegistration) { p.Operation.OperationID += "-other" },
		func(p *FeatureRegistration) { p.Operation.SchemaID += "-other" },
		func(p *FeatureRegistration) { p.Operation.SchemaVersion++ },
		func(p *FeatureRegistration) { p.Operation.RecordRequirement = identity.FeatureRecordOmitted },
	} {
		bad := want
		change(&bad)
		if entry, e := r.selectFeatureOperation(bad); e == nil || entry.registry != nil {
			t.Fatal("changed registration accepted")
		}
	}
	for _, zero := range []*ContributorRegistry{nil, {}} {
		if len(zero.FeatureOperations()) != 0 {
			t.Fatal("zero registry advertises features")
		}
		if _, e := zero.selectFeatureOperation(want); e == nil {
			t.Fatal("zero registry selects feature")
		}
	}
	plain, e := NewContributorRegistry([]Contributor{&registryContributor{ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}}})
	if e != nil || len(plain.FeatureOperations()) != 0 {
		t.Fatal("legacy contributor gained features")
	}
	if _, e := plain.selectFeatureOperation(want); e == nil {
		t.Fatal("undeclared feature selected")
	}
}

func TestFeatureRegistryBoundsAndCompositionOrder(t *testing.T) {
	cs := make([]Contributor, 17)
	for i := range cs {
		c := featureRegistryInput()
		c.descriptor.ContractID = fmt.Sprintf("session.part-%d", i)
		count := 64
		if i == 16 {
			count = 1
		}
		base := c.operations[0]
		c.operations = make([]identity.FeatureOperation, count)
		for j := range c.operations {
			c.operations[j] = base
			c.operations[j].OperationID = fmt.Sprintf("identity.session.part-%d-op-%d", i, j)
		}
		cs[i] = c
	}
	r, e := NewContributorRegistry(cs[:16])
	if e != nil || len(r.FeatureOperations()) != 1024 {
		t.Fatal("maximum feature inventory rejected", e)
	}
	for i, p := range r.FeatureOperations() {
		c := cs[i/64].(*featureRegistryContributor)
		if p.Contributor != c.descriptor || p.Operation != c.operations[i%64] {
			t.Fatal("composition order changed")
		}
	}
	if over, e := NewContributorRegistry(cs); over != nil || e == nil {
		t.Fatal("oversized feature inventory accepted")
	}
}
