package postgres

import (
	"reflect"

	identity "github.com/faustbrian/go-identity"
)

// Contributor is an open composition-time identity supplied by a durable
// adapter. Descriptor must be a pure, bounded local operation returning a
// stable compile-time identity; it must not perform I/O or call user hooks.
// Registration conveys no transaction, commit or cross-package authority.
// Transaction phase capabilities are not yet implemented by this interface.
type Contributor interface {
	Descriptor() ContributorDescriptor
}

// ContributorDescriptor identifies an exact public contributor contract.
// Owner is 1..128 lowercase printable ASCII bytes; ContractID is 1..256
// printable ASCII bytes. Whitespace/control characters are rejected, not
// normalized. Version is positive. All fields are comparable; zero is invalid.
// Composition roots must supply canonical package owners and compile-time
// contract IDs, never user-supplied aliases or runtime-generated identities.
type ContributorDescriptor struct {
	Owner      string
	ContractID string
	Version    uint32
}

// ContributorRegistry is an immutable snapshot of 1..64 contributors, created
// only by NewContributorRegistry. Values may be copied and read concurrently;
// the zero value is invalid. There is no late registration or removal.
// It retains contributor references, not ownership of their resources. Those
// implementations remain responsible for synchronization and lifecycle.
type ContributorRegistry struct{ state *contributorRegistryState }

type contributorRegistryState struct {
	entries []registeredContributor
	byID    map[string]int
}

type registeredContributor struct {
	descriptor  ContributorDescriptor
	contributor Contributor
	registry    *contributorRegistryState
}

// NewContributorRegistry validates and snapshots the complete composition
// before any transaction opens. Nil (including typed nil), malformed descriptors,
// duplicate ContractIDs (including different owners or versions), empty and
// oversized compositions return identity.InvalidInputError without input data.
// Descriptors are read exactly once and copied; mutating the input slice later
// cannot change admission. Contributors are trusted compile-time adapters, not
// arbitrary callbacks: panics in their Descriptor method are not recovered.
// This constructor performs no I/O and never grants mutation authority.
func NewContributorRegistry(contributors []Contributor) (*ContributorRegistry, error) {
	if len(contributors) == 0 || len(contributors) > 64 {
		return nil, invalidRegistry()
	}
	s := &contributorRegistryState{entries: make([]registeredContributor, 0, len(contributors)), byID: make(map[string]int, len(contributors))}
	for _, c := range contributors {
		if nilContributor(c) {
			return nil, invalidRegistry()
		}
		d := c.Descriptor()
		if !validContributorDescriptor(d) {
			return nil, invalidRegistry()
		}
		if _, exists := s.byID[d.ContractID]; exists {
			return nil, invalidRegistry()
		}
		s.byID[d.ContractID] = len(s.entries)
		s.entries = append(s.entries, registeredContributor{descriptor: d, contributor: c, registry: s})
	}
	return &ContributorRegistry{state: s}, nil
}

// Descriptors returns an owned snapshot in composition order. Changing the
// returned slice cannot affect registration. A nil/zero registry returns nil;
// it does not become a valid empty registry. No contributor method is called.
func (r *ContributorRegistry) Descriptors() []ContributorDescriptor {
	if r == nil || r.state == nil {
		return nil
	}
	result := make([]ContributorDescriptor, len(r.state.entries))
	for i, entry := range r.state.entries {
		result[i] = entry.descriptor
	}
	return result
}

// selectContributors binds an entire ordered command selection to this exact
// registry snapshot. No prefix escapes on failure and no callbacks execute.
// Only the future coordinator may use these private retained references.
func (r *ContributorRegistry) selectContributors(descriptors []ContributorDescriptor) ([]registeredContributor, error) {
	if r == nil || r.state == nil || len(descriptors) == 0 || len(descriptors) > 64 {
		return nil, invalidRegistry()
	}
	result := make([]registeredContributor, 0, len(descriptors))
	seen := make(map[string]bool, len(descriptors))
	for _, d := range descriptors {
		i, exists := r.state.byID[d.ContractID]
		if !exists || seen[d.ContractID] || r.state.entries[i].descriptor != d {
			return nil, invalidRegistry()
		}
		seen[d.ContractID] = true
		result = append(result, r.state.entries[i])
	}
	return result, nil
}

func validContributorDescriptor(d ContributorDescriptor) bool {
	return d.Version != 0 && printableContributorID(d.Owner, 128, true) && printableContributorID(d.ContractID, 256, false)
}

func printableContributorID(s string, maximum int, lowercase bool) bool {
	if len(s) == 0 || len(s) > maximum {
		return false
	}
	for i := range len(s) {
		b := s[i]
		if b < '!' || b > '~' || (lowercase && b >= 'A' && b <= 'Z') {
			return false
		}
	}
	return true
}

func nilContributor(c Contributor) bool {
	if c == nil {
		return true
	}
	// Reflection is confined to nil detection; registration never discovers,
	// invokes or wires methods dynamically. Interfaces can hide typed nils.
	v := reflect.ValueOf(c)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func invalidRegistry() error { return identity.InvalidInputError{Field: "contributor_registry"} }
