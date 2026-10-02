package postgres

import identity "github.com/faustbrian/go-identity"

// FeatureContributor optionally declares the compile-time storage-neutral
// operations owned by a durable adapter. FeatureOperations must be a pure,
// bounded local method returning 1..64 stable descriptors; no I/O, hooks or
// runtime-generated request identities are allowed. Construction reads it once
// and owns a copy. Each descriptor's Owner plus "/postgres" must exactly equal
// the contributor's adapter Owner. All supported schema versions of an operation
// belong to one exact contributor identity. Declaration is not authorization,
// an executable command codec, transaction authority or a phase implementation.
// Phase capabilities remain separately typed and coordinator-owned.
type FeatureContributor interface {
	Contributor
	FeatureOperations() []identity.FeatureOperation
}

// FeatureRegistration binds a feature schema to one exact registered adapter.
// Its scalar fields are copied during composition. It grants no registry,
// transaction or execution authority; use only the registry's frozen projection
// for trusted composition, not request-supplied descriptors or HTTP discovery.
type FeatureRegistration struct {
	// Contributor is the exact adapter owner, contract ID and contract version.
	Contributor ContributorDescriptor
	// Operation is the exact core owner, operation, schema and record policy.
	Operation identity.FeatureOperation
}

type featureOperationKey struct {
	operation, schema string
	version           uint32
}

func featureKey(d identity.FeatureOperation) featureOperationKey {
	return featureOperationKey{operation: d.OperationID, schema: d.SchemaID, version: d.SchemaVersion}
}

// FeatureOperations returns an owned copy in contributor/declaration order.
// Nil/zero registries and legacy contributors declare no features. No method on
// a contributor is called. Concurrent reads are supported; changing the result
// cannot change registry admission. A declaration is not runtime readiness,
// enabled HTTP discovery or evidence of an implemented execution phase.
func (r *ContributorRegistry) FeatureOperations() []FeatureRegistration {
	if r == nil || r.state == nil {
		return nil
	}
	return append([]FeatureRegistration(nil), r.state.features...)
}

// Only trusted coordinator preparation can select this registered identity.
// The complete descriptor (including record policy) must match, not its name.
func (r *ContributorRegistry) selectFeatureOperation(p FeatureRegistration) (registeredContributor, error) {
	if r == nil || r.state == nil || p.Operation.Validate() != nil {
		return registeredContributor{}, invalidRegistry()
	}
	i, exists := r.state.featureByKey[featureKey(p.Operation)]
	if !exists || r.state.features[i] != p {
		return registeredContributor{}, invalidRegistry()
	}
	return r.state.entries[r.state.featureOwner[p.Operation.OperationID]], nil
}

func (s *contributorRegistryState) registerFeatures(index int) error {
	entry := s.entries[index]
	feature, ok := entry.contributor.(FeatureContributor)
	if !ok {
		return nil
	}
	operations := feature.FeatureOperations()
	if len(operations) == 0 || len(operations) > 64 || len(operations) > 1024-len(s.features) {
		return invalidRegistry()
	}
	for _, operation := range operations {
		if operation.Validate() != nil || entry.descriptor.Owner != operation.Owner+"/postgres" {
			return invalidRegistry()
		}
		key := featureKey(operation)
		if _, exists := s.featureByKey[key]; exists {
			return invalidRegistry()
		}
		if owner, exists := s.featureOwner[operation.OperationID]; exists && owner != index {
			return invalidRegistry()
		}
		s.featureOwner[operation.OperationID] = index
		s.featureByKey[key] = len(s.features)
		s.features = append(s.features, FeatureRegistration{Contributor: entry.descriptor, Operation: operation})
	}
	return nil
}
