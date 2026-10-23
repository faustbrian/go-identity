package postgres

import identity "github.com/faustbrian/go-identity"

// FeatureContributor optionally declares the compile-time storage-neutral
// operations owned by a durable adapter. FeatureOperations must be a pure,
// bounded local method returning 1..64 stable descriptors; no I/O, hooks or
// runtime-generated request identities are allowed. Construction reads it once
// and owns a copy. Each descriptor's Owner plus "/postgres" must exactly equal
// the contributor's adapter Owner, except the closed username signup/signin
// profiles also admit the exact existing identity/password/postgres participant.
// Closed phone/password-signin v1 exclusively selects that password participant;
// a generic same-owner declaration cannot override this profile's native owner.
// Closed phone SMS-code signin v1 instead selects the existing OTP participant.
// All supported schema versions of an operation
// belong to one exact contributor identity. A schema may declare distinct user
// and anonymous-flow subjects; duplicates within either namespace are invalid.
// Declaration is not authorization,
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
	subject           identity.FeatureSubjectRequirement
}

func featureKey(d identity.FeatureOperation) featureOperationKey {
	return featureOperationKey{operation: d.OperationID, schema: d.SchemaID, version: d.SchemaVersion, subject: d.SubjectRequirement}
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
		if operation.Validate() != nil || !featureContributorOwns(entry.descriptor, operation) {
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

// Username and phone own their workflows, not another password proof engine. Keep
// this exception to the exact existing adapter and closed paired-custody tuples;
// no arbitrary cross-owner operation, schema or future version is admitted.
func featureContributorOwns(d ContributorDescriptor, op identity.FeatureOperation) bool {
	// The OIDC child owns logout protocol semantics; the existing OAuth native
	// participant composes its session-owned effect. Admit only this closed
	// tuple, not arbitrary child operations or a second native authority.
	if op.OperationID == "identity.oauth-server.end-session" {
		return op == (identity.FeatureOperation{Owner: "oauth-server/oidc", OperationID: "identity.oauth-server.end-session", SchemaID: "identity.oauth-server.end-session.native-rp-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) && d == (ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1})
	}
	// Anonymous creation can mutate kernel rows only through the closed owning
	// seam. A schema alias must not bypass its creation/commit/recovery guards.
	if op.OperationID == "identity.anonymous.signin" {
		return op == anonymousCreationOperation() && d == anonymousCreationDescriptor()
	}
	if op.OperationID == "identity.anonymous.delete" {
		return op == anonymousDisposalOperation() && d == anonymousCreationDescriptor()
	}
	if op.OperationID == "identity.anonymous.expire" {
		return op == anonymousExpiryDisposalOperation() && d == anonymousCreationDescriptor()
	}
	if op.OperationID == "identity.anonymous.upgrade" {
		return (op == anonymousUpgradeOperation() || op == anonymousUpgradePreparationOperation()) && d == anonymousCreationDescriptor()
	}
	// Phone recovery must retain the existing password/reset material writer;
	// neither a same-owner alias nor a future schema can omit its typed phases.
	if op.OperationID == "identity.phone.password-reset-complete" {
		return op == phonePasswordResetOperation() && d == (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1})
	}
	// A schema alias must not turn this issuance/supersession operation into
	// a generic feature without its typed grant, delivery and audit phases.
	if op.OperationID == organizationInvitationResendOperation().OperationID {
		return op == organizationInvitationResendOperation() && d == organizationInvitationDescriptor()
	}
	// Reserve the operation before generic same-owner registration. An unknown
	// schema must not skip the typed replacement/OTP/cascade path and report
	// success as a generic feature with no identifier mutation.
	if op.OperationID == "identity.phone.update" {
		return op == phoneChangeOperation() && d == (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1})
	}
	// Phone owns this workflow, but the existing OTP participant exclusively
	// owns its counted attempt and consuming transaction. Do not admit a second
	// phone storage engine or a generic cross-owner delegation.
	if op.Owner == "identity/phone" && op.OperationID == "identity.phone.signin" {
		return op.SchemaID == "identity.phone.signin.native-v1" && op.SchemaVersion == 1 && op.RecordRequirement == identity.FeatureRecordOmitted &&
			d == (ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1})
	}
	// This closed phone profile reuses password's verifier and transaction
	// participant. A generic same-owner registration must not replace it.
	if op.Owner == "identity/phone" && passwordSigninOperation(op) {
		return d == (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1})
	}
	if d.Owner == op.Owner+"/postgres" {
		return true
	}
	return op.Owner == "identity/username" && (passwordRegistrationOperation(op) || passwordSigninOperation(op)) && d == (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1})
}
