package passwordpostgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	username "github.com/faustbrian/go-identity/username"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Constructed only by the native signup service from its frozen startup
// schema/policies. Selecting a server ID is structural preparation, not
// credential generation or execution authority. The callback is the deployment's
// bounded canonical identifier policy, never a request-selected customer ID.
type signupKeyPreparation struct {
	profile            [32]byte
	crypto             *envelope.Service
	envelopeKey        string
	policyID           string
	policyVersion      uint64
	schemaID           string
	schemaVersion      uint32
	comparison         string
	fields             *identity.AttributeProcessor
	address            email.AddressParser
	flowStorage        sessionpg.Config
	flowKeys           []session.DigestKey
	origins, callbacks []string
	selectUser         func(context.Context) (identity.UserID, error)
	username           *username.Policy
}

// The kernel may invoke this outside SQL for discarded missing-key candidates.
// Only reads, structural server-ID selection, field policy and local encryption
// occur here. No risk attempt, hash, grant, send or account mutation is allowed.
// The winning immutable mapping alone unlocks the subsequent journal phases.
func (r *Repository) prepareSignupKeyInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, request password.SignupRequest, intent identity.RequestIntent, config signupKeyPreparation) (wire []byte, err error) {
	callerContext := ctx
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if callerContext != nil && callerContext.Err() != nil {
			err = callerContext.Err()
		}
		if err != nil {
			clear(wire)
			wire = nil
		}
	}()
	if ctx == nil || !r.configuredWriter() || request.Validate() != nil || config.selectUser == nil || config.fields == nil || config.policyVersion != k.PolicyVersion || len(config.flowKeys) == 0 || len(config.flowKeys) > 16 || request.TenantID != k.Scope.TenantID || identity.ActorID(request.Caller.Request.Subject.ID) != k.Scope.ActorID || request.Caller.Request.Subject.Kind != k.Scope.ActorKind || !slices.Contains(config.origins, request.Origin) || !slices.Contains(config.callbacks, request.CallbackURL) {
		return nil, password.ErrPasswordWork
	}
	op := passwordSignupOperation()
	if config.username != nil {
		op = usernameSignupOperation()
	}
	if (config.username != nil) != (request.Username != "") || k.Feature.Operation != op || request.Caller.Request.Action != authorization.Action(op.OperationID) {
		return nil, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	if _, err := r.signupInputAAD(k, config.profile); err != nil {
		return nil, err
	}
	flow, err := sessionpg.ReadPreAuth(ctx, r.pool.Raw(), config.flowStorage, request.TenantID, request.PreAuthID)
	if err != nil {
		return nil, readerFailure(ctx)
	}
	var primary time.Time
	if err := r.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primary); err != nil {
		return nil, readerFailure(ctx)
	}
	possessed := false
	for _, key := range config.flowKeys {
		if r.admitSignupFlow(request, flow, key, config.policyID, config.policyVersion, primary) == nil {
			possessed = true
			break
		}
	}
	if !possessed {
		return nil, identity.ForbiddenError{}
	}
	user, err := config.selectUser(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, readerFailure(ctx)
	}
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: k.Scope.TenantID, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind, AnonymousFlowID: string(request.PreAuthID), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: config.policyID, PolicyVersion: config.policyVersion, CorrelationID: string(k.Admission.CommandID)}
	selected, err := r.prepareSignupCreation(ctx, request, b, user, config.fields, config.address, config.schemaID, config.schemaVersion, config.comparison, config.username)
	if err != nil {
		return nil, err
	}
	return r.retainSignupInput(ctx, config.crypto, config.envelopeKey, k, config.profile, b, selected, flow, intent, primary.UTC().Truncate(time.Microsecond))
}

func passwordSignupOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
}

func usernameSignupOperation() identity.FeatureOperation {
	op := passwordSignupOperation()
	op.Owner, op.OperationID, op.SchemaID = "identity/username", "identity.username.signup", "username-signup"
	return op
}

func signupOperation(op identity.FeatureOperation) bool {
	return op == passwordSignupOperation() || op == usernameSignupOperation()
}

func signupBindingOperation(b identity.CommandBinding) identity.FeatureOperation {
	if b.OperationID == "identity.username.signup" {
		return usernameSignupOperation()
	}
	return passwordSignupOperation()
}

// Only the native request-key preparation owner selects user and the frozen
// processor/address/schema composition. Requested fields are not preapproved.
// Creation keeps the actual ingress actor; it must never obtain FieldWriteSelf
// by masquerading as the proposed new user. The original command stays bound
// to its anonymous flow even though structural creation names the new account.
// No provider, password work, verification issuance or SQL mutation occurs here.
// The kernel must still fence the same prepared attributes in the final Work.
func (*Repository) prepareSignupCreation(ctx context.Context, r password.SignupRequest, b identity.CommandBinding, user identity.UserID, fields *identity.AttributeProcessor, address email.AddressParser, schemaID string, schemaVersion uint32, comparison string, names *username.Policy) (intent kernel.PasswordRegistrationIntent, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			intent = kernel.PasswordRegistrationIntent{}
		}
	}()
	op := passwordSignupOperation()
	if names != nil {
		op = usernameSignupOperation()
	}
	if ctx == nil || fields == nil || (names != nil) != (r.Username != "") || r.Validate() != nil || b.ValidateFor(op) != nil || b.TenantID != r.TenantID || b.ActorID != identity.ActorID(r.Caller.Request.Subject.ID) || b.ActorKind != r.Caller.Request.Subject.Kind || b.AnonymousFlowID != string(r.PreAuthID) || schemaVersion == 0 {
		return intent, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return intent, err
	}
	if _, err := identity.ParseIdentifierID(comparison); err != nil {
		return intent, password.ErrPasswordWork
	}
	creation := b
	creation.OperationID, creation.AnonymousFlowID, creation.UserID = "identity.user.create", "", user
	creation.SchemaID, creation.SchemaVersion = schemaID, schemaVersion
	// Establish bounded structural provenance before normalization or policy
	// callbacks. Canonical ID policy, including ULID support, remains the injected
	// kernel processor's responsibility; do not hard-code the default ID format.
	if _, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive}); err != nil {
		return intent, err
	}
	parsed, err := address.Parse(email.AddressInput(r.Email))
	if err != nil {
		return intent, password.ErrInvalidSignupAddress
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(b.PolicyVersion)
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(b.TenantID), "identity.user.create"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}
	prepared, err := fields.Prepare(ctx, identity.AttributePrepareRequest{TenantID: b.TenantID, UserID: user, SchemaVersion: schemaVersion, Updates: r.AllowedFields, Context: caller})
	if err != nil {
		return intent, err
	}
	intent = kernel.PasswordRegistrationIntent{
		Creation:          identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive, Attributes: prepared},
		Identifier:        identity.Identifier{ID: identity.IdentifierID(user), UserID: user, Kind: identity.IdentifierEmail, CanonicalValue: parsed.Canonical().Record().Value, DisplayValue: parsed.Display(), Version: 1},
		Credential:        identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: user, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1},
		ComparisonProfile: comparison,
	}
	if names != nil {
		name, err := names.Validate(ctx, r.Username)
		if err != nil {
			return intent, err
		}
		// Identifier IDs are tenant-wide, not per-user labels. Generate an
		// independent structural ID before retaining the winning keyed input;
		// retries restore it instead of generating another reservation target.
		id, err := identity.NewSubjectID()
		if err != nil {
			return intent, password.ErrPasswordWork
		}
		record := name.Record()
		intent.Username = identity.Identifier{ID: identity.IdentifierID(id), UserID: user, Kind: identity.IdentifierUsername, CanonicalValue: record.Canonical, DisplayValue: record.Display, Version: 1, NormalizationProfile: string(record.ProfileID), NormalizationVersion: record.ProfileVersion}
	}
	if _, err := kernel.PasswordRegistrationFields(intent); err != nil {
		return intent, err
	}
	return intent, nil
}
