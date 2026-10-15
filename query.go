package identity

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
)

// ErrUserAbsent is returned by a repository for enumeration-safe absence. The
// query service exposes the same ForbiddenError as a denied projection.
var ErrUserAbsent = errors.New("identity: user absent")

// ForbiddenError is a redacted policy denial or enumeration-safe absence.
type ForbiddenError struct{}

func (ForbiddenError) Error() string { return "identity: forbidden" }

// UnavailableError is a redacted dependency, panic or invalid-output failure.
type UnavailableError struct{}

func (UnavailableError) Error() string { return "identity: unavailable" }

// CancelledError identifies cancellation without exposing dependency errors.
type CancelledError struct{}

func (CancelledError) Error() string { return "identity: cancelled" }
func (CancelledError) Unwrap() error { return context.Canceled }

// DeadlineExceededError identifies expiration of the bounded read context.
type DeadlineExceededError struct{}

func (DeadlineExceededError) Error() string { return "identity: deadline exceeded" }
func (DeadlineExceededError) Unwrap() error { return context.DeadlineExceeded }

// FieldName is a canonical schema field name, never an attribute value.
type FieldName struct{ Value string }

// GetUserQuery is an exact tenant/user lookup with a bounded safe projection.
// Repository implementations must not return another subject or tenant.
type GetUserQuery struct {
	TenantID TenantID
	UserID   UserID
	Fields   []FieldName
}

// UserQueryRepository owns authoritative user reads. Implementations must be
// concurrent-safe, honor cancellation/deadlines, and return ErrUserAbsent for
// absence without leaking personal data. The full Repository will compose this
// narrow read seam with its write/list contracts; this is not a second store.
type UserQueryRepository interface {
	Get(context.Context, GetUserQuery) (User, error)
}

// UserGetRequest binds a target to an exact upstream authorization context.
// Trusted authenticated composition supplies Context; it must never be decoded
// from a client override. IDs and this request alone confer no authority.
type UserGetRequest struct {
	TenantID TenantID
	UserID   UserID
	Context  authorization.DecisionContext
}

// UserGetResult is a permission-filtered directory snapshot, not a credential.
type UserGetResult struct{ User User }

// ActorID identifies the authenticated policy viewer; it is not an identity proof.
type ActorID string

// RedactionResource binds the exact resource kind and target being projected.
type RedactionResource struct {
	Kind string
	ID   string
}

// RedactionPolicyInput binds the viewer, tenant, operation, policy revision and
// deadline to a copied bounded projection. Callbacks are side-effect-free,
// concurrent-safe and must honor the supplied context; no stores/transactions.
type RedactionPolicyInput struct {
	TenantID      TenantID
	ViewerID      ActorID
	Resource      RedactionResource
	Fields        []FieldName
	OperationID   string
	PolicyVersion uint64
	Deadline      time.Time
}

// RedactionPolicyDecision describes exactly which requested fields are visible
// or redacted, with one registered policy ID/version. Unknown, overlapping or
// duplicate field names are invalid. Empty visibility omits the projection.
type RedactionPolicyDecision struct {
	VisibleFields  []FieldName
	RedactedFields []FieldName
	PolicyID       string
	PolicyVersion  uint64
	Reason         PolicyReason
}

// PolicyReason is a registered diagnostic code, never user or secret data.
// Read composition registers at most 32 unique codes, each 1..64 UTF-8 bytes
// without ASCII whitespace or control characters.
type PolicyReason string

// RedactFunc is the bounded, side-effect-free redaction policy callback.
type RedactFunc func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error)

// CanonicalUserIDValidator validates a directory ID without replacing it.
// Composition may accept existing ULIDs. It must be bounded, side-effect-free
// and concurrency-safe; errors are redacted at the service boundary.
type CanonicalUserIDValidator func(context.Context, UserID) error

// UserQueryConfig is explicit immutable read composition. Clock is sampled
// once per call at authorization; MaximumDuration is positive and at most one
// minute. PolicyID/version bind both authorization and redaction. All callbacks
// and dependencies must be bounded and concurrency-safe; no implicit defaults.
// RedactionReasons is copied at construction and cannot be empty.
type UserQueryConfig struct {
	Clock                   clock.Clock
	MaximumDuration         time.Duration
	PolicyID                string
	PolicyVersion           uint64
	RedactionReasons        []PolicyReason
	ValidateCanonicalUserID CanonicalUserIDValidator
}

// UserQueryService is the shared user-read implementation. It owns no store,
// goroutines or locks and grants no caller identity. Its constructor permits an
// explicit read-only composition without mutation/capability dependencies; the
// full identity service composes this same query implementation.
type UserQueryService struct {
	repo       UserQueryRepository
	authorize  authorization.Service
	redact     RedactFunc
	config     UserQueryConfig
	list       UserListRepository
	listConfig UserListConfig
}

// NewUserQueryService validates and snapshots the read composition without I/O.
// It rejects nil/typed-nil dependencies, missing policies and unbounded config.
func NewUserQueryService(repo UserQueryRepository, authorize authorization.Service, redact RedactFunc, config UserQueryConfig) (*UserQueryService, error) {
	if nilDependency(repo) {
		return nil, InvalidInputError{Field: "query_configuration"}
	}
	s, err := newQueryPolicy(authorize, redact, config)
	if err != nil {
		return nil, err
	}
	s.repo = repo
	return s, nil
}

// Mutation projection reuses the read policy without creating another store.
func newQueryPolicy(authorize authorization.Service, redact RedactFunc, config UserQueryConfig) (*UserQueryService, error) {
	if nilDependency(authorize) || nilDependency(config.Clock) || redact == nil || config.ValidateCanonicalUserID == nil || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute || !validDirectoryID(config.PolicyID) || config.PolicyVersion == 0 {
		return nil, InvalidInputError{Field: "query_configuration"}
	}
	if len(config.RedactionReasons) == 0 || len(config.RedactionReasons) > 32 {
		return nil, InvalidInputError{Field: "redaction_reasons"}
	}
	for i, reason := range config.RedactionReasons {
		if len(reason) > 64 || !validDirectoryID(string(reason)) || slices.Contains(config.RedactionReasons[:i], reason) {
			return nil, InvalidInputError{Field: "redaction_reasons"}
		}
	}
	config.RedactionReasons = slices.Clone(config.RedactionReasons)
	return &UserQueryService{authorize: authorize, redact: redact, config: config}, nil
}

// UserGet admits scope before policy or storage work, requires explicit Allow
// at the selected policy revision, checks authoritative output and applies
// redaction before disclosure. No provider hints/role strings grant authority.
// Repository absence is indistinguishable from forbidden output. Cancellation,
// callback panic/error and malformed outputs fail closed with no user returned.
func (s *UserQueryService) UserGet(ctx context.Context, req UserGetRequest) (result UserGetResult, err error) {
	defer func() {
		if recover() != nil {
			result = UserGetResult{}
			err = UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "query_context"}
	}
	if err := req.validate(s.config.PolicyVersion); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if err := readContextError(ctx); err != nil {
		return result, err
	}
	if err := s.config.ValidateCanonicalUserID(ctx, req.UserID); err != nil {
		if ctxErr := readContextError(ctx); ctxErr != nil {
			return result, ctxErr
		}
		return result, InvalidInputError{Field: "user_id"}
	}
	if err := readContextError(ctx); err != nil {
		return result, err
	}
	decisionContext := req.Context.Clone()
	now := s.config.Clock.Now()
	if now.IsZero() {
		return result, UnavailableError{}
	}
	decisionContext.Request.Environment.Time = now.UTC()
	decision, err := s.authorize.Decide(ctx, decisionContext)
	if ctxErr := readContextError(ctx); ctxErr != nil {
		return result, ctxErr
	}
	if err != nil {
		return result, UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.config.PolicyVersion) {
		return result, ForbiddenError{}
	}
	user, err := s.repo.Get(ctx, GetUserQuery{TenantID: req.TenantID, UserID: req.UserID, Fields: userProjectionFields()})
	if ctxErr := readContextError(ctx); ctxErr != nil {
		return result, ctxErr
	}
	if errors.Is(err, ErrUserAbsent) {
		return result, ForbiddenError{}
	}
	if err != nil || user.ID != req.UserID || user.Validate(req.TenantID) != nil {
		return result, UnavailableError{}
	}
	deadline, _ := ctx.Deadline()
	redaction, err := s.redact(ctx, RedactionPolicyInput{
		TenantID: req.TenantID, ViewerID: ActorID(req.Context.Request.Subject.ID),
		Resource: RedactionResource{Kind: "identity.user", ID: string(req.UserID)},
		Fields:   userProjectionFields(), OperationID: "identity.user.get",
		PolicyVersion: s.config.PolicyVersion, Deadline: deadline.UTC(),
	})
	if ctxErr := readContextError(ctx); ctxErr != nil {
		return result, ctxErr
	}
	if err != nil || !s.completeUserProjection(redaction) {
		return result, ForbiddenError{}
	}
	return UserGetResult{User: user}, nil
}

func (r UserGetRequest) validate(version uint64) error {
	return validateQueryContext(r.Context, r.TenantID, string(r.UserID), "identity.user.get", "identity.user", version)
}

func validateQueryContext(dc authorization.DecisionContext, tenant TenantID, target, action, resourceType string, version uint64) error {
	request := dc.Request
	if !validDirectoryID(string(tenant)) || !validDirectoryID(target) || !validDirectoryID(string(request.Subject.ID)) || request.Action != authorization.Action(action) || request.Resource.Type != authorization.ResourceType(resourceType) || request.Resource.ID != authorization.ResourceID(target) || request.Tenant != authorization.TenantID(tenant) || dc.PolicyRevision != authorization.Revision(version) {
		return InvalidInputError{Field: "query_scope"}
	}
	if request.Subject.Kind != authorization.SubjectUser && request.Subject.Kind != authorization.SubjectAPIKey && request.Subject.Kind != authorization.SubjectServiceAccount {
		return InvalidInputError{Field: "actor_kind"}
	}
	if len(request.Subject.Groups) > 32 {
		return InvalidInputError{Field: "actor_groups"}
	}
	for _, group := range request.Subject.Groups {
		if !validDirectoryID(string(group)) {
			return InvalidInputError{Field: "actor_groups"}
		}
	}
	for _, attributes := range []authorization.Attributes{request.Subject.Attributes, request.Resource.Attributes, request.Environment.Attributes, request.Attributes} {
		if len(attributes) > 128 {
			return InvalidInputError{Field: "authorization_attributes"}
		}
		for name, value := range attributes {
			if !validDirectoryID(string(name)) || value.Kind() == authorization.ValueMissing {
				return InvalidInputError{Field: "authorization_attributes"}
			}
			if text, ok := value.String(); ok && (len(text) > 4096 || !utf8.ValidString(text)) {
				return InvalidInputError{Field: "authorization_attributes"}
			}
			if n, ok := value.CollectionLength(); ok {
				if n > 64 {
					return InvalidInputError{Field: "authorization_attributes"}
				}
				items, _ := value.StringSet()
				for _, item := range items {
					if len(item) > 4096 || !utf8.ValidString(item) {
						return InvalidInputError{Field: "authorization_attributes"}
					}
				}
			}
		}
	}
	if dc.Validate() != nil {
		return InvalidInputError{Field: "decision_context"}
	}
	return nil
}

func userProjectionFields() []FieldName {
	return []FieldName{{"id"}, {"tenant_id"}, {"status"}, {"version"}}
}

func (s *UserQueryService) completeUserProjection(d RedactionPolicyDecision) bool {
	if d.PolicyID != s.config.PolicyID || d.PolicyVersion != s.config.PolicyVersion || !slices.Contains(s.config.RedactionReasons, d.Reason) || len(d.VisibleFields) != 4 || len(d.RedactedFields) != 0 {
		return false
	}
	var seen uint8
	for _, field := range d.VisibleFields {
		var bit uint8
		switch field.Value {
		case "id":
			bit = 1
		case "tenant_id":
			bit = 2
		case "status":
			bit = 4
		case "version":
			bit = 8
		default:
			return false
		}
		if seen&bit != 0 {
			return false
		}
		seen |= bit
	}
	return seen == 15
}

func readContextError(ctx context.Context) error {
	switch ctx.Err() {
	case context.Canceled:
		return CancelledError{}
	case context.DeadlineExceeded:
		return DeadlineExceededError{}
	default:
		return nil
	}
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
