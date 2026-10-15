package identity

import (
	"context"
	"math"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
)

// IdentifierKind selects an exact indexed identifier namespace. Empty means
// no identifier filter, not a wildcard namespace for a supplied value.
type IdentifierKind string

const (
	IdentifierEmail           IdentifierKind = "email"
	IdentifierPhone           IdentifierKind = "phone"
	IdentifierUsername        IdentifierKind = "username"
	IdentifierProviderSubject IdentifierKind = "provider-subject"
)

// UserListFilters contains exact indexed filters; at least one known status is
// required, at most 16, without duplicates. Identifier kind/value are paired.
// CanonicalIdentifier is at most 512 UTF-8 bytes, never free-text search.
type UserListFilters struct {
	Statuses            []Status
	IdentifierKind      IdentifierKind
	CanonicalIdentifier string
}

// Cursor is an immutable storage-neutral snapshot position, not authority.
// Its zero value starts a new snapshot. Only trusted repositories construct
// continuations; wire cursors are authenticated and decoded by the service.
type Cursor struct {
	snapshot SubjectID
	position uint64
}

// NewCursor constructs a repository continuation for a canonical random
// snapshot ID and a positive position no greater than MaxInt64. Adapters must
// never substitute a user's ID for the snapshot ID or recreate expired snapshots.
func NewCursor(snapshot SubjectID, position uint64) (Cursor, error) {
	if _, err := ParseSubjectID(string(snapshot)); err != nil || position == 0 || position > math.MaxInt64 {
		return Cursor{}, InvalidInputError{Field: "cursor"}
	}
	return Cursor{snapshot, position}, nil
}

// SnapshotID returns the opaque repository snapshot identifier, not a user ID.
func (c Cursor) SnapshotID() SubjectID { return c.snapshot }

// Position returns the number of snapshot rows already scanned.
func (c Cursor) Position() uint64 { return c.position }

// ListUsersQuery selects one authoritative stable snapshot. Users are ordered
// by the bytewise ascending canonical UserID, with no duplicates. A continuation
// must retain that snapshot and filters even when live directory state changes.
// Repositories must retain snapshots through ExpiresAt, scope them to TenantID
// and Filters, fail closed on expiry, and honor cancellation. Collections are
// call-owned; implementations must not mutate inputs or retain their aliases.
type ListUsersQuery struct {
	TenantID  TenantID
	Filters   UserListFilters
	Cursor    Cursor
	Limit     uint32
	Fields    []FieldName
	ExpiresAt time.Time
}

// UserPage is a caller-owned bounded ordered snapshot page. Next is absent
// only at the end; otherwise its position advances exactly by len(Users).
// An empty page is terminal. No totals or storage diagnostics are disclosed.
type UserPage struct {
	Users []User
	Next  Cursor
}

// UserListRepository owns authoritative snapshot selection and retention.
// Implementations must be concurrency-safe and obey ListUsersQuery semantics.
type UserListRepository interface {
	List(context.Context, ListUsersQuery) (UserPage, error)
}

// UserDirectoryRepository composes reads and listing without a parallel store.
type UserDirectoryRepository interface {
	UserQueryRepository
	UserListRepository
}

// UserListRequest binds a collection to a trusted authenticated upstream
// context. Resource type is identity.user.collection, ID is the exact tenant,
// and action is identity.user.list. The service overwrites reserved query
// attributes with the actual filters and limit, preventing dishonest bindings.
type UserListRequest struct {
	TenantID TenantID
	Filters  UserListFilters
	Cursor   string
	Limit    uint32
	Context  authorization.DecisionContext
}

// UserListResult contains only authorized/redacted users. NextCursor advances
// over all scanned rows, including omissions, without exposing hidden IDs.
type UserListResult struct {
	Users      []User
	NextCursor string
}

// UserListConfig is immutable explicit cursor composition. CursorKey must be
// an independently generated 256-bit secret (all-zero is invalid). It must not
// be logged; rotation invalidates old cursors. TTL is positive, at most 15m.
// The canonical identifier validator is bounded, concurrency-safe and must
// validate without rewriting indexed values. Cursor possession grants no access.
type UserListConfig struct {
	CursorKey                   [32]byte
	CursorTTL                   time.Duration
	ValidateCanonicalIdentifier func(context.Context, IdentifierKind, string) error
}

// NewUserDirectoryService composes the existing get implementation with
// listing; NewUserQueryService remains get-only. No repository or policy I/O is
// performed during construction and all configuration is copied.
func NewUserDirectoryService(repo UserDirectoryRepository, authorize authorization.Service, redact RedactFunc, config UserQueryConfig, listConfig UserListConfig) (*UserQueryService, error) {
	if listConfig.CursorKey == ([32]byte{}) || listConfig.CursorTTL <= 0 || listConfig.CursorTTL > 15*time.Minute || listConfig.ValidateCanonicalIdentifier == nil {
		return nil, InvalidInputError{Field: "list_configuration"}
	}
	s, err := NewUserQueryService(repo, authorize, redact, config)
	if err != nil {
		return nil, err
	}
	s.list, s.listConfig = repo, listConfig
	return s, nil
}

// UserList authorizes before reading and reauthorizes every snapshot row before
// applying redaction. Every page uses one clock sample and one bounded context.
// Denied rows are omitted; dependency failures, panics, malformed pages and
// cancellation return no partial result. A cursor cannot renew its original
// expiry, change its query/viewer/tenant/policy, or authorize a later page.
func (s *UserQueryService) UserList(ctx context.Context, req UserListRequest) (result UserListResult, err error) {
	defer func() {
		if recover() != nil {
			result = UserListResult{}
			err = UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "query_context"}
	}
	if s.list == nil {
		return result, UnavailableError{}
	}
	if err := validateQueryContext(req.Context, req.TenantID, string(req.TenantID), "identity.user.list", "identity.user.collection", s.config.PolicyVersion); err != nil {
		return result, err
	}
	if req.Limit == 0 || req.Limit > 100 || len(req.Cursor) > 1024 || !req.Filters.valid() {
		return result, InvalidInputError{Field: "list_query"}
	}
	req.Filters.Statuses = slices.Clone(req.Filters.Statuses)
	slices.Sort(req.Filters.Statuses)
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if err := readContextError(ctx); err != nil {
		return result, err
	}
	if req.Filters.IdentifierKind != "" {
		if err := s.listConfig.ValidateCanonicalIdentifier(ctx, req.Filters.IdentifierKind, req.Filters.CanonicalIdentifier); err != nil {
			if ctxErr := readContextError(ctx); ctxErr != nil {
				return result, ctxErr
			}
			return result, InvalidInputError{Field: "identifier_filter"}
		}
	}
	if err := readContextError(ctx); err != nil {
		return result, err
	}
	// Wall time selects the cursor validity interval once. Local monotonic time
	// accounts for subsequent work; decoding must not restart that interval.
	clockBoundary := time.Now()
	now := s.config.Clock.Now()
	expiry := now.Add(s.listConfig.CursorTTL)
	if now.IsZero() || now.UnixNano() <= 0 || !time.Unix(0, now.UnixNano()).Equal(now) || !time.Unix(0, expiry.UnixNano()).Equal(expiry) || expiry.UnixNano() <= now.UnixNano() {
		return result, UnavailableError{}
	}
	dc := req.Context.Clone()
	dc.Request.Environment.Time = now.UTC()
	statuses := make([]string, len(req.Filters.Statuses))
	for i, status := range req.Filters.Statuses {
		statuses[i] = string(status)
	}
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	dc.Request.Resource.Attributes["identity.query.statuses"] = authorization.StringSetValue(statuses)
	dc.Request.Resource.Attributes["identity.query.identifier_kind"] = authorization.StringValue(string(req.Filters.IdentifierKind))
	dc.Request.Resource.Attributes["identity.query.identifier"] = authorization.StringValue(req.Filters.CanonicalIdentifier)
	dc.Request.Resource.Attributes["identity.query.limit"] = authorization.IntValue(int64(req.Limit))
	// Reserve two per-row attributes without letting caller values stand in for
	// the actual snapshot state. The collection has no individual user state.
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.NullValue()
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.NullValue()
	if len(dc.Request.Resource.Attributes) > 128 {
		return result, InvalidInputError{Field: "authorization_attributes"}
	}
	binding := listBinding(req, s.config)
	claims := cursorClaims{Binding: binding, Issued: now.UnixNano(), Expires: expiry.UnixNano()}
	if req.Cursor != "" {
		claims, err = s.listConfig.openCursor(req.Cursor, binding, now)
		if err != nil {
			return result, err
		}
	}
	remaining := time.Duration(claims.Expires-now.UnixNano()) - time.Since(clockBoundary)
	ctx, cancelSnapshot := context.WithTimeout(ctx, remaining)
	defer cancelSnapshot()
	if err := readContextError(ctx); err != nil {
		return result, err
	}
	decision, err := s.authorize.Decide(ctx, dc.Clone())
	if ctxErr := readContextError(ctx); ctxErr != nil {
		return result, ctxErr
	}
	if err != nil {
		return result, UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.config.PolicyVersion) {
		return result, ForbiddenError{}
	}
	query := ListUsersQuery{TenantID: req.TenantID, Filters: req.Filters, Cursor: claims.Cursor, Limit: req.Limit, Fields: userProjectionFields(), ExpiresAt: time.Unix(0, claims.Expires).UTC()}
	// Keep the policy-binding filters independent of repository-owned call data.
	query.Filters.Statuses = slices.Clone(req.Filters.Statuses)
	page, err := s.list.List(ctx, query)
	if ctxErr := readContextError(ctx); ctxErr != nil {
		return result, ctxErr
	}
	if err != nil || !page.valid(req, claims.Cursor, claims.Last) {
		return result, UnavailableError{}
	}
	users := make([]User, 0, len(page.Users))
	deadline, _ := ctx.Deadline()
	for _, user := range page.Users {
		if err := s.config.ValidateCanonicalUserID(ctx, user.ID); err != nil {
			if ctxErr := readContextError(ctx); ctxErr != nil {
				return result, ctxErr
			}
			return result, UnavailableError{}
		}
		if err := readContextError(ctx); err != nil {
			return result, err
		}
		row := dc.Clone()
		row.Request.Resource.Type, row.Request.Resource.ID = "identity.user", authorization.ResourceID(user.ID)
		row.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(user.Status))
		row.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(user.Version, 10))
		decision, err := s.authorize.Decide(ctx, row)
		if ctxErr := readContextError(ctx); ctxErr != nil {
			return result, ctxErr
		}
		if err != nil {
			return result, UnavailableError{}
		}
		if decision.Revision != authorization.Revision(s.config.PolicyVersion) {
			return result, ForbiddenError{}
		}
		if decision.Outcome != authorization.Allow {
			continue
		}
		redaction, err := s.redact(ctx, RedactionPolicyInput{TenantID: req.TenantID, ViewerID: ActorID(req.Context.Request.Subject.ID), Resource: RedactionResource{Kind: "identity.user", ID: string(user.ID)}, Fields: userProjectionFields(), OperationID: "identity.user.list", PolicyVersion: s.config.PolicyVersion, Deadline: deadline.UTC()})
		if ctxErr := readContextError(ctx); ctxErr != nil {
			return result, ctxErr
		}
		if err != nil {
			return result, ForbiddenError{}
		}
		if !s.completeUserProjection(redaction) {
			continue
		}
		users = append(users, user)
	}
	if page.Next != (Cursor{}) {
		claims.Cursor = page.Next
		claims.Last = page.Users[len(page.Users)-1].ID
		result.NextCursor = s.listConfig.sealCursor(claims)
	}
	if err := readContextError(ctx); err != nil {
		return UserListResult{}, err
	}
	result.Users = users
	return result, nil
}

func (f UserListFilters) valid() bool {
	if len(f.Statuses) == 0 || len(f.Statuses) > 16 {
		return false
	}
	for i, status := range f.Statuses {
		if !status.Valid() || slices.Contains(f.Statuses[:i], status) {
			return false
		}
	}
	if f.IdentifierKind == "" {
		return f.CanonicalIdentifier == ""
	}
	if !f.IdentifierKind.Valid() {
		return false
	}
	return len(f.CanonicalIdentifier) > 0 && len(f.CanonicalIdentifier) <= 512 && utf8.ValidString(f.CanonicalIdentifier)
}

func (p UserPage) valid(req UserListRequest, previous Cursor, last UserID) bool {
	if len(p.Users) > int(req.Limit) {
		return false
	}
	for i, user := range p.Users {
		if user.Validate(req.TenantID) != nil || !slices.Contains(req.Filters.Statuses, user.Status) || (i == 0 && user.ID <= last) || (i > 0 && p.Users[i-1].ID >= user.ID) {
			return false
		}
	}
	if p.Next == (Cursor{}) {
		return true
	}
	if len(p.Users) == 0 || previous.position > math.MaxInt64-uint64(len(p.Users)) || p.Next.position != previous.position+uint64(len(p.Users)) {
		return false
	}
	if _, err := NewCursor(p.Next.snapshot, p.Next.position); err != nil {
		return false
	}
	return previous == (Cursor{}) || previous.snapshot == p.Next.snapshot
}
