package email

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// Cursor is a bounded opaque address-page position, not permission or freshness.
// Empty selects the first page. Treat its explicit string value as personal data.
type Cursor string

// AddressGetRequest selects one address under a trusted authenticated caller.
// An omitted target means the caller's human subject. Caller and tenant must be
// supplied by authenticated composition, not decoded from a public request.
type AddressGetRequest struct {
	TenantID        identity.TenantID
	TargetSubjectID identity.UserID
	AddressID       identity.IdentifierID
	Caller          authorization.DecisionContext
}

// AddressGetResult is an authorized primary observation, never a commit or lease.
// Success uses Outcome NotCommitted because this operation performs no mutation.
type AddressGetResult struct {
	Outcome identity.CommitOutcome
	Address identity.IdentifierProjection
}

// AddressListRequest selects a bounded page under current owner/admin policy.
// Zero Limit defaults to 25; 1..100 is accepted. Cursor cannot cross the exact
// tenant, target, actor, policy or page-size scope or a changed primary snapshot.
type AddressListRequest struct {
	TenantID        identity.TenantID
	TargetSubjectID identity.UserID
	Cursor          Cursor
	Limit           uint32
	Caller          authorization.DecisionContext
}

// AddressListResult owns its address slice. Success may be an empty non-nil
// slice and reports NotCommitted. NextCursor is empty after the final page.
type AddressListResult struct {
	Outcome    identity.CommitOutcome
	Addresses  []identity.IdentifierProjection
	NextCursor Cursor
}

// AddressQueryService owns authorized email reads, not storage, mutation,
// credential validation or sessions. It owns no resources or goroutines.
type AddressQueryService struct {
	repo   identity.IdentifierRepository
	auth   authorization.Service
	redact identity.RedactFunc
	config identity.UserQueryConfig
}

// NewAddressQueryService composes platform-owned primary storage and existing
// authorization/redaction contracts. All dependencies must honor bounded
// contexts and support concurrent calls; callers retain their ownership.
func NewAddressQueryService(repo identity.IdentifierRepository, auth authorization.Service, redact identity.RedactFunc, config identity.UserQueryConfig) (*AddressQueryService, error) {
	if nilAddressDependency(repo) || nilAddressDependency(auth) || nilAddressDependency(config.Clock) || redact == nil || config.ValidateCanonicalUserID == nil || config.MaximumDuration <= 0 || config.MaximumDuration > time.Minute || !verificationID(config.PolicyID) || config.PolicyVersion == 0 || len(config.RedactionReasons) == 0 || len(config.RedactionReasons) > 32 {
		return nil, identity.InvalidInputError{Field: "email_query_configuration"}
	}
	for index, reason := range config.RedactionReasons {
		if len(reason) > 64 || !verificationID(string(reason)) || slices.Contains(config.RedactionReasons[:index], reason) {
			return nil, identity.InvalidInputError{Field: "email_query_configuration"}
		}
	}
	config.RedactionReasons = slices.Clone(config.RedactionReasons)
	return &AddressQueryService{repo: repo, auth: auth, redact: redact, config: config}, nil
}

// AddressGet authorizes exact scope before primary IO and again against current
// state. Absent, non-email, cross-tenant and forbidden targets are indistinguishable.
func (s *AddressQueryService) AddressGet(ctx context.Context, request AddressGetRequest) (out AddressGetResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AddressGetResult{}, identity.UnavailableError{}
		}
	}()
	if s == nil || ctx == nil || !verificationID(string(request.AddressID)) {
		return out, identity.InvalidInputError{Field: "email_query"}
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	state, dc, now, err := s.read(bounded, request.TenantID, request.TargetSubjectID, request.Caller, "identity.email.address-get")
	if err != nil {
		return out, err
	}
	for _, address := range state.Identifiers {
		if address.ID == request.AddressID && address.Kind == identity.IdentifierEmail {
			projection, err := s.project(bounded, state, dc, address.ID, now)
			if err != nil {
				return out, err
			}
			return AddressGetResult{Outcome: identity.CommitOutcomeNotCommitted, Address: projection}, nil
		}
	}
	return out, identity.ForbiddenError{}
}

// AddressList returns only safe versioned email projections under current policy.
// It never truncates an unavailable primary partition or consumes a bearer.
func (s *AddressQueryService) AddressList(ctx context.Context, request AddressListRequest) (out AddressListResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = AddressListResult{}, identity.UnavailableError{}
		}
	}()
	if s == nil || ctx == nil || request.Limit > 100 || len(request.Cursor) > 512 {
		return out, identity.InvalidInputError{Field: "email_query"}
	}
	limit := request.Limit
	if limit == 0 {
		limit = 25
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	state, dc, now, err := s.read(bounded, request.TenantID, request.TargetSubjectID, request.Caller, "identity.email.address-list")
	if err != nil {
		return out, err
	}
	binding := s.cursorBinding(dc, limit)
	start := 0
	if request.Cursor != "" {
		last, err := decodeAddressCursor(request.Cursor, state, binding)
		if err != nil {
			return out, err
		}
		start = slices.IndexFunc(state.Identifiers, func(address identity.Identifier) bool {
			return address.ID == last && address.Kind == identity.IdentifierEmail
		})
		if start < 0 {
			return out, identity.InvalidInputError{Field: "email_cursor"}
		}
		start++
	}
	addresses := make([]identity.IdentifierProjection, 0, limit)
	var last identity.IdentifierID
	var next Cursor
	for _, address := range state.Identifiers[start:] {
		if address.Kind != identity.IdentifierEmail {
			continue
		}
		if len(addresses) == int(limit) {
			next = encodeAddressCursor(state, binding, last)
			break
		}
		projection, err := s.project(bounded, state, dc, address.ID, now)
		if err != nil {
			return out, err
		}
		addresses = append(addresses, projection)
		last = address.ID
	}
	if err := addressContextError(bounded); err != nil {
		return out, err
	}
	return AddressListResult{Outcome: identity.CommitOutcomeNotCommitted, Addresses: addresses, NextCursor: next}, nil
}

func (s *AddressQueryService) read(ctx context.Context, tenant identity.TenantID, target identity.UserID, caller authorization.DecisionContext, action authorization.Action) (identity.IdentifierState, authorization.DecisionContext, time.Time, error) {
	zero := identity.IdentifierState{}
	empty := authorization.DecisionContext{}
	if err := addressContextError(ctx); err != nil {
		return zero, empty, time.Time{}, err
	}
	// Browser/transport input cannot redirect authenticated tenant authority.
	if caller.Request.Tenant != authorization.TenantID(tenant) {
		return zero, empty, time.Time{}, identity.ForbiddenError{}
	}
	if target == "" {
		if caller.Request.Subject.Kind != authorization.SubjectUser {
			return zero, empty, time.Time{}, identity.ForbiddenError{}
		}
		target = identity.UserID(caller.Request.Subject.ID)
	}
	if !verificationID(string(target)) || caller.Request.Resource.ID != authorization.ResourceID(target) || caller.PolicyRevision != authorization.Revision(s.config.PolicyVersion) || validateEmailCaller(tenant, caller, action) != nil {
		return zero, empty, time.Time{}, identity.ForbiddenError{}
	}
	if err := s.config.ValidateCanonicalUserID(ctx, target); err != nil {
		if cancelled := addressContextError(ctx); cancelled != nil {
			return zero, empty, time.Time{}, cancelled
		}
		return zero, empty, time.Time{}, identity.ForbiddenError{}
	}
	now := s.config.Clock.Now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return zero, empty, time.Time{}, identity.UnavailableError{}
	}
	dc := caller.Clone()
	dc.Request.Environment.Time = now
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for key := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(key), "identity.") {
			delete(dc.Request.Resource.Attributes, key)
		}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(true)
	dc.Request.Resource.Attributes["identity.email.administrative-target"] = authorization.BoolValue(string(target) != string(dc.Request.Subject.ID) || dc.Request.Subject.Kind != authorization.SubjectUser)
	if err := s.allow(ctx, dc); err != nil {
		return zero, empty, time.Time{}, err
	}
	state, err := s.repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: tenant, UserID: target, MaximumIdentifiers: 128})
	if cancelled := addressContextError(ctx); cancelled != nil {
		return zero, empty, time.Time{}, cancelled
	}
	if errors.Is(err, identity.ErrUserAbsent) {
		return zero, empty, time.Time{}, identity.ForbiddenError{}
	}
	if err != nil {
		return zero, empty, time.Time{}, identity.UnavailableError{}
	}
	if state.User.Validate(tenant) != nil || state.User.ID != target || state.AuthorityVersion == 0 || len(state.Identifiers) > 128 || len(state.Identifiers) != len(state.Verifications) {
		return zero, empty, time.Time{}, identity.UnavailableError{}
	}
	if len(state.Identifiers) != 0 {
		// The kernel projection validates the complete ordered partition, including
		// non-email rows and duplicate values/primaries, without disclosing values.
		if _, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: tenant, UserID: target, IdentifierID: state.Identifiers[0].ID, State: state, Values: identity.IdentifierValuesOmitted, ObservedAt: now}); err != nil {
			return zero, empty, time.Time{}, identity.UnavailableError{}
		}
	}
	if dc.Request.Subject.Kind == authorization.SubjectUser && string(dc.Request.Subject.ID) == string(target) && !state.User.Status.AllowsAuthentication() {
		return zero, empty, time.Time{}, identity.ForbiddenError{}
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(state.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(state.User.Version, 10))
	dc.Request.Resource.Attributes["identity.identifier.authority-version"] = authorization.StringValue(strconv.FormatUint(state.AuthorityVersion, 10))
	if err := s.allow(ctx, dc); err != nil {
		return zero, empty, time.Time{}, err
	}
	return state, dc, now, nil
}

func (s *AddressQueryService) allow(ctx context.Context, dc authorization.DecisionContext) error {
	if err := addressContextError(ctx); err != nil {
		return err
	}
	decision, err := s.auth.Decide(ctx, dc)
	if cancelled := addressContextError(ctx); cancelled != nil {
		return cancelled
	}
	if err != nil || decision.Revision != authorization.Revision(s.config.PolicyVersion) || decision.Outcome != authorization.Allow && decision.Outcome != authorization.Deny {
		return identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *AddressQueryService) project(ctx context.Context, state identity.IdentifierState, dc authorization.DecisionContext, id identity.IdentifierID, now time.Time) (identity.IdentifierProjection, error) {
	deadline, _ := ctx.Deadline()
	decision, err := s.redact(ctx, identity.RedactionPolicyInput{TenantID: state.User.TenantID, ViewerID: identity.ActorID(dc.Request.Subject.ID), Resource: identity.RedactionResource{Kind: "identity.email", ID: string(id)}, Fields: []identity.FieldName{{Value: "canonical_value"}, {Value: "display_value"}}, OperationID: string(dc.Request.Action), PolicyVersion: s.config.PolicyVersion, Deadline: deadline.UTC()})
	if cancelled := addressContextError(ctx); cancelled != nil {
		return identity.IdentifierProjection{}, cancelled
	}
	if err != nil || decision.PolicyID != s.config.PolicyID || decision.PolicyVersion != s.config.PolicyVersion || !slices.Contains(s.config.RedactionReasons, decision.Reason) || len(decision.VisibleFields)+len(decision.RedactedFields) != 2 {
		return identity.IdentifierProjection{}, identity.UnavailableError{}
	}
	// The kernel exposes both values or neither, never a silently widened
	// partially redacted projection. Metadata already passed current policy.
	fields := decision.VisibleFields
	visibility := identity.IdentifierValuesIncluded
	if len(fields) == 0 {
		fields, visibility = decision.RedactedFields, identity.IdentifierValuesOmitted
	}
	if len(fields) != 2 || fields[0].Value == fields[1].Value || !slices.Contains(fields, identity.FieldName{Value: "canonical_value"}) || !slices.Contains(fields, identity.FieldName{Value: "display_value"}) {
		return identity.IdentifierProjection{}, identity.UnavailableError{}
	}
	projection, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: state.User.TenantID, UserID: state.User.ID, IdentifierID: id, State: state, Values: visibility, ObservedAt: now})
	if err != nil {
		return identity.IdentifierProjection{}, identity.UnavailableError{}
	}
	return projection, nil
}

func (s *AddressQueryService) cursorBinding(dc authorization.DecisionContext, limit uint32) [32]byte {
	// A cursor is not a signed credential. Binding rejects accidental reuse;
	// every page separately authenticates/authorizes and reads primary state.
	h := sha256.New()
	_, _ = h.Write([]byte("identity-email-page-v1\x00"))
	for _, field := range []string{string(dc.Request.Tenant), string(dc.Request.Resource.ID), string(dc.Request.Subject.ID), string(dc.Request.Subject.Kind), s.config.PolicyID, strconv.FormatUint(s.config.PolicyVersion, 10), string(dc.Request.Action), strconv.FormatUint(uint64(limit), 10)} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(field))
	}
	var binding [32]byte
	copy(binding[:], h.Sum(nil))
	return binding
}

func encodeAddressCursor(state identity.IdentifierState, binding [32]byte, last identity.IdentifierID) Cursor {
	encoded := make([]byte, 49+len(last))
	encoded[0] = 1
	binary.BigEndian.PutUint64(encoded[1:9], state.User.Version)
	binary.BigEndian.PutUint64(encoded[9:17], state.AuthorityVersion)
	copy(encoded[17:49], binding[:])
	copy(encoded[49:], last)
	return Cursor(base64.RawURLEncoding.EncodeToString(encoded))
}

func decodeAddressCursor(cursor Cursor, state identity.IdentifierState, binding [32]byte) (identity.IdentifierID, error) {
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(string(cursor))
	if err != nil || len(encoded) < 50 || len(encoded) > 177 || encoded[0] != 1 || base64.RawURLEncoding.EncodeToString(encoded) != string(cursor) || !verificationID(string(encoded[49:])) {
		return "", identity.InvalidInputError{Field: "email_cursor"}
	}
	if string(encoded[17:49]) != string(binding[:]) {
		return "", identity.ForbiddenError{}
	}
	if binary.BigEndian.Uint64(encoded[1:9]) != state.User.Version || binary.BigEndian.Uint64(encoded[9:17]) != state.AuthorityVersion {
		return "", identity.ConflictError{}
	}
	return identity.IdentifierID(encoded[49:]), nil
}

func nilAddressDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func addressContextError(ctx context.Context) error {
	switch ctx.Err() {
	case context.Canceled:
		return identity.CancelledError{}
	case context.DeadlineExceeded:
		return identity.DeadlineExceededError{}
	default:
		return nil
	}
}
