package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization"
)

// UserProfile is the self-service projection. It deliberately has no email,
// status, roles, credentials or authentication authority. AdditionalFields are
// private copies filtered by schema output permission and current redaction.
// Version is the positive identity aggregate version, not session freshness.
// Formatting is redacted; explicit response serialization is caller-owned.
type UserProfile struct {
	ID               UserID
	TenantID         TenantID
	Name             string
	Image            string
	Version          uint64
	AdditionalFields []AttributeUpdate
}

// Format prevents implicit display of personal profile contents.
func (UserProfile) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "identity.UserProfile(redacted)")
}

// ProfileRecord is an authoritative internal-port snapshot. User and Profile
// must agree on tenant, subject and aggregate version. Only active users may
// self-service. User's lifecycle metadata never enters the public projection.
type ProfileRecord struct {
	User    User
	Profile UserProfile
}

// ProfileQuery requests an exact subject/tenant projection from primary state.
// Fields is bounded and privately owned; no pagination, arbitrary target or
// cache is allowed. Repositories must return one consistent aggregate snapshot.
type ProfileQuery struct {
	TenantID TenantID
	UserID   UserID
	Fields   []FieldName
}

// ProfileRepository owns consistent profile reads. GetProfile is bounded and
// concurrent-safe, returns ErrUserAbsent for absence, and never confers authority.
type ProfileRepository interface {
	GetProfile(context.Context, ProfileQuery) (ProfileRecord, error)
}

// ProfileGetRequest supplies trusted authenticated composition, never client
// JSON. The current human subject is the only target; resource ID must match it.
// Session validation is the session/transport owner, not these scope fields.
type ProfileGetRequest struct {
	TenantID TenantID
	Context  authorization.DecisionContext
}

// ProfileGetResult is the current permission-filtered self projection.
type ProfileGetResult struct {
	User    UserProfile
	Version uint64
}

// ProfileUpdateRequest is the explicit-command core boundary. Empty Name/Image
// mean omitted, not clearing. Additional values retain false/zero/empty presence.
// ExpectedVersion is positive and cannot overflow its next version. Preserve
// CommandID and logical intent on retries; HTTP keyed/session/CSRF admission
// will compose this boundary and must not decode Context from a request body.
type ProfileUpdateRequest struct {
	TenantID         TenantID
	Context          authorization.DecisionContext
	CommandID        CommandID
	SchemaVersion    uint32
	ExpectedVersion  uint64
	Name             string
	Image            string
	AdditionalFields []AttributeUpdate
	CorrelationID    string
}

// ProfileUpdateResult preserves known outcome even when current disclosure fails.
// User/InvalidationVersion are zero when output is withheld. Invalid means no
// authoritative outcome observation, never inferred rollback of a prior attempt.
type ProfileUpdateResult struct {
	User                UserProfile
	InvalidationVersion uint64
	CommandID           CommandID
	CommitOutcome       CommitOutcome
}

// ProfileRecoveryRequest performs current-subject scoped primary recovery only;
// no new fields, alternate target or mutation may be submitted.
type ProfileRecoveryRequest struct {
	TenantID  TenantID
	CommandID CommandID
	Context   authorization.DecisionContext
}

// ProfileConfig freezes field/time/current-policy composition and 1..32 exact
// canonical HTTPS image origins. Images are never fetched. No wildcard, userinfo,
// query, path, fragment or opaque origin is supported. Origins must match URL
// authority exactly; default ports are not silently equivalent to explicit ones.
type ProfileConfig struct {
	Fields              UserCreationConfig
	AllowedImageOrigins []string
}

// ProfileService owns self-service reads, mutation and recovery without stores,
// workers or raw transactions. Dependencies remain caller-owned, bounded and
// concurrency-safe. Construction snapshots configuration without I/O.
type ProfileService struct {
	repo     ProfileRepository
	creation *UserCreationService
	origins  []string
}

// NewProfileService composes the existing field, authorization and command owners.
func NewProfileService(repo ProfileRepository, uow UnitOfWork, authorize authorization.Service, redact RedactFunc, config ProfileConfig) (*ProfileService, error) {
	if nilDependency(repo) || len(config.AllowedImageOrigins) == 0 || len(config.AllowedImageOrigins) > 32 || len(config.Fields.Schema.Fields) > 123 {
		return nil, InvalidInputError{Field: "profile_configuration"}
	}
	for i, origin := range config.AllowedImageOrigins {
		if len(origin) > 2048 || !utf8.ValidString(origin) {
			return nil, InvalidInputError{Field: "image_origins"}
		}
		u, e := url.Parse(origin)
		if e != nil || !validImageURL(u) || u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(origin, "#") || u.String() != origin || slices.Contains(config.AllowedImageOrigins[:i], origin) {
			return nil, InvalidInputError{Field: "image_origins"}
		}
	}
	for _, field := range config.Fields.Schema.Fields {
		if forbiddenProfileField(field.Name) {
			return nil, InvalidInputError{Field: "profile_schema"}
		}
	}
	creation, e := NewUserCreationService(uow, authorize, redact, config.Fields)
	if e != nil {
		return nil, e
	}
	return &ProfileService{repo: repo, creation: creation, origins: slices.Clone(config.AllowedImageOrigins)}, nil
}

// UnauthenticatedError is missing human identity; it retains no caller data.
type UnauthenticatedError struct{}

func (UnauthenticatedError) Error() string { return "identity: unauthenticated" }

// ProfileGet returns only the exact current human subject's safe projection.
// Absence, blocking and output denial are indistinguishable ForbiddenError.
func (s *ProfileService) ProfileGet(ctx context.Context, req ProfileGetRequest) (out ProfileGetResult, err error) {
	defer func() {
		if recover() != nil {
			out = ProfileGetResult{}
			err = UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "profile_context"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.creation.policy.config.MaximumDuration)
	defer cancel()
	dc, _, e := s.admit(ctx, req, "identity.profile.get", false)
	if e != nil {
		return out, e
	}
	record, e := s.read(ctx, req.TenantID, UserID(dc.Request.Subject.ID))
	if e != nil {
		return out, e
	}
	dc = profileCurrentContext(dc, record.User)
	if e := s.creation.attributes.allow(ctx, dc); e != nil {
		return out, e
	}
	profile, e := s.project(ctx, record.Profile, dc)
	if e != nil {
		return out, e
	}
	return ProfileGetResult{User: profile, Version: profile.Version}, nil
}

// ProfileUpdate authorizes current state and every self-writable field before a
// stable command. New writes must CAS the locked version and active status after
// command replay lookup. Its one clock sample is reused for field decisions.
func (s *ProfileService) ProfileUpdate(ctx context.Context, req ProfileUpdateRequest) (out ProfileUpdateResult, err error) {
	attempted := false
	defer func() {
		if recover() != nil {
			out.User = UserProfile{}
			out.InvalidationVersion = 0
			if attempted && out.CommitOutcome == CommitOutcomeUnknown {
				err = UnknownCommitError{req.CommandID}
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "profile_context"}
	}
	if _, ok := decodeID(string(req.CommandID)); !ok {
		return out, InvalidInputError{Field: "command_id"}
	}
	out.CommandID = req.CommandID
	if e := validateProfileChanges(req.Name, req.Image, req.AdditionalFields, req.ExpectedVersion); e != nil {
		return out, e
	}
	image, e := s.image(req.Image)
	if e != nil {
		return out, e
	}
	if req.CorrelationID == "" {
		req.CorrelationID = string(req.CommandID)
	}
	if !validDirectoryID(req.CorrelationID) {
		return out, InvalidInputError{Field: "correlation_id"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.creation.policy.config.MaximumDuration)
	defer cancel()
	dc, now, e := s.admit(ctx, ProfileGetRequest{req.TenantID, req.Context}, "identity.profile.update", false)
	if e != nil {
		return out, e
	}
	id := UserID(dc.Request.Subject.ID)
	record, e := s.read(ctx, req.TenantID, id)
	if e != nil {
		return out, e
	}
	if req.ExpectedVersion > record.User.Version {
		return out, ConflictError{req.CommandID}
	}
	dc = profileCurrentContext(dc, record.User)
	for _, update := range req.AdditionalFields {
		field, ok := s.creation.attributes.field(update.Name)
		if !ok || forbiddenProfileField(update.Name) {
			return out, InvalidInputError{Field: "profile_fields"}
		}
		if field.WriteAuthorization != FieldWriteSelf {
			return out, ForbiddenError{}
		}
	}
	fields, e := s.creation.attributes.prepare(ctx, AttributePrepareRequest{TenantID: req.TenantID, UserID: id, SchemaVersion: req.SchemaVersion, Updates: req.AdditionalFields, Context: dc}, now)
	if e != nil {
		return out, e
	}
	for _, name := range []string{"name", "image"} {
		if name == "name" && req.Name == "" || name == "image" && image == "" {
			continue
		}
		fdc := dc.Clone()
		fdc.Request.Resource.Attributes["identity.field"] = authorization.StringValue(name)
		fdc.Request.Resource.Attributes["identity.field.write_class"] = authorization.StringValue("self")
		fdc.Request.Resource.Attributes["identity.field.sensitivity"] = authorization.StringValue("personal")
		if e := s.creation.attributes.allow(ctx, fdc); e != nil {
			return out, e
		}
	}
	policy := s.creation.policy.config
	binding := CommandBinding{CommandID: req.CommandID, TenantID: req.TenantID, UserID: id, ActorID: ActorID(id), ActorKind: authorization.SubjectUser, OperationID: "identity.profile.update", PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion, SchemaID: s.creation.attributes.schema.ID, SchemaVersion: req.SchemaVersion, CorrelationID: req.CorrelationID}
	command, e := NewProfileUpdateCommand(ProfileUpdateCommand{Binding: binding, ExpectedVersion: req.ExpectedVersion, Name: req.Name, Image: image, AdditionalFields: fields})
	if e != nil {
		return out, e
	}
	if e := readContextError(ctx); e != nil {
		return out, e
	}
	attempted = true
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.creation.uow.Execute(ctx, command)
	if !receipt.valid() || receipt.Binding != binding || receipt.Outcome == CommitOutcomeCommitted && receipt.ExpectedVersion != req.ExpectedVersion {
		return out, unknownError(ctx, req.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, dependencyErr, dc)
}

// RecoverProfileUpdate reads the original command under current subject/purpose
// authorization and redaction. Its result is historic, never login authority.
func (s *ProfileService) RecoverProfileUpdate(ctx context.Context, req ProfileRecoveryRequest) (out ProfileUpdateResult, err error) {
	defer func() {
		if recover() != nil {
			out.User = UserProfile{}
			out.InvalidationVersion = 0
			if out.CommitOutcome == CommitOutcomeUnknown {
				err = unknownError(ctx, req.CommandID)
			} else {
				err = UnavailableError{}
			}
		}
	}()
	if s == nil || ctx == nil {
		return out, InvalidInputError{Field: "profile_context"}
	}
	if _, ok := decodeID(string(req.CommandID)); !ok {
		return out, InvalidInputError{Field: "command_id"}
	}
	out.CommandID = req.CommandID
	ctx, cancel := context.WithTimeout(ctx, s.creation.policy.config.MaximumDuration)
	defer cancel()
	dc, _, e := s.admit(ctx, ProfileGetRequest{req.TenantID, req.Context}, "identity.profile.update", true)
	if e != nil {
		return out, e
	}
	id := UserID(dc.Request.Subject.ID)
	out.CommitOutcome = CommitOutcomeUnknown
	receipt, dependencyErr := s.creation.uow.Recover(ctx, RecoveryQuery{CommandID: req.CommandID, TenantID: req.TenantID, UserID: id, ActorID: ActorID(id), ActorKind: authorization.SubjectUser, OperationID: "identity.profile.update"})
	if !receipt.valid() || receipt.Binding.CommandID != req.CommandID || receipt.Binding.TenantID != req.TenantID || receipt.Binding.UserID != id || receipt.Binding.ActorID != ActorID(id) || receipt.Binding.ActorKind != authorization.SubjectUser || receipt.Binding.OperationID != "identity.profile.update" {
		return out, unknownError(ctx, req.CommandID)
	}
	out.CommitOutcome = receipt.Outcome
	return s.finish(ctx, out, receipt, dependencyErr, dc)
}

func (s *ProfileService) admit(ctx context.Context, req ProfileGetRequest, operation string, recovery bool) (authorization.DecisionContext, time.Time, error) {
	dc := req.Context
	if dc.Request.Subject.ID == "" {
		return dc, time.Time{}, UnauthenticatedError{}
	}
	if dc.Request.Subject.Kind != authorization.SubjectUser {
		return dc, time.Time{}, ForbiddenError{}
	}
	id := UserID(dc.Request.Subject.ID)
	policy := s.creation.policy.config
	if e := validateQueryContext(dc, req.TenantID, string(id), operation, "identity.user", policy.PolicyVersion); e != nil {
		return dc, time.Time{}, e
	}
	if e := readContextError(ctx); e != nil {
		return dc, time.Time{}, e
	}
	if e := policy.ValidateCanonicalUserID(ctx, id); e != nil {
		if e := readContextError(ctx); e != nil {
			return dc, time.Time{}, e
		}
		return dc, time.Time{}, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return dc, time.Time{}, e
	}
	now := policy.Clock.Now()
	if now.IsZero() {
		return dc, now, UnavailableError{}
	}
	dc = dc.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for _, key := range []authorization.AttributeName{"identity.user.status", "identity.user.version", "identity.field", "identity.field.write_class", "identity.field.sensitivity", "identity.schema.id", "identity.schema.version", "identity.fields.first", "identity.fields.second"} {
		delete(dc.Request.Resource.Attributes, key)
	}
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(!recovery)
	dc.Request.Resource.Attributes["identity.command.recovery"] = authorization.BoolValue(recovery)
	if e := s.creation.attributes.allow(ctx, dc); e != nil {
		return dc, now, e
	}
	return dc, now, nil
}

func (s *ProfileService) read(ctx context.Context, tenant TenantID, id UserID) (ProfileRecord, error) {
	r, e := s.repo.GetProfile(ctx, ProfileQuery{tenant, id, s.fields()})
	if e := readContextError(ctx); e != nil {
		return ProfileRecord{}, e
	}
	if errors.Is(e, ErrUserAbsent) {
		return ProfileRecord{}, ForbiddenError{}
	}
	if e != nil || r.User.Validate(tenant) != nil || r.User.ID != id || !validProfile(r.Profile) || r.Profile.ID != id || r.Profile.TenantID != tenant || r.Profile.Version != r.User.Version {
		return ProfileRecord{}, UnavailableError{}
	}
	if r.User.Status != StatusActive {
		return ProfileRecord{}, ForbiddenError{}
	}
	if e := s.validateProjection(r.Profile); e != nil {
		return ProfileRecord{}, e
	}
	r.Profile.AdditionalFields = cloneUpdates(r.Profile.AdditionalFields)
	return r, nil
}

func profileCurrentContext(dc authorization.DecisionContext, user User) authorization.DecisionContext {
	dc.Request.Resource.Attributes["identity.command.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(user.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(user.Version, 10))
	return dc
}

func (s *ProfileService) finish(ctx context.Context, out ProfileUpdateResult, r CommandResult, dependencyErr error, dc authorization.DecisionContext) (ProfileUpdateResult, error) {
	if r.Outcome == CommitOutcomeUnknown {
		return out, unknownError(ctx, out.CommandID)
	}
	if e := readContextError(ctx); e != nil {
		return out, e
	}
	if dependencyErr != nil {
		return out, UnavailableError{}
	}
	switch r.Outcome {
	case CommitOutcomeConflict:
		return out, ConflictError{out.CommandID}
	case CommitOutcomeNotCommitted:
		return out, NotCommittedError{out.CommandID}
	case CommitOutcomeInProgress:
		return out, InProgressError{out.CommandID, r.RetryAfter}
	}
	profile, e := s.project(ctx, *r.Profile, dc)
	if e != nil {
		return out, e
	}
	out.User = profile
	out.InvalidationVersion = profile.Version
	return out, nil
}

func (s *ProfileService) fields() []FieldName {
	fields := []FieldName{{"id"}, {"tenant_id"}, {"version"}, {"name"}, {"image"}}
	for _, field := range s.creation.attributes.schema.Fields {
		if readable(field.OutputPermission) {
			fields = append(fields, FieldName{field.Name})
		}
	}
	return fields
}

func (s *ProfileService) validateProjection(p UserProfile) error {
	if image, e := s.image(p.Image); e != nil || image != p.Image {
		return UnavailableError{}
	}
	for _, update := range p.AdditionalFields {
		field, ok := s.creation.attributes.field(update.Name)
		if !ok || forbiddenProfileField(update.Name) {
			return UnavailableError{}
		}
		if _, ok := attributeSize(update.Value, field.Kind); !ok {
			return UnavailableError{}
		}
	}
	return nil
}

func (s *ProfileService) project(ctx context.Context, p UserProfile, dc authorization.DecisionContext) (UserProfile, error) {
	if e := s.validateProjection(p); e != nil {
		return UserProfile{}, e
	}
	fields := s.fields()
	deadline, _ := ctx.Deadline()
	policy := s.creation.policy.config
	d, e := s.creation.policy.redact(ctx, RedactionPolicyInput{TenantID: p.TenantID, ViewerID: ActorID(dc.Request.Subject.ID), Resource: RedactionResource{"identity.user", string(p.ID)}, Fields: slices.Clone(fields), OperationID: string(dc.Request.Action), PolicyVersion: policy.PolicyVersion, Deadline: deadline.UTC()})
	if e := readContextError(ctx); e != nil {
		return UserProfile{}, e
	}
	if e != nil || d.PolicyID != policy.PolicyID || d.PolicyVersion != policy.PolicyVersion || !slices.Contains(policy.RedactionReasons, d.Reason) || len(d.VisibleFields)+len(d.RedactedFields) != len(fields) {
		return UserProfile{}, ForbiddenError{}
	}
	seen := make(map[FieldName]bool, len(fields))
	for _, group := range [][]FieldName{d.VisibleFields, d.RedactedFields} {
		for _, f := range group {
			if seen[f] || !slices.Contains(fields, f) {
				return UserProfile{}, ForbiddenError{}
			}
			seen[f] = true
		}
	}
	for _, f := range []FieldName{{"id"}, {"tenant_id"}, {"version"}} {
		if !slices.Contains(d.VisibleFields, f) {
			return UserProfile{}, ForbiddenError{}
		}
	}
	if !slices.Contains(d.VisibleFields, FieldName{"name"}) {
		p.Name = ""
	}
	if !slices.Contains(d.VisibleFields, FieldName{"image"}) {
		p.Image = ""
	}
	updates := make([]AttributeUpdate, 0, len(p.AdditionalFields))
	for _, u := range p.AdditionalFields {
		if slices.Contains(d.VisibleFields, FieldName{u.Name}) {
			updates = append(updates, u)
		}
	}
	p.AdditionalFields = cloneUpdates(updates)
	return p, nil
}

func forbiddenProfileField(name string) bool {
	switch name {
	case "id", "tenant_id", "version", "name", "image", "email", "email_verified", "phone", "phone_verified", "username", "status", "role", "roles", "password", "credentials":
		return true
	}
	return false
}

func validProfile(p UserProfile) bool {
	if !validDirectoryID(string(p.ID)) || !validDirectoryID(string(p.TenantID)) || p.Version == 0 || len(p.Name) > 256 || !utf8.ValidString(p.Name) || len(p.Image) > 2048 || !utf8.ValidString(p.Image) || len(p.AdditionalFields) > 123 {
		return false
	}
	total := 0
	for i, u := range p.AdditionalFields {
		if !validFieldName(u.Name) || forbiddenProfileField(u.Name) {
			return false
		}
		for _, old := range p.AdditionalFields[:i] {
			if old.Name == u.Name {
				return false
			}
		}
		n, ok := attributeSize(u.Value, u.Value.Kind)
		if !ok || n > attributeBudget-total {
			return false
		}
		total += n
	}
	return true
}

func validateProfileChanges(name, image string, fields []AttributeUpdate, version uint64) error {
	if version == 0 || version == ^uint64(0) || len(name) > 256 || !utf8.ValidString(name) || len(image) > 2048 || !utf8.ValidString(image) || len(fields) > 64 || name == "" && image == "" && len(fields) == 0 {
		return InvalidInputError{Field: "profile_update"}
	}
	if !validProfile(UserProfile{ID: "structural", TenantID: "structural", Version: version, Name: name, Image: image, AdditionalFields: fields}) {
		return InvalidInputError{Field: "profile_fields"}
	}
	return nil
}

func validImageURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Opaque == "" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && !strings.ContainsAny(u.Host, "*\\") && !strings.HasSuffix(u.Host, ":") && u.Host == strings.ToLower(u.Host) && (u.Port() == "" || u.Port() == "443")
}

func (s *ProfileService) image(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 || !utf8.ValidString(raw) || strings.Contains(raw, "#") {
		return "", InvalidInputError{Field: "profile_image"}
	}
	u, e := url.Parse(raw)
	if e != nil || !validImageURL(u) || !slices.Contains(s.origins, "https://"+u.Host) {
		return "", InvalidInputError{Field: "profile_image"}
	}
	return u.String(), nil
}

// ProfileUpdateCommand is immutable prepared intent for the existing command
// owner. Empty name/image are omitted; additional fields are whole replacements.
// New mutation requires the exact locked expected version and active status,
// one next version, immutable profile/result and identity.user.update audit.
// Replay must precede CAS. Structural construction is not authorization.
type ProfileUpdateCommand struct {
	Binding          CommandBinding
	ExpectedVersion  uint64
	Name             string
	Image            string
	AdditionalFields []AttributeUpdate
}

// NewProfileUpdateCommand bounds and copies intent without granting authority.
func NewProfileUpdateCommand(spec ProfileUpdateCommand) (Command, error) {
	if !validCommandBinding(spec.Binding) || spec.Binding.OperationID != "identity.profile.update" || spec.Binding.ActorKind != authorization.SubjectUser || string(spec.Binding.ActorID) != string(spec.Binding.UserID) {
		return Command{}, InvalidInputError{Field: "profile_command"}
	}
	if e := validateProfileChanges(spec.Name, spec.Image, spec.AdditionalFields, spec.ExpectedVersion); e != nil {
		return Command{}, e
	}
	spec.AdditionalFields = cloneUpdates(spec.AdditionalFields)
	return Command{profile: &spec}, nil
}

// UpdateProfile returns a private adapter copy, never another command variant.
func (c Command) UpdateProfile() (ProfileUpdateCommand, bool) {
	if c.profile == nil || c.create != nil || c.update != nil || c.status != nil || c.unlink != nil || c.link != nil || c.identifier != nil || c.feature != nil {
		return ProfileUpdateCommand{}, false
	}
	spec := *c.profile
	spec.AdditionalFields = cloneUpdates(spec.AdditionalFields)
	return spec, true
}
