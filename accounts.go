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
	"unicode"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
)

// AccountID is an exact case-sensitive directory ID of at most 128 UTF-8 bytes.
// It preserves canonical imported IDs, including ULIDs; empty is invalid.
// Structural parsing is not ownership, provider proof or canonical-source policy.
type AccountID string

// ParseAccountID validates structure without normalizing or changing the ID.
func ParseAccountID(raw string) (AccountID, error) {
	if !validDirectoryID(raw) {
		return "", InvalidInputError{Field: "account_id"}
	}
	return AccountID(raw), nil
}

// Account is identity-owned safe provider-link metadata, not provider tokens or
// a credential verifier. Its zero value is invalid. TenantID makes partition
// ownership explicit even when the same user/account ID exists in two tenants.
// Treat snapshots as immutable. Issuer/Subject may be withheld in public results;
// only complete authoritative records may be validated or used in commands.
type Account struct {
	ID       AccountID
	TenantID TenantID
	UserID   UserID
	Provider string
	Issuer   string
	Subject  string
	Version  uint64
}

// Validate checks the exact owner and bounded canonical metadata. It never
// authorizes access or rewrites provider subjects/issuers. The current provider
// issuer profiles are HTTPS and federation URNs without query, fragment or
// credentials. Provider registration owns protocol-specific canonicalization
// and must separately establish the trusted exact issuer; no URI is fetched.
func (a Account) Validate(tenant TenantID, user UserID) error {
	if !validDirectoryID(string(a.ID)) || !validDirectoryID(string(tenant)) || a.TenantID != tenant || !validDirectoryID(string(user)) || a.UserID != user || !validDirectoryID(a.Provider) || !validAccountIssuer(a.Issuer) || !validAccountSubject(a.Subject) || a.Version == 0 {
		return InvalidInputError{Field: "account"}
	}
	return nil
}

func validAccountSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 512 || !utf8.ValidString(subject) {
		return false
	}
	for _, r := range subject {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validAccountIssuer(raw string) bool {
	if validClaimIssuer(raw) {
		return true
	}
	if !validPolicyText(raw, 2048) || strings.ContainsAny(raw, "?#") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "urn" && u.Opaque != "" && u.Host == "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

// Format prevents diagnostic exposure of provider subjects or link metadata.
func (Account) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "identity.Account(redacted)")
}

// CredentialID names a non-secret credential reference. Empty is invalid and
// structural bounds are the same as directory IDs; it is never a bearer.
type CredentialID string

// CredentialKind is the closed credential namespace, not a login permission.
type CredentialKind uint8

const (
	CredentialPassword CredentialKind = iota + 1
	CredentialPasskey
	CredentialProvider
	CredentialAPIKey
)

// CredentialRef is a versioned non-secret pointer to one owning feature. It
// contains no verifier, bearer, factor material or provider payload. Ownership
// and authoritative usability are separate from this structural reference.
type CredentialRef struct {
	ID       CredentialID
	TenantID TenantID
	UserID   UserID
	Kind     CredentialKind
	Owner    string
	Version  uint64
}

// Validate checks a reference's exact user and closed kind/owner pairing.
// Password/API-key owners are their identity features, passkey owners may be
// webauthn or passkey, and federation/provider owners may be sso or identity/oauth.
// Neither its tenant/user fields nor ID grants authority.
func (c CredentialRef) Validate(tenant TenantID, user UserID) error {
	if !validDirectoryID(string(c.ID)) || !validDirectoryID(string(tenant)) || c.TenantID != tenant || !validDirectoryID(string(user)) || c.UserID != user || c.Version == 0 {
		return InvalidInputError{Field: "credential_reference"}
	}
	valid := false
	switch c.Kind {
	case CredentialPassword:
		valid = c.Owner == "identity/password"
	case CredentialPasskey:
		valid = c.Owner == "passkey" || c.Owner == "webauthn"
	case CredentialProvider:
		valid = c.Owner == "identity/oauth" || c.Owner == "sso"
	case CredentialAPIKey:
		valid = c.Owner == "identity/apikey"
	}
	if !valid {
		return InvalidInputError{Field: "credential_owner"}
	}
	return nil
}

// Format keeps references out of diagnostic snapshots despite carrying no secret.
func (CredentialRef) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "identity.CredentialRef(redacted)")
}

// AccountQuery is one exact primary partition read, bounded to MaximumAccounts.
// The repository must not truncate: more than the bound is an unavailable
// projection until stable account pagination is implemented.
type AccountQuery struct {
	TenantID        TenantID
	UserID          UserID
	MaximumAccounts uint16
}

// AccountSnapshot is one consistent user/account primary projection, ordered by
// account ID. It must not mix transactions, tenant partitions or cache versions.
type AccountSnapshot struct {
	User     User
	Accounts []Account
}

// AccountRepository owns concurrent-safe, bounded consistent primary listing.
// Return ErrUserAbsent for missing scope. Returned slices are immutable during
// a call; the service privately copies output. No provider network work occurs.
type AccountRepository interface {
	ListAccounts(context.Context, AccountQuery) (AccountSnapshot, error)
}

// AccountListRequest is a trusted core current-human-subject read. ActorScope
// must come from authenticated composition, never client JSON or a role label.
type AccountListRequest struct {
	TenantID   TenantID
	UserID     UserID
	ActorScope authorization.DecisionContext
}

// AccountListResult contains at most 100 permission-filtered safe records.
// Empty success is an explicit non-nil empty slice. NextCursor is reserved for
// stable pagination and remains empty in this bounded complete-read profile.
type AccountListResult struct {
	Accounts   []Account
	NextCursor string
}

// AccountService owns bounded account read policy, not link authority, provider
// tokens, sessions, goroutines or transactions. Dependencies must be concurrency-safe.
type AccountService struct {
	repo   AccountRepository
	policy *UserQueryService
}

// NewAccountService freezes validated query policy without I/O. Typed-nil
// repositories and authorization, missing callbacks and unbounded config fail.
func NewAccountService(repo AccountRepository, authorize authorization.Service, redact RedactFunc, config UserQueryConfig) (*AccountService, error) {
	if nilDependency(repo) {
		return nil, InvalidInputError{Field: "account_repository"}
	}
	p, err := newQueryPolicy(authorize, redact, config)
	if err != nil {
		return nil, err
	}
	return &AccountService{repo: repo, policy: p}, nil
}

// AccountList authorizes before primary access, then again against current user
// state and each owned account. Denied rows are omitted without exposing counts.
// Invalid or unavailable policy/projection aborts the whole result. Clock is
// sampled once; no caller-supplied identity metadata becomes policy evidence.
func (s *AccountService) AccountList(ctx context.Context, req AccountListRequest) (result AccountListResult, err error) {
	defer func() {
		if recover() != nil {
			result = AccountListResult{}
			err = UnavailableError{}
		}
	}()
	if s == nil || ctx == nil {
		return result, InvalidInputError{Field: "account_context"}
	}
	if req.ActorScope.Request.Subject.Kind != authorization.SubjectUser || string(req.ActorScope.Request.Subject.ID) != string(req.UserID) {
		return result, ForbiddenError{}
	}
	if e := validateQueryContext(req.ActorScope, req.TenantID, string(req.UserID), "identity.account.list", "identity.user", s.policy.config.PolicyVersion); e != nil {
		return result, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.policy.config.MaximumDuration)
	defer cancel()
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if e := s.policy.config.ValidateCanonicalUserID(ctx, req.UserID); e != nil {
		if e := readContextError(ctx); e != nil {
			return result, e
		}
		return result, InvalidInputError{Field: "user_id"}
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	now := s.policy.config.Clock.Now()
	if now.IsZero() {
		return result, UnavailableError{}
	}
	dc := req.ActorScope.Clone()
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for key := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(key), "identity.user.") || strings.HasPrefix(string(key), "identity.account.") || strings.HasPrefix(string(key), "identity.command.") {
			delete(dc.Request.Resource.Attributes, key)
		}
	}
	dc.Request.Resource.Attributes["identity.account.read-admission"] = authorization.BoolValue(true)
	if e := s.allow(ctx, dc); e != nil {
		return result, e
	}
	snapshot, dependencyErr := s.repo.ListAccounts(ctx, AccountQuery{TenantID: req.TenantID, UserID: req.UserID, MaximumAccounts: 100})
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	if dependencyErr != nil {
		if errors.Is(dependencyErr, ErrUserAbsent) {
			return result, ForbiddenError{}
		}
		return result, UnavailableError{}
	}
	if !snapshot.valid(req.TenantID, req.UserID) {
		return result, UnavailableError{}
	}
	if !snapshot.User.Status.AllowsAuthentication() {
		return result, ForbiddenError{}
	}
	dc.Request.Resource.Attributes["identity.account.read-admission"] = authorization.BoolValue(false)
	dc.Request.Resource.Attributes["identity.user.status"] = authorization.StringValue(string(snapshot.User.Status))
	dc.Request.Resource.Attributes["identity.user.version"] = authorization.StringValue(strconv.FormatUint(snapshot.User.Version, 10))
	if e := s.allow(ctx, dc); e != nil {
		return result, e
	}
	accounts := make([]Account, 0, len(snapshot.Accounts))
	for _, account := range snapshot.Accounts {
		row := dc.Clone()
		row.Request.Resource.Type = "identity.account"
		row.Request.Resource.ID = authorization.ResourceID(account.ID)
		row.Request.Resource.Attributes["identity.account.provider"] = authorization.StringValue(account.Provider)
		row.Request.Resource.Attributes["identity.account.version"] = authorization.StringValue(strconv.FormatUint(account.Version, 10))
		if e := s.allow(ctx, row); e != nil {
			var denied ForbiddenError
			if errors.As(e, &denied) {
				continue
			}
			return result, e
		}
		deadline, _ := ctx.Deadline()
		d, e := s.policy.redact(ctx, RedactionPolicyInput{TenantID: req.TenantID, ViewerID: ActorID(dc.Request.Subject.ID), Resource: RedactionResource{Kind: "identity.account", ID: string(account.ID)}, Fields: accountProjectionFields(), OperationID: "identity.account.list", PolicyVersion: s.policy.config.PolicyVersion, Deadline: deadline.UTC()})
		if e := readContextError(ctx); e != nil {
			return result, e
		}
		if e != nil {
			return result, UnavailableError{}
		}
		visible, valid := s.projection(d)
		if !valid {
			return result, ForbiddenError{}
		}
		if !visible["id"] || !visible["tenant_id"] || !visible["user_id"] || !visible["provider"] || !visible["version"] {
			continue
		}
		if !visible["issuer"] {
			account.Issuer = ""
		}
		if !visible["subject"] {
			account.Subject = ""
		}
		accounts = append(accounts, account)
	}
	if e := readContextError(ctx); e != nil {
		return result, e
	}
	return AccountListResult{Accounts: accounts}, nil
}

func (s *AccountService) allow(ctx context.Context, dc authorization.DecisionContext) error {
	if len(dc.Request.Resource.Attributes) > 128 {
		return InvalidInputError{Field: "authorization_attributes"}
	}
	d, e := s.policy.authorize.Decide(ctx, dc)
	if e := readContextError(ctx); e != nil {
		return e
	}
	if e != nil {
		return UnavailableError{}
	}
	if d.Revision != authorization.Revision(s.policy.config.PolicyVersion) || (d.Outcome != authorization.Allow && d.Outcome != authorization.Deny) {
		return UnavailableError{}
	}
	if d.Outcome != authorization.Allow {
		return ForbiddenError{}
	}
	return nil
}

func (s AccountSnapshot) valid(tenant TenantID, user UserID) bool {
	if s.User.Validate(tenant) != nil || s.User.ID != user || len(s.Accounts) > 100 {
		return false
	}
	for i, a := range s.Accounts {
		if a.Validate(tenant, user) != nil || i > 0 && a.ID <= s.Accounts[i-1].ID {
			return false
		}
		for _, old := range s.Accounts[:i] {
			if a.Provider == old.Provider && a.Issuer == old.Issuer && a.Subject == old.Subject {
				return false
			}
		}
	}
	return true
}

func accountProjectionFields() []FieldName {
	return []FieldName{{"id"}, {"tenant_id"}, {"user_id"}, {"provider"}, {"issuer"}, {"subject"}, {"version"}}
}

func (s *AccountService) projection(d RedactionPolicyDecision) (map[string]bool, bool) {
	if d.PolicyID != s.policy.config.PolicyID || d.PolicyVersion != s.policy.config.PolicyVersion || !slices.Contains(s.policy.config.RedactionReasons, d.Reason) || len(d.VisibleFields)+len(d.RedactedFields) != 7 {
		return nil, false
	}
	visible := make(map[string]bool, 7)
	seen := make(map[string]bool, 7)
	for i, fields := range [][]FieldName{d.VisibleFields, d.RedactedFields} {
		for _, field := range fields {
			if !slices.Contains(accountProjectionFields(), field) || seen[field.Value] {
				return nil, false
			}
			seen[field.Value] = true
			visible[field.Value] = i == 0
		}
	}
	return visible, true
}

// LoginMethod is a primary authority-owned eligibility observation, never a
// caller assertion. Usable includes verification, enablement, policy/factor and
// provider availability. ExpiresAt zero means indefinite; otherwise expiry is
// exclusive. AccountID is mandatory only for provider methods. API keys never
// count as a replacement for a human login method, even if marked usable.
type LoginMethod struct {
	Credential CredentialRef
	AccountID  AccountID
	Usable     bool
	ExpiresAt  time.Time
}

// AccountAccessSnapshot is a bounded consistent primary view of every linked
// account and login method for one user. It is not an authority proof. The
// durable owner must re-read it under its locks, including credential/factor
// owner eligibility, rather than trusting caller-provided counts or this view.
type AccountAccessSnapshot struct {
	User     User
	Accounts []Account
	Methods  []LoginMethod
}

// AccountUnlinkPlan is the pure final-access decision for one exact owned link.
// It is not an Execute command, provider proof or permission. Removing an
// authentication link invalidates the credential dimension even if expired.
type AccountUnlinkPlan struct {
	Account                Account
	RemainingUsableMethods uint16
	InvalidatesCredential  bool
}

// FinalAccessError means unlink would leave no independent human login method.
// Public workflows must authorize before running this enumeration-sensitive check.
type FinalAccessError struct{}

func (FinalAccessError) Error() string { return "identity: final usable access method" }

// CheckAccountUnlink validates a complete owned primary snapshot and determines
// whether one versioned unlink would orphan access. It mutates nothing and
// grants no authority. Call after authorization and repeat under durable locks
// immediately before mutation with one trusted clock sample. The owner must
// fence user, account, social-link and applicable credential authority versions
// atomically with audit, cleanup intent and replay-safe command receipt.
func CheckAccountUnlink(snapshot AccountAccessSnapshot, tenant TenantID, user UserID, accountID AccountID, expectedVersion uint64, now time.Time) (AccountUnlinkPlan, error) {
	zero := AccountUnlinkPlan{}
	if now.IsZero() || expectedVersion == 0 || expectedVersion == ^uint64(0) || !validDirectoryID(string(accountID)) || !(AccountSnapshot{User: snapshot.User, Accounts: snapshot.Accounts}).valid(tenant, user) || len(snapshot.Methods) > 128 {
		return zero, InvalidInputError{Field: "account_access_snapshot"}
	}
	if !snapshot.User.Status.AllowsAuthentication() {
		return zero, ForbiddenError{}
	}
	var target Account
	for _, a := range snapshot.Accounts {
		if a.ID == accountID {
			target = a
			break
		}
	}
	if target.ID == "" {
		return zero, ForbiddenError{}
	}
	if target.Version != expectedVersion || snapshot.User.Version == ^uint64(0) {
		return zero, ConflictError{}
	}
	plan := AccountUnlinkPlan{Account: target}
	for i, method := range snapshot.Methods {
		if method.Credential.Validate(tenant, user) != nil {
			return zero, InvalidInputError{Field: "login_method"}
		}
		for _, old := range snapshot.Methods[:i] {
			if old.Credential.ID == method.Credential.ID {
				return zero, InvalidInputError{Field: "login_method"}
			}
		}
		if !method.ExpiresAt.IsZero() && (method.ExpiresAt.Year() < 1 || method.ExpiresAt.Year() > 9999 || method.ExpiresAt.Nanosecond()%1000 != 0) {
			return zero, InvalidInputError{Field: "login_expiry"}
		}
		if method.Credential.Kind == CredentialProvider {
			found := false
			for _, a := range snapshot.Accounts {
				if a.ID == method.AccountID {
					found = true
					break
				}
			}
			if !found {
				return zero, InvalidInputError{Field: "login_account"}
			}
		} else if method.AccountID != "" {
			return zero, InvalidInputError{Field: "login_account"}
		}
		if method.AccountID == accountID {
			plan.InvalidatesCredential = true
			continue
		}
		if method.Credential.Kind != CredentialAPIKey && method.Usable && (method.ExpiresAt.IsZero() || method.ExpiresAt.After(now)) {
			plan.RemainingUsableMethods++
		}
	}
	if plan.RemainingUsableMethods == 0 {
		return zero, FinalAccessError{}
	}
	return plan, nil
}
