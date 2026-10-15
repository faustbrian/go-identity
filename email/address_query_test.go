package email_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

type addressQueryClock struct{}

func (addressQueryClock) Now() time.Time { return time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) }

type addressQueryRepo struct {
	state identity.IdentifierState
	err   error
	reads int
	read  func(context.Context)
}

func (r *addressQueryRepo) GetIdentifierState(ctx context.Context, q identity.IdentifierQuery) (identity.IdentifierState, error) {
	if _, bounded := ctx.Deadline(); !bounded || q.MaximumIdentifiers != 128 || q.TenantID != "tenant" || q.UserID != "owner" {
		panic("unbounded or changed query")
	}
	r.reads++
	if r.read != nil {
		r.read(ctx)
	}
	return r.state, r.err
}

type addressQueryAuthorizer struct {
	deny        bool
	err         error
	currentDeny bool
}

func (a *addressQueryAuthorizer) Decide(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	if _, bounded := ctx.Deadline(); !bounded || request.Environment.Time.IsZero() {
		panic("unbounded or untimed policy")
	}
	outcome := authorization.Allow
	if a.deny || a.currentDeny && request.Resource.Attributes["identity.user.version"].Kind() != authorization.ValueMissing {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, a.err
}

func addressQueryFixture(t *testing.T, selected ...identity.RedactFunc) (*email.AddressQueryService, *addressQueryRepo, *addressQueryAuthorizer, email.AddressListRequest) {
	t.Helper()
	now := (addressQueryClock{}).Now()
	repo := &addressQueryRepo{state: identity.IdentifierState{
		User: identity.User{ID: "owner", TenantID: "tenant", Status: identity.StatusActive, Version: 7}, AuthorityVersion: 3,
		Identifiers: []identity.Identifier{
			{ID: "a", UserID: "owner", Kind: identity.IdentifierEmail, CanonicalValue: "one@example.test", DisplayValue: "One@example.test", Verified: true, Primary: true, Version: 2},
			{ID: "b", UserID: "owner", Kind: identity.IdentifierUsername, CanonicalValue: "handle", Version: 1},
			{ID: "c", UserID: "owner", Kind: identity.IdentifierEmail, CanonicalValue: "two@example.test", Version: 1},
		},
		Verifications: []identity.Verification{
			{IdentifierID: "a", State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 4},
			{IdentifierID: "b", State: identity.VerificationPending, Version: 1},
			{IdentifierID: "c", State: identity.VerificationPending, Version: 1},
		},
	}}
	authorizer := &addressQueryAuthorizer{}
	auth, err := authorization.NewDecisionService(authorizer)
	if err != nil {
		t.Fatal(err)
	}
	redact := func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		return identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "email-read", PolicyVersion: 1, Reason: "address-visible"}, nil
	}
	if len(selected) > 1 {
		t.Fatal("ambiguous test projection policy")
	}
	if len(selected) == 1 {
		redact = selected[0]
	}
	service, err := email.NewAddressQueryService(repo, auth, redact, identity.UserQueryConfig{
		Clock: addressQueryClock{}, MaximumDuration: time.Second, PolicyID: "email-read", PolicyVersion: 1,
		RedactionReasons:        []identity.PolicyReason{"address-visible"},
		ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := email.AddressListRequest{TenantID: "tenant", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{
		Tenant: "tenant", Action: "identity.email.address-list", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"},
		Resource: authorization.Resource{Type: "identity.user", ID: "owner"},
	}}}
	return service, repo, authorizer, request
}

func TestAddressQueriesPreserveVersionsAndFilterNonEmail(t *testing.T) {
	s, repo, _, request := addressQueryFixture(t)
	request.Limit = 1
	first, err := s.AddressList(context.Background(), request)
	if err != nil || first.Outcome != identity.CommitOutcomeNotCommitted || len(first.Addresses) != 1 || first.NextCursor == "" {
		t.Fatal("first page", err)
	}
	bindings, err := first.Addresses[0].Bindings()
	canonical, display, present := first.Addresses[0].Values()
	if err != nil || bindings.IdentifierID != "a" || bindings.UserVersion != 7 || bindings.AuthorityVersion != 3 || bindings.IdentifierVersion != 2 || bindings.VerificationVersion != 4 || !bindings.Primary || !bindings.Verified || !present || canonical != "one@example.test" || display != "One@example.test" {
		t.Fatal("safe original projection")
	}
	request.Cursor = first.NextCursor
	second, err := s.AddressList(context.Background(), request)
	if err != nil || len(second.Addresses) != 1 || second.NextCursor != "" {
		t.Fatal("second page", err)
	}
	bindings, _ = second.Addresses[0].Bindings()
	if bindings.IdentifierID != "c" || bindings.Verified || bindings.Primary {
		t.Fatal("non-email or invented verification")
	}
	get := email.AddressGetRequest{TenantID: "tenant", AddressID: "a", Caller: request.Caller}
	get.Caller.Request.Action = "identity.email.address-get"
	result, err := s.AddressGet(context.Background(), get)
	bindings, _ = result.Address.Bindings()
	if err != nil || result.Outcome != identity.CommitOutcomeNotCommitted || bindings != mustAddressBindings(t, first.Addresses[0]) || repo.reads != 3 {
		t.Fatal("get changed observation", err)
	}
}

func mustAddressBindings(t *testing.T, p identity.IdentifierProjection) identity.IdentifierProjectionBindings {
	t.Helper()
	b, err := p.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAddressQueriesDenyBeforeReadAndAfterCurrentPolicy(t *testing.T) {
	for _, current := range []bool{false, true} {
		s, repo, auth, request := addressQueryFixture(t)
		auth.deny, auth.currentDeny = !current, current
		result, err := s.AddressList(context.Background(), request)
		var forbidden identity.ForbiddenError
		wantReads := 0
		if current {
			wantReads = 1
		}
		if !errors.As(err, &forbidden) || result.Addresses != nil || result.NextCursor != "" || repo.reads != wantReads {
			t.Fatal("policy denial disclosed data", current, err)
		}
	}
}

func TestAddressQueryPaginationRejectsChangedSnapshotAndScope(t *testing.T) {
	for _, change := range []string{"version", "authority", "actor", "target", "malformed", "oversized"} {
		t.Run(change, func(t *testing.T) {
			s, repo, _, request := addressQueryFixture(t)
			request.Limit = 1
			first, err := s.AddressList(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			request.Cursor = first.NextCursor
			switch change {
			case "version":
				repo.state.User.Version++
			case "authority":
				repo.state.AuthorityVersion++
			case "actor":
				request.Caller.Request.Subject.ID = "admin"
			case "target":
				request.TargetSubjectID = "other"
				request.Caller.Request.Resource.ID = "other"
			case "malformed":
				request.Cursor = "not+base64"
			case "oversized":
				request.Cursor = email.Cursor(strings.Repeat("x", 513))
			}
			out, err := s.AddressList(context.Background(), request)
			if err == nil || out.Addresses != nil || out.NextCursor != "" {
				t.Fatal("changed query accepted its predecessor page")
			}
		})
	}
}

func TestAddressQueriesDoNotDistinguishAbsentForbiddenOrForeign(t *testing.T) {
	for _, variant := range []string{"absent-user", "absent-address", "non-email", "denied", "foreign"} {
		s, repo, auth, list := addressQueryFixture(t)
		request := email.AddressGetRequest{TenantID: "tenant", AddressID: "a", Caller: list.Caller}
		request.Caller.Request.Action = "identity.email.address-get"
		switch variant {
		case "absent-user":
			repo.err = identity.ErrUserAbsent
		case "absent-address":
			request.AddressID = "missing"
		case "non-email":
			request.AddressID = "b"
		case "denied":
			auth.deny = true
		case "foreign":
			request.TenantID = "foreign"
		}
		out, err := s.AddressGet(context.Background(), request)
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || out.Address != (identity.IdentifierProjection{}) || err.Error() != "identity: forbidden" {
			t.Fatal("existence disclosure", variant, err)
		}
	}
}

func TestAddressQueriesSupportExplicitAuthorizedAdministrator(t *testing.T) {
	s, _, auth, request := addressQueryFixture(t)
	request.TargetSubjectID = "owner"
	request.Caller.Request.Subject.ID = "administrator"
	out, err := s.AddressList(context.Background(), request)
	if err != nil || len(out.Addresses) != 2 {
		t.Fatal("authorized administrator", err)
	}
	auth.deny = true
	out, err = s.AddressList(context.Background(), request)
	if err == nil || out.Addresses != nil {
		t.Fatal("administrator name granted authority")
	}
}

func TestAddressQueryErrorsAndDiagnosticsAreRedacted(t *testing.T) {
	s, repo, _, request := addressQueryFixture(t)
	repo.err = errors.New("private one@example.test")
	out, err := s.AddressList(context.Background(), request)
	var unavailable identity.UnavailableError
	if !errors.As(err, &unavailable) || strings.Contains(err.Error(), "example") || out.Addresses != nil {
		t.Fatal("storage error disclosure", err)
	}
	repo.err = nil
	out, err = s.AddressList(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{request, out, email.AddressGetRequest{TenantID: "tenant", AddressID: "a", Caller: request.Caller}} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(verb, value)
			if strings.Contains(formatted, "owner") || strings.Contains(formatted, "example") || strings.Contains(formatted, "tenant") {
				t.Fatal("diagnostic disclosure")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, email.ErrSensitiveSerialization) {
			t.Fatal("implicit address export", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.AddressList(ctx, request); !errors.Is(err, context.Canceled) || out.Addresses != nil {
		t.Fatal("cancellation disclosed addresses", err)
	}
}

func TestAddressQueriesRejectMalformedPrimaryPartitions(t *testing.T) {
	for name, change := range map[string]func(*identity.IdentifierState){
		"tenant":             func(s *identity.IdentifierState) { s.User.TenantID = "foreign" },
		"user":               func(s *identity.IdentifierState) { s.User.ID = "foreign" },
		"authority":          func(s *identity.IdentifierState) { s.AuthorityVersion = 0 },
		"verification count": func(s *identity.IdentifierState) { s.Verifications = s.Verifications[:1] },
		"foreign identifier": func(s *identity.IdentifierState) { s.Identifiers[1].UserID = "foreign" },
		"reordered": func(s *identity.IdentifierState) {
			s.Identifiers[1], s.Identifiers[2] = s.Identifiers[2], s.Identifiers[1]
		},
		"duplicate mailbox": func(s *identity.IdentifierState) { s.Identifiers[2].CanonicalValue = s.Identifiers[0].CanonicalValue },
		"future verification": func(s *identity.IdentifierState) {
			s.Verifications[0].VerifiedAt = (addressQueryClock{}).Now().Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, repo, _, request := addressQueryFixture(t)
			change(&repo.state)
			out, err := s.AddressList(context.Background(), request)
			var unavailable identity.UnavailableError
			if !errors.As(err, &unavailable) || out.Addresses != nil || out.NextCursor != "" {
				t.Fatal("malformed partition disclosed", err)
			}
		})
	}
}

func TestAddressQueriesFailClosedOnDependencyCancellationAndPanic(t *testing.T) {
	for _, variant := range []string{"cancel", "panic", "policy failure", "banned owner"} {
		s, repo, auth, request := addressQueryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		switch variant {
		case "cancel":
			repo.read = func(context.Context) { cancel() }
		case "panic":
			repo.read = func(context.Context) { panic("private mailbox") }
		case "policy failure":
			auth.err = errors.New("private policy")
		case "banned owner":
			repo.state.User.Status = identity.StatusBanned
		}
		out, err := s.AddressList(ctx, request)
		cancel()
		if err == nil || out.Addresses != nil || out.NextCursor != "" || strings.Contains(err.Error(), "private") {
			t.Fatal("dependency failure disclosed", variant, err)
		}
		if variant == "cancel" && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost classification")
		}
	}
}

func TestAddressQueriesAllowEmptyPartitionAndRejectBounds(t *testing.T) {
	s, repo, _, request := addressQueryFixture(t)
	repo.state.Identifiers, repo.state.Verifications = nil, nil
	out, err := s.AddressList(context.Background(), request)
	if err != nil || out.Addresses == nil || len(out.Addresses) != 0 || out.NextCursor != "" {
		t.Fatal("empty authorized partition", err)
	}
	request.Limit = 101
	before := repo.reads
	if out, err := s.AddressList(context.Background(), request); err == nil || out.Addresses != nil || repo.reads != before {
		t.Fatal("oversized page reached storage")
	}
	request.Limit = 0
	request.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
	if out, err := s.AddressList(context.Background(), request); err == nil || out.Addresses != nil || repo.reads != before {
		t.Fatal("oversized caller reached storage")
	}
}

func TestAddressQueriesUseRealDefaultDenyAuthorization(t *testing.T) {
	_, repo, _, request := addressQueryFixture(t)
	snapshot, err := authorization.NewSnapshot(1, authorization.DenyOverrides)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	s, err := email.NewAddressQueryService(repo, auth, func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
		panic("denied read requested projection")
	}, identity.UserQueryConfig{
		Clock: addressQueryClock{}, MaximumDuration: time.Second, PolicyID: "email-read", PolicyVersion: 1,
		RedactionReasons: []identity.PolicyReason{"address-visible"}, ValidateCanonicalUserID: func(context.Context, identity.UserID) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.AddressList(context.Background(), request)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || out.Addresses != nil || repo.reads != 0 {
		t.Fatal("empty real policy admitted primary access", err)
	}
}

func TestAddressQueriesRequireExactDisclosurePolicy(t *testing.T) {
	for _, variant := range []string{"omit values", "partial", "wrong policy", "wrong revision", "wrong reason", "duplicate field", "panic", "error"} {
		t.Run(variant, func(t *testing.T) {
			s, _, _, request := addressQueryFixture(t, func(_ context.Context, in identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
				decision := identity.RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "email-read", PolicyVersion: 1, Reason: "address-visible"}
				switch variant {
				case "omit values":
					decision.VisibleFields, decision.RedactedFields = nil, in.Fields
				case "partial":
					decision.VisibleFields, decision.RedactedFields = in.Fields[:1], in.Fields[1:]
				case "wrong policy":
					decision.PolicyID = "foreign"
				case "wrong revision":
					decision.PolicyVersion++
				case "wrong reason":
					decision.Reason = "unregistered"
				case "duplicate field":
					decision.VisibleFields = []identity.FieldName{{Value: "canonical_value"}, {Value: "canonical_value"}}
				case "panic":
					panic("private mailbox")
				case "error":
					return decision, errors.New("private mailbox")
				}
				return decision, nil
			})
			out, err := s.AddressList(context.Background(), request)
			if variant == "omit values" {
				if err != nil || len(out.Addresses) != 2 {
					t.Fatal("metadata-only policy", err)
				}
				for _, address := range out.Addresses {
					if canonical, display, visible := address.Values(); visible || canonical != "" || display != "" {
						t.Fatal("omitted values retained hidden mailbox")
					}
				}
			} else if err == nil || out.Addresses != nil || out.NextCursor != "" || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid disclosure widened visibility", err)
			}
		})
	}
}

func FuzzAddressQueryCursorAdmission(f *testing.F) {
	for _, seed := range []string{"", "not+base64", "AA", strings.Repeat("x", 512), strings.Repeat("x", 513), "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		s, _, _, request := addressQueryFixture(t)
		request.Cursor = email.Cursor(cursor)
		request.Limit = 1
		out, err := s.AddressList(context.Background(), request)
		if err != nil {
			if out.Addresses != nil || out.NextCursor != "" {
				t.Fatal("invalid cursor returned partial data")
			}
			return
		}
		if len(out.Addresses) > 1 || len(out.NextCursor) > 512 {
			t.Fatal("cursor escaped selected output bounds")
		}
		for _, address := range out.Addresses {
			binding := mustAddressBindings(t, address)
			if binding.TenantID != "tenant" || binding.UserID != "owner" || binding.Kind != identity.IdentifierEmail {
				t.Fatal("cursor changed primary scope")
			}
		}
	})
}
