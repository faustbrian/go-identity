package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
)

type accountReadFunc func(context.Context, AccountQuery) (AccountSnapshot, error)

func (f accountReadFunc) ListAccounts(ctx context.Context, q AccountQuery) (AccountSnapshot, error) {
	return f(ctx, q)
}

func accountFixture(t *testing.T) (*AccountService, AccountListRequest, AccountSnapshot) {
	t.Helper()
	f := newQueryFixture(t)
	account := Account{ID: "account-a", TenantID: f.repo.user.TenantID, UserID: f.repo.user.ID, Provider: "example", Issuer: "https://issuer.example", Subject: "subject-a", Version: 1}
	snapshot := AccountSnapshot{User: f.repo.user, Accounts: []Account{account}}
	service, err := NewAccountService(accountReadFunc(func(ctx context.Context, q AccountQuery) (AccountSnapshot, error) {
		if _, ok := ctx.Deadline(); !ok {
			panic("unbounded read")
		}
		if q.TenantID != snapshot.User.TenantID || q.UserID != snapshot.User.ID || q.MaximumAccounts != 100 {
			panic("changed account scope")
		}
		return snapshot, nil
	}), f.service.authorize, queryRedact, f.service.config)
	if err != nil {
		t.Fatal(err)
	}
	r := AccountListRequest{TenantID: snapshot.User.TenantID, UserID: snapshot.User.ID, ActorScope: f.request.Context}
	r.ActorScope.Request.Action = "identity.account.list"
	r.ActorScope.Request.Subject.ID = authorization.SubjectID(r.UserID)
	return service, r, snapshot
}

func TestAccountListReturnsOnlyOwnedSafeMetadataAndCopies(t *testing.T) {
	s, r, snapshot := accountFixture(t)
	got, err := s.AccountList(context.Background(), r)
	if err != nil || len(got.Accounts) != 1 || got.Accounts[0] != snapshot.Accounts[0] {
		t.Fatalf("accounts = %+v, %v", got, err)
	}
	got.Accounts[0].Provider = "changed"
	if snapshot.Accounts[0].Provider != "example" {
		t.Fatal("output aliases repository")
	}
}

func TestAccountSupportsFederationURNWithoutProviderTokens(t *testing.T) {
	_, _, s := accountFixture(t)
	a := s.Accounts[0]
	a.Provider = "enterprise-saml"
	a.Issuer = "urn:example:enterprise"
	if err := a.Validate(a.TenantID, a.UserID); err != nil {
		t.Fatal("federation URN rejected by protocol-neutral link metadata")
	}
}

func TestAccountPreservesOpaqueProviderSubjectWhitespace(t *testing.T) {
	_, _, s := accountFixture(t)
	a := s.Accounts[0]
	a.Subject = "opaque provider subject"
	if err := a.Validate(a.TenantID, a.UserID); err != nil {
		t.Fatal("protocol-neutral subject was narrowed beyond its byte bounds")
	}
}

func TestAccountListRejectsCrossScopeAndCurrentDenialBeforeRead(t *testing.T) {
	for _, which := range []string{"tenant", "actor", "kind", "operation", "revision", "deny"} {
		s, r, _ := accountFixture(t)
		s.repo = accountReadFunc(func(context.Context, AccountQuery) (AccountSnapshot, error) {
			t.Fatal("denied read accessed primary")
			return AccountSnapshot{}, nil
		})
		switch which {
		case "tenant":
			r.ActorScope.Request.Tenant = "foreign"
		case "actor":
			r.ActorScope.Request.Subject.ID = "other"
		case "kind":
			r.ActorScope.Request.Subject.Kind = authorization.SubjectAPIKey
		case "operation":
			r.ActorScope.Request.Action = "identity.user.get"
		case "revision":
			r.ActorScope.PolicyRevision++
		case "deny":
			s.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
			})
		}
		got, err := s.AccountList(context.Background(), r)
		if err == nil || len(got.Accounts) != 0 {
			t.Fatal("denied account output exposed")
		}
	}
}

func TestAccountListValidatesPrimaryStatusAndEveryRecord(t *testing.T) {
	for _, change := range []func(*AccountSnapshot){
		func(s *AccountSnapshot) { s.User.Status = StatusSuspended },
		func(s *AccountSnapshot) { s.User.TenantID = "foreign" },
		func(s *AccountSnapshot) { s.Accounts[0].TenantID = "foreign" },
		func(s *AccountSnapshot) { s.Accounts[0].UserID = "foreign-user" },
		func(s *AccountSnapshot) { s.Accounts[0].Version = 0 },
		func(s *AccountSnapshot) { s.Accounts = append(s.Accounts, s.Accounts[0]) },
		func(s *AccountSnapshot) { a := s.Accounts[0]; a.ID = "other"; s.Accounts = append(s.Accounts, a) },
		func(s *AccountSnapshot) { s.Accounts[0].Issuer = "https://secret@issuer.example" },
		func(s *AccountSnapshot) { s.Accounts = make([]Account, 101) },
	} {
		s, r, snapshot := accountFixture(t)
		change(&snapshot)
		s.repo = accountReadFunc(func(context.Context, AccountQuery) (AccountSnapshot, error) { return snapshot, nil })
		got, err := s.AccountList(context.Background(), r)
		if err == nil || len(got.Accounts) != 0 {
			t.Fatal("invalid primary projection disclosed")
		}
	}
}

func accessFixture(t *testing.T) AccountAccessSnapshot {
	t.Helper()
	_, _, s := accountFixture(t)
	return AccountAccessSnapshot{User: s.User, Accounts: s.Accounts, Methods: []LoginMethod{
		{Credential: CredentialRef{ID: "provider-credential", TenantID: s.User.TenantID, UserID: s.User.ID, Kind: CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: s.Accounts[0].ID, Usable: true},
		{Credential: CredentialRef{ID: "password-credential", TenantID: s.User.TenantID, UserID: s.User.ID, Kind: CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true},
	}}
}

func TestAccountUnlinkCheckProtectsFinalIndependentLoginMethod(t *testing.T) {
	s := accessFixture(t)
	plan, err := CheckAccountUnlink(s, s.User.TenantID, s.User.ID, "account-a", 1, queryClock{}.Now())
	if err != nil || plan.Account.ID != "account-a" || !plan.InvalidatesCredential || plan.RemainingUsableMethods != 1 {
		t.Fatal("safe unlink rejected")
	}
	for _, change := range []func(*AccountAccessSnapshot){
		func(s *AccountAccessSnapshot) { s.Methods = s.Methods[:1] },
		func(s *AccountAccessSnapshot) { s.Methods[1].Usable = false },
		func(s *AccountAccessSnapshot) { s.Methods[1].ExpiresAt = queryClock{}.Now() },
		func(s *AccountAccessSnapshot) {
			s.Methods[1].Credential.Kind = CredentialAPIKey
			s.Methods[1].Credential.Owner = "identity/apikey"
		},
		func(s *AccountAccessSnapshot) {
			s.Methods[1].Credential.Kind = CredentialProvider
			s.Methods[1].Credential.Owner = "identity/oauth"
			s.Methods[1].AccountID = "account-a"
		},
	} {
		s := accessFixture(t)
		change(&s)
		if _, err := CheckAccountUnlink(s, s.User.TenantID, s.User.ID, "account-a", 1, queryClock{}.Now()); err == nil {
			t.Fatal("unlink orphaned final usable method")
		}
	}
}

func TestAccountUnlinkCheckRejectsMalformedScopeVersionAndDuplicates(t *testing.T) {
	for _, change := range []func(*AccountAccessSnapshot){
		func(s *AccountAccessSnapshot) { s.Methods[1].Credential.UserID = "foreign-user" },
		func(s *AccountAccessSnapshot) { s.Methods[1].Credential.TenantID = "foreign" },
		func(s *AccountAccessSnapshot) { s.Methods[1].Credential.Owner = "unknown-owner" },
		func(s *AccountAccessSnapshot) { s.Methods[1].Credential.Version = 0 },
		func(s *AccountAccessSnapshot) { s.Methods = append(s.Methods, s.Methods[1]) },
		func(s *AccountAccessSnapshot) { s.Accounts[0].Version++ },
		func(s *AccountAccessSnapshot) { s.User.Status = StatusBanned },
		func(s *AccountAccessSnapshot) { s.Accounts[0].TenantID = "foreign" },
	} {
		s := accessFixture(t)
		change(&s)
		if _, err := CheckAccountUnlink(s, s.User.TenantID, s.User.ID, "account-a", 1, queryClock{}.Now()); err == nil {
			t.Fatal("invalid unlink snapshot accepted")
		}
	}
}

func TestAccountUnlinkCheckCountsFutureIndependentPasskey(t *testing.T) {
	s := accessFixture(t)
	s.Methods[1].Credential.Kind = CredentialPasskey
	s.Methods[1].Credential.Owner = "webauthn"
	s.Methods[1].ExpiresAt = queryClock{}.Now().Add(time.Microsecond)
	plan, err := CheckAccountUnlink(s, s.User.TenantID, s.User.ID, "account-a", 1, queryClock{}.Now())
	if err != nil || plan.RemainingUsableMethods != 1 {
		t.Fatal("unexpired independent passkey not counted")
	}
}

func TestAccountListCurrentStatePolicyAndOptionalRedaction(t *testing.T) {
	s, r, snapshot := accountFixture(t)
	decisions := 0
	s.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		decisions++
		if decisions == 2 && !reflect.DeepEqual(dc.Request.Resource.Attributes["identity.user.status"], authorization.StringValue(string(snapshot.User.Status))) {
			t.Fatal("post-read policy used caller state")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	s.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{VisibleFields: []FieldName{{"id"}, {"tenant_id"}, {"user_id"}, {"provider"}, {"version"}}, RedactedFields: []FieldName{{"issuer"}, {"subject"}}, PolicyID: "identity-read", PolicyVersion: 1, Reason: "projection-visible"}, nil
	}
	got, err := s.AccountList(context.Background(), r)
	if err != nil || decisions != 3 || len(got.Accounts) != 1 || got.Accounts[0].Subject != "" || got.Accounts[0].Issuer != "" {
		t.Fatal("account redaction or current state policy missing")
	}
}

func TestAccountListAbsenceAndDependencyErrorsAreRedacted(t *testing.T) {
	for _, dependency := range []error{ErrUserAbsent, errors.New("sensitive provider state")} {
		s, r, _ := accountFixture(t)
		s.repo = accountReadFunc(func(context.Context, AccountQuery) (AccountSnapshot, error) { return AccountSnapshot{}, dependency })
		got, err := s.AccountList(context.Background(), r)
		if err == nil || len(got.Accounts) != 0 || err.Error() == dependency.Error() {
			t.Fatal("dependency detail exposed")
		}
	}
}

func TestAccountListDropsDeniedRowsAndWithholdsInvalidOrFailedProjection(t *testing.T) {
	for _, which := range []string{"row-denial", "required-redacted", "overlap", "unregistered", "panic", "cancel", "policy-error", "policy-revision", "policy-outcome"} {
		s, r, _ := accountFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		s.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
			if dc.Request.Resource.Type == "identity.account" {
				if which == "row-denial" {
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				}
				if which == "policy-error" {
					return authorization.Decision{}, errors.New("sensitive")
				}
				if which == "policy-revision" {
					return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
				}
				if which == "policy-outcome" {
					return authorization.Decision{Outcome: authorization.Outcome(99), Revision: 1}, nil
				}
			}
			return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
		})
		s.policy.redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
			d, err := queryRedact(ctx, in)
			switch which {
			case "required-redacted":
				d.VisibleFields = nil
				d.RedactedFields = in.Fields
			case "overlap":
				d.VisibleFields[0] = d.VisibleFields[1]
			case "unregistered":
				d.Reason = "unregistered"
			case "panic":
				panic("sensitive")
			case "cancel":
				cancel()
			}
			return d, err
		}
		got, err := s.AccountList(ctx, r)
		cancel()
		if len(got.Accounts) != 0 {
			t.Fatal("withheld account exposed")
		}
		if which == "row-denial" || which == "required-redacted" {
			if err != nil || got.Accounts == nil {
				t.Fatal("denied row changed empty-success contract")
			}
		} else if err == nil || got.Accounts != nil {
			t.Fatal("failed projection returned partial success")
		}
	}
}

func TestAccountListPrimaryStateDenialAndCancellationNeverDisclose(t *testing.T) {
	for _, which := range []string{"state-denial", "read-panic", "clock-zero", "clock-panic", "cancel"} {
		s, r, _ := accountFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		switch which {
		case "state-denial":
			n := 0
			s.policy.authorize = queryDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				n++
				if n == 2 {
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
		case "read-panic":
			s.repo = accountReadFunc(func(context.Context, AccountQuery) (AccountSnapshot, error) { panic("sensitive") })
		case "clock-zero":
			s.policy.config.Clock = queryClockFunc(func() time.Time { return time.Time{} })
		case "clock-panic":
			s.policy.config.Clock = queryClockFunc(func() time.Time { panic("sensitive") })
		case "cancel":
			cancel()
		}
		got, err := s.AccountList(ctx, r)
		cancel()
		if err == nil || got.Accounts != nil {
			t.Fatal("failed primary state disclosed accounts")
		}
	}
}

func TestAccountListNotApplicableAfterAllowedRowAbortsAllOutput(t *testing.T) {
	s, r, snapshot := accountFixture(t)
	second := snapshot.Accounts[0]
	second.ID = "account-b"
	second.Subject = "subject-b"
	snapshot.Accounts = append(snapshot.Accounts, second)
	s.repo = accountReadFunc(func(context.Context, AccountQuery) (AccountSnapshot, error) { return snapshot, nil })
	s.policy.authorize = queryDecisionFunc(func(_ context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if dc.Request.Resource.Type == "identity.account" && dc.Request.Resource.ID == "account-b" {
			return authorization.Decision{Outcome: authorization.NotApplicable, Revision: 1}, nil
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	got, err := s.AccountList(context.Background(), r)
	var unavailable UnavailableError
	if !errors.As(err, &unavailable) || got.Accounts != nil {
		t.Fatal("invalid zero row outcome became successful partial account output")
	}
}

func TestAccountAndCredentialZeroValuesAndDiagnostics(t *testing.T) {
	if (Account{}).Validate("tenant-a", "user-a") == nil || (CredentialRef{}).Validate("tenant-a", "user-a") == nil {
		t.Fatal("zero metadata accepted")
	}
	for _, raw := range []string{"", " bad", "bad\x00", strings.Repeat("x", 129)} {
		if id, err := ParseAccountID(raw); err == nil || id != "" {
			t.Fatal("invalid account ID accepted")
		}
	}
	id, err := ParseAccountID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil || string(id) != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatal("canonical imported ID changed")
	}
	_, _, s := accountFixture(t)
	if strings.Contains(fmt.Sprintf("%#v", s.Accounts[0]), "subject-a") {
		t.Fatal("account metadata appeared in diagnostic")
	}
}

func FuzzAccountValidation(f *testing.F) {
	f.Add("account-a", "example", "https://issuer.example", "subject-a")
	f.Add("", "", "urn:example:enterprise", "")
	f.Fuzz(func(t *testing.T, id, provider, issuer, subject string) {
		a := Account{ID: AccountID(id), TenantID: "tenant-a", UserID: "user-a", Provider: provider, Issuer: issuer, Subject: subject, Version: 1}
		if a.Validate("tenant-a", "user-a") != nil {
			return
		}
		if len(id) == 0 || len(id) > 128 || len(provider) > 128 || len(issuer) > 2048 || len(subject) == 0 || len(subject) > 512 || strings.ContainsAny(issuer, "?#") {
			t.Fatal("unbounded account metadata accepted")
		}
	})
}
