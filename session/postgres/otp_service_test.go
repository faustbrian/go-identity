package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOTPReaderDerivesExactOwnerScopesAndRejectsOtherProfiles(t *testing.T) {
	c := OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}
	record := otpRecordFixture(t, true)
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
	sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	pk, _ := (authority.AuthorityScope{TenantID: "tenant-a", PolicyNamespace: "users", SubjectID: "user-a"}).Key()
	a.Global.ScopeKey, a.Tenant.ScopeKey, a.User.ScopeKey, a.Identifier.ScopeKey, a.Credential.ScopeKey = keys.Global, keys.Tenant, keys.User, keys.Identifier, keys.Credential
	a.SessionFamily.ScopeKey, a.Session.ScopeKey, a.Authorization.ScopeKey = sk.Family, sk.Session, pk
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	record, err := session.NewSessionWithOTPAndCSRF(s, record.OTPAuthentication(), record.CSRFState())
	if err != nil {
		t.Fatal(err)
	}
	query, scope, err := otpSessionAdmission(c, record)
	if err != nil || query.TenantID != s.TenantID || string(scope.SubjectID) != string(s.UserID) {
		t.Fatal("exact OTP owners denied", err)
	}
	for _, mutate := range []func(*OTPAdmissionConfig){
		func(c *OTPAdmissionConfig) { c.GlobalAuthorityID = "foreign" },
		func(c *OTPAdmissionConfig) { c.PolicyNamespace = "foreign" },
		func(c *OTPAdmissionConfig) { c.Audience = "foreign" },
		func(c *OTPAdmissionConfig) { c.GlobalAuthorityID = "" },
	} {
		changed := c
		mutate(&changed)
		if _, _, err := otpSessionAdmission(changed, record); !errors.Is(err, session.ErrUnauthenticated) {
			t.Fatal("foreign OTP owner admitted", err)
		}
	}
	for _, other := range []session.Session{{}, testSession(t)} {
		if _, _, err := otpSessionAdmission(c, other); !errors.Is(err, session.ErrUnauthenticated) {
			t.Fatal("other authentication profile admitted", err)
		}
	}
	if got, err := NewOTPSessionService(nil, OTPSessionServiceConfig{}); got != nil || err == nil {
		t.Fatal("zero reader configuration accepted")
	}
	for _, value := range []struct {
		input    any
		redacted string
	}{{c, "postgres.OTPAdmissionConfig(redacted)"}, {OTPSessionServiceConfig{Profile: c}, "postgres.OTPSessionServiceConfig(redacted)"}} {
		if _, err := json.Marshal(value.input); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("implicit config disclosure", err)
		}
		if fmt.Sprintf("%#v", value.input) != value.redacted {
			t.Fatal("configuration formatting disclosed profile")
		}
	}
	var reader *primarySessionReader
	if _, err := reader.ObserveSession(context.Background(), session.SessionLookup{}); !errors.Is(err, session.ErrInvalidInput) {
		t.Fatal("zero reader admitted", err)
	}
}
