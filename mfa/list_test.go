package mfa

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func factorListRequestFixture(t *testing.T) ListRequest {
	t.Helper()
	token, err := session.ParseToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return ListRequest{TenantID: "tenant-a", Credential: credential, CorrelationID: "factor-list-fixture"}
}

func TestFactorListRequestRequiresRealCredentialAndBoundedScope(t *testing.T) {
	r := factorListRequestFixture(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid list structure denied", err)
	}
	for _, change := range []func(*ListRequest){
		func(r *ListRequest) { r.TenantID = "" },
		func(r *ListRequest) { r.Credential = session.Credential{} },
		func(r *ListRequest) { r.CorrelationID = "" },
		func(r *ListRequest) { r.CorrelationID = "unsafe\ncorrelation" },
	} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid list structure accepted")
		}
	}
}

func TestFactorListSnapshotAllowsEmptyButRejectsForeignOrCorruptMetadata(t *testing.T) {
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	q := FactorListQuery{TenantID: "tenant-a", UserID: "user-a"}
	snapshot := FactorListSnapshot{TenantID: q.TenantID, UserID: q.UserID, AuthorityVersion: 1, Factors: []FactorProjection{}, TrustedDevices: []TrustedDeviceProjection{}}
	if _, err := snapshot.Projection(q, now); err != nil {
		t.Fatal("empty authoritative inventory denied", err)
	}
	factor := FactorProjection{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Method: "totp", State: FactorActive, CreatedAt: now.Add(-time.Minute), Version: 1}
	snapshot.Factors = []FactorProjection{factor}
	snapshot.RecoveryCodeCount = 10
	projected, err := snapshot.Projection(q, now)
	if err != nil || len(projected.Factors) != 1 || projected.RecoveryCodeCount != 10 {
		t.Fatal("safe projection unavailable", err)
	}
	projected.Factors[0].Label = "caller-mutation"
	if snapshot.Factors[0].Label != "" {
		t.Fatal("projection aliases borrowed metadata")
	}
	for _, change := range []func(*FactorListSnapshot){
		func(s *FactorListSnapshot) { s.TenantID = "other" },
		func(s *FactorListSnapshot) { s.UserID = "other" },
		func(s *FactorListSnapshot) { s.AuthorityVersion = 0 },
		func(s *FactorListSnapshot) { s.RecoveryCodeCount = 101 },
		func(s *FactorListSnapshot) { s.Factors[0].Version = 0 },
		func(s *FactorListSnapshot) { s.Factors[0].Method = "" },
		func(s *FactorListSnapshot) { s.Factors[0].State = FactorState(0) },
		func(s *FactorListSnapshot) { s.Factors[0].CreatedAt = now.Add(time.Second) },
		func(s *FactorListSnapshot) { s.Factors[0].Label = "unsafe\nlabel" },
		func(s *FactorListSnapshot) { s.Factors = append(s.Factors, s.Factors[0]) },
		func(s *FactorListSnapshot) { s.TrustedDevices = []TrustedDeviceProjection{{}} },
	} {
		bad := snapshot
		bad.Factors = append([]FactorProjection(nil), snapshot.Factors...)
		change(&bad)
		if out, err := bad.Projection(q, now); err == nil || len(out.Factors) != 0 {
			t.Fatal("foreign/corrupt metadata disclosed partial inventory")
		}
	}
}

type unauthenticatedFactorListSession struct{}

func (unauthenticatedFactorListSession) Get(context.Context, session.GetRequest) (session.GetResult, error) {
	return session.GetResult{}, nil
}

type forbiddenFactorListRead struct{}

func (forbiddenFactorListRead) ReadFactors(context.Context, FactorListQuery) (FactorListSnapshot, error) {
	panic("unauthenticated inventory read")
}

type enrollmentListPolicy struct{}

func (enrollmentListPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	panic("unauthenticated policy admission")
}

type factorListClock struct{}

func (factorListClock) Now() time.Time { return time.Now() }

func TestFactorListDeniesUnauthenticatedCallerBeforeMetadataRead(t *testing.T) {
	service, err := NewListService(unauthenticatedFactorListSession{}, forbiddenFactorListRead{}, ListConfig{Authorization: enrollmentListPolicy{}, Clock: factorListClock{}, PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.List(context.Background(), factorListRequestFixture(t))
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || len(out.Factors) != 0 {
		t.Fatal("unauthenticated list did not deny before read", err)
	}
}

func TestFactorListConstructorAndCancellationFailClosed(t *testing.T) {
	config := ListConfig{Authorization: enrollmentListPolicy{}, Clock: factorListClock{}, PolicyRevision: 1, MaximumDuration: time.Second}
	for _, change := range []func(*ListConfig){
		func(c *ListConfig) { c.Authorization = nil },
		func(c *ListConfig) { c.Clock = nil },
		func(c *ListConfig) { c.PolicyRevision = 0 },
		func(c *ListConfig) { c.MaximumDuration = 0 },
		func(c *ListConfig) { c.MaximumDuration = 6 * time.Second },
	} {
		bad := config
		change(&bad)
		if service, err := NewListService(unauthenticatedFactorListSession{}, forbiddenFactorListRead{}, bad); err == nil || service != nil {
			t.Fatal("invalid list composition accepted")
		}
	}
	var missing *unauthenticatedFactorListSession
	if service, err := NewListService(missing, forbiddenFactorListRead{}, config); err == nil || service != nil {
		t.Fatal("typed-nil session source accepted")
	}
	service, err := NewListService(unauthenticatedFactorListSession{}, forbiddenFactorListRead{}, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := service.List(ctx, factorListRequestFixture(t)); !errors.Is(err, context.Canceled) || len(out.Factors) != 0 {
		t.Fatal("cancelled listing disclosed metadata or lost cancellation")
	}
}

func TestFactorListProjectionBoundsAndDeviceMetadata(t *testing.T) {
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	query := FactorListQuery{TenantID: "tenant-a", UserID: "user-a"}
	snapshot := FactorListSnapshot{TenantID: query.TenantID, UserID: query.UserID, AuthorityVersion: 1,
		TrustedDevices: []TrustedDeviceProjection{{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Label: "Laptop", ExpiresAt: now.Add(time.Hour), LastUsedAt: now.Add(-time.Minute), Version: 1}}}
	if out, err := snapshot.Projection(query, now); err != nil || len(out.TrustedDevices) != 1 || out.RecoveryCodeCount != 0 {
		t.Fatal("valid device metadata and exhausted codes denied")
	}
	for _, change := range []func(*FactorListSnapshot){
		func(s *FactorListSnapshot) { s.TrustedDevices[0].Label = string([]byte{0xff}) },
		func(s *FactorListSnapshot) { s.TrustedDevices[0].Version = 0 },
		func(s *FactorListSnapshot) { s.TrustedDevices[0].LastUsedAt = now.Add(time.Second) },
		func(s *FactorListSnapshot) { s.TrustedDevices[0].ExpiresAt = time.Time{} },
		func(s *FactorListSnapshot) { s.TrustedDevices = append(s.TrustedDevices, s.TrustedDevices[0]) },
		func(s *FactorListSnapshot) { s.TrustedDevices = make([]TrustedDeviceProjection, 101) },
		func(s *FactorListSnapshot) { s.Factors = make([]FactorProjection, 101) },
	} {
		bad := snapshot
		bad.TrustedDevices = append([]TrustedDeviceProjection(nil), snapshot.TrustedDevices...)
		change(&bad)
		if out, err := bad.Projection(query, now); err == nil || len(out.Factors) != 0 || len(out.TrustedDevices) != 0 {
			t.Fatal("invalid/oversized device or factor inventory disclosed")
		}
	}
}

func TestFactorListResultValidationIsDisplayOnly(t *testing.T) {
	now := time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
	result := ListResult{Factors: []FactorProjection{}, TrustedDevices: []TrustedDeviceProjection{}}
	if result.ValidateAt(now) != nil {
		t.Fatal("empty display output denied")
	}
	result.Outcome = identity.CommitOutcomeCommitted
	if result.ValidateAt(now) == nil {
		t.Fatal("read output claimed a mutation commit")
	}
	result.Outcome = 0
	result.RecoveryCodeCount = 101
	if result.ValidateAt(now) == nil {
		t.Fatal("oversized display output accepted")
	}
}
