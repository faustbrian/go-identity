package impersonation_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
)

func requestInput(t *testing.T) impersonation.RequestInput {
	t.Helper()
	actor, err := impersonation.NewActor("tenant", "actor")
	if err != nil {
		t.Fatal(err)
	}
	target, err := impersonation.NewTarget("tenant", "target", 7)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := impersonation.NewScope([]string{"profile:read", "address:read"})
	if err != nil {
		t.Fatal(err)
	}
	reason, err := impersonation.NewReason("sensitive support reason")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := impersonation.NewPolicy("support", 3)
	if err != nil {
		t.Fatal(err)
	}
	return impersonation.RequestInput{Tenant: "tenant", Actor: actor, Target: target, Scope: scope, Reason: reason, Duration: 15 * time.Minute, Policy: policy}
}

func fixture(t *testing.T) (impersonation.Grant, impersonation.ApprovalInput) {
	t.Helper()
	request, err := impersonation.NewRequest(requestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	grant, err := impersonation.NewPendingGrant("AQEBAQEBAQEBAQEBAQEBAQ", request, now)
	if err != nil {
		t.Fatal(err)
	}
	approver, err := impersonation.NewActor("tenant", "approver")
	if err != nil {
		t.Fatal(err)
	}
	reason, err := impersonation.NewReason("independent review")
	if err != nil {
		t.Fatal(err)
	}
	return grant, impersonation.ApprovalInput{GrantID: grant.ID(), ExpectedVersion: 1, Request: request, Approver: approver, Reason: reason, At: now.Add(time.Minute)}
}

func TestPendingRequestAndDistinctApproval(t *testing.T) {
	grant, input := fixture(t)
	if grant.Status() != impersonation.StatusPendingApproval || grant.Version() != 1 || !grant.ExpiresAt().Equal(grant.RequestedAt().Add(15*time.Minute)) {
		t.Fatal("pending grant lost bounds")
	}
	approved, approval, err := impersonation.Approve(grant, input)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status() != impersonation.StatusApproved || approved.Version() != 2 || grant.Status() != impersonation.StatusPendingApproval {
		t.Fatal("approval did not return a new version")
	}
	if approval.Approver() != input.Approver || approval.RequestDigest() != input.Request.Digest() || approval.RequestVersion() != 1 || approval.GrantID() != grant.ID() {
		t.Fatal("approval lost exact binding")
	}
	if _, _, err := impersonation.Approve(approved, input); !errors.Is(err, impersonation.ErrConflict) {
		t.Fatalf("repeated transition: %v", err)
	}
}

func TestApprovalRejectsSelfTargetCrossTenantStaleExpiredAndChangedIntent(t *testing.T) {
	for _, name := range []string{"self", "target", "tenant", "version", "id", "expired", "before-request", "zero-time", "policy-id", "policy-version", "target-version", "scope", "reason", "duration", "actor", "target-user", "request-zero", "reason-zero"} {
		t.Run(name, func(t *testing.T) {
			grant, input := fixture(t)
			request := requestInput(t)
			switch name {
			case "self":
				input.Approver = request.Actor
			case "target":
				input.Approver, _ = impersonation.NewActor("tenant", "target")
			case "tenant":
				input.Approver, _ = impersonation.NewActor("other", "approver")
			case "version":
				input.ExpectedVersion++
			case "id":
				input.GrantID = "BBBBBBBBBBBBBBBBBBBBBQ"
			case "expired":
				input.At = grant.ExpiresAt()
			case "before-request":
				input.At = grant.RequestedAt().Add(-time.Nanosecond)
			case "zero-time":
				input.At = time.Time{}
			case "policy-id":
				request.Policy, _ = impersonation.NewPolicy("different", 3)
			case "policy-version":
				request.Policy, _ = impersonation.NewPolicy("support", 4)
			case "target-version":
				request.Target, _ = impersonation.NewTarget("tenant", "target", 8)
			case "scope":
				request.Scope, _ = impersonation.NewScope([]string{"profile:read"})
			case "reason":
				request.Reason, _ = impersonation.NewReason("changed reason")
			case "duration":
				request.Duration = time.Minute
			case "actor":
				request.Actor, _ = impersonation.NewActor("tenant", "another")
			case "target-user":
				request.Target, _ = impersonation.NewTarget("tenant", "another", 7)
			case "request-zero":
				input.Request = impersonation.Request{}
			case "reason-zero":
				input.Reason = impersonation.Reason{}
			}
			if strings.HasPrefix(name, "policy-") || strings.HasPrefix(name, "target-") || name == "scope" || name == "reason" || name == "duration" || name == "actor" {
				input.Request, _ = impersonation.NewRequest(request)
			}
			approved, approval, err := impersonation.Approve(grant, input)
			if err == nil || approved.Status() != impersonation.StatusUnspecified || approval.GrantID() != "" {
				t.Fatal("invalid approval accepted or returned authority")
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("reason leaked in denial")
			}
		})
	}
}

func TestRequestValidationAndStableCanonicalDigest(t *testing.T) {
	input := requestInput(t)
	request, err := impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	permissions := input.Scope.Permissions()
	permissions[0] = "modified"
	input.Scope, _ = impersonation.NewScope([]string{"address:read", "profile:read"})
	restored, err := impersonation.NewRequest(input)
	if err != nil || request.Digest() != restored.Digest() {
		t.Fatal("scope order/caller mutation changed canonical request")
	}
	if request.Reason().Digest() != sha256.Sum256([]byte("sensitive support reason")) {
		t.Fatal("reason digest mismatch")
	}
	for _, name := range []string{"zero", "tenant", "self", "duration-zero", "duration-large", "scope-zero", "reason-zero", "policy-zero", "actor-zero", "target-zero"} {
		t.Run(name, func(t *testing.T) {
			bad := requestInput(t)
			switch name {
			case "zero":
				bad = impersonation.RequestInput{}
			case "tenant":
				bad.Tenant = "different"
			case "self":
				bad.Target, _ = impersonation.NewTarget("tenant", "actor", 7)
			case "duration-zero":
				bad.Duration = 0
			case "duration-large":
				bad.Duration = 15*time.Minute + time.Nanosecond
			case "scope-zero":
				bad.Scope = impersonation.Scope{}
			case "reason-zero":
				bad.Reason = impersonation.Reason{}
			case "policy-zero":
				bad.Policy = impersonation.Policy{}
			case "actor-zero":
				bad.Actor = impersonation.Actor{}
			case "target-zero":
				bad.Target = impersonation.Target{}
			}
			if _, err := impersonation.NewRequest(bad); !errors.Is(err, impersonation.ErrInvalidInput) {
				t.Fatalf("invalid request: %v", err)
			}
		})
	}
}

func TestBoundedValuesAndReasonRedaction(t *testing.T) {
	for _, raw := range []string{"", " ", "\xff", strings.Repeat("x", 1025)} {
		if _, err := impersonation.NewReason(raw); err == nil {
			t.Fatal("invalid reason accepted")
		}
	}
	for _, scope := range [][]string{nil, {""}, {"read", "read"}, {"read write"}, {"\xff"}, {strings.Repeat("x", 129)}, make([]string, 65)} {
		if _, err := impersonation.NewScope(scope); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
	for _, id := range []identity.UserID{"", "bad id", identity.UserID(strings.Repeat("x", 129))} {
		if _, err := impersonation.NewActor("tenant", id); err == nil {
			t.Fatal("invalid actor accepted")
		}
	}
	if _, err := impersonation.NewTarget("tenant", "target", 0); err == nil {
		t.Fatal("zero target version accepted")
	}
	if _, err := impersonation.NewPolicy("policy", 0); err == nil {
		t.Fatal("zero policy version accepted")
	}
	grant, input := fixture(t)
	for _, value := range []any{input.Reason, input.Request, grant, requestInput(t)} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "sensitive support reason") {
				t.Fatal("reason leaked through formatting")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "sensitive support reason") {
			t.Fatal("reason leaked through JSON")
		}
	}
}

func TestPendingGrantRejectsReservedZeroAndNoncanonicalIDs(t *testing.T) {
	grant, _ := fixture(t)
	for _, id := range []impersonation.GrantID{"", "AAAAAAAAAAAAAAAAAAAAAA", "AQEBAQEBAQEBAQEBAQEBAR", "short"} {
		if _, err := impersonation.NewPendingGrant(id, grant.Request(), grant.RequestedAt()); !errors.Is(err, impersonation.ErrInvalidInput) {
			t.Fatalf("invalid grant ID accepted: %v", err)
		}
	}
}

func TestRequestRejectsSubsecondDuration(t *testing.T) {
	input := requestInput(t)
	input.Duration = time.Second - time.Nanosecond
	if _, err := impersonation.NewRequest(input); !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatalf("subsecond request accepted: %v", err)
	}
	input.Duration = time.Second
	if _, err := impersonation.NewRequest(input); err != nil {
		t.Fatalf("minimum valid duration denied: %v", err)
	}
}

func TestScopeCopiesInputAndExposesOnlyCallerOwnedSlices(t *testing.T) {
	permissions := []string{"profile:read", "address:read"}
	scope, err := impersonation.NewScope(permissions)
	if err != nil {
		t.Fatal(err)
	}
	permissions[0] = "changed"
	returned := scope.Permissions()
	if strings.Join(returned, ",") != "address:read,profile:read" {
		t.Fatal("scope retained mutable caller input")
	}
	returned[0] = "changed"
	if strings.Join(scope.Permissions(), ",") != "address:read,profile:read" {
		t.Fatal("scope returned mutable storage")
	}
}

func TestPersistenceRoundTripPreservesExactIntentAndDeadline(t *testing.T) {
	grant, input := fixture(t)
	original := grant.Request().Input()
	actor, _ := impersonation.NewActor(original.Actor.Tenant(), original.Actor.User())
	target, _ := impersonation.NewTarget(original.Target.Tenant(), original.Target.User(), original.Target.Version())
	scope, _ := impersonation.NewScope(original.Scope.Permissions())
	reason, _ := impersonation.NewReason(original.Reason.StorageText())
	policy, _ := impersonation.NewPolicy(original.Policy.ID(), original.Policy.Version())
	request, err := impersonation.NewRequest(impersonation.RequestInput{Tenant: original.Tenant, Actor: actor, Target: target, Scope: scope, Reason: reason, Duration: original.Duration, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	encodedAt := grant.RequestedAt().Format(time.RFC3339Nano)
	storedAt, err := time.Parse(time.RFC3339Nano, encodedAt)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := impersonation.NewPendingGrant(grant.ID(), request, storedAt)
	if err != nil || restored.Request().Digest() != grant.Request().Digest() || !restored.ExpiresAt().Equal(grant.ExpiresAt()) {
		t.Fatal("persistence changed original binding")
	}
	input.Request = request
	approved, approval, err := impersonation.Approve(restored, input)
	if err != nil || approved.Version() != 2 || !approval.At().Equal(input.At) {
		t.Fatal("rehydrated approval failed")
	}
}

func TestStatusAndZeroGrantFailClosed(t *testing.T) {
	for _, status := range []impersonation.Status{impersonation.StatusUnspecified, "unknown"} {
		if status.Valid() {
			t.Fatal("invalid status accepted")
		}
	}
	_, input := fixture(t)
	if _, _, err := impersonation.Approve(impersonation.Grant{}, input); !errors.Is(err, impersonation.ErrConflict) {
		t.Fatalf("zero grant: %v", err)
	}
	grant, _ := fixture(t)
	for _, at := range []time.Time{grant.RequestedAt(), grant.ExpiresAt().Add(-time.Nanosecond)} {
		input.At = at
		if _, _, err := impersonation.Approve(grant, input); err != nil {
			t.Fatalf("valid boundary denied: %v", err)
		}
	}
}

func FuzzReasonAndScope(f *testing.F) {
	for _, seed := range []string{"", "read", "\xff", "sensitive reason", strings.Repeat("x", 1025)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		reason, err := impersonation.NewReason(raw)
		if err == nil && reason.StorageText() != raw {
			t.Fatal("reason changed input")
		}
		if err != nil && strings.Contains(err.Error(), raw) && len(raw) > 32 {
			t.Fatal("reason leaked in error")
		}
		scope, err := impersonation.NewScope([]string{raw})
		if err == nil && (len(scope.Permissions()) != 1 || scope.Permissions()[0] != raw) {
			t.Fatal("scope changed permission")
		}
	})
}
