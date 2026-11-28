package impersonation_test

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/impersonation"
)

func TestPolicyWithQuorumBoundaries(t *testing.T) {
	for _, required := range []int{-1, 0, 1, 2, 32, 33} {
		t.Run(strconv.Itoa(required), func(t *testing.T) {
			policy, err := impersonation.NewPolicyWithQuorum("support", 3, required)
			if required < 1 || required > 32 {
				if !errors.Is(err, impersonation.ErrInvalidInput) || policy != (impersonation.Policy{}) {
					t.Fatalf("invalid quorum returned policy %v and error %v", policy, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if policy.ID() != "support" || policy.Version() != 3 || policy.RequiredApprovals() != required {
				t.Fatalf("policy lost exact identity, revision or quorum: %v", policy)
			}
		})
	}
}

func TestPolicyWithQuorumRejectsMalformedIdentityAndRevision(t *testing.T) {
	for _, id := range []string{"", "bad id", strings.Repeat("x", 129)} {
		if _, err := impersonation.NewPolicyWithQuorum(id, 3, 2); !errors.Is(err, impersonation.ErrInvalidInput) {
			t.Fatalf("malformed policy ID accepted: %v", err)
		}
	}
	if _, err := impersonation.NewPolicyWithQuorum("support", 0, 2); !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatalf("zero policy revision accepted: %v", err)
	}
	var zero impersonation.Policy
	if zero.RequiredApprovals() != 0 {
		t.Fatal("zero policy acquired an approval requirement")
	}
	input := requestInput(t)
	input.Policy = zero
	if _, err := impersonation.NewRequest(input); !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatalf("zero policy became valid request intent: %v", err)
	}
}

func TestPolicyWithOneApprovalPreservesLegacyPolicyAndBinding(t *testing.T) {
	input := requestInput(t)
	legacyPolicy := input.Policy
	explicitPolicy, err := impersonation.NewPolicyWithQuorum("support", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if explicitPolicy != legacyPolicy || legacyPolicy.RequiredApprovals() != 1 {
		t.Fatal("NewPolicy is not exactly equivalent to explicit quorum one")
	}
	legacyRequest, err := impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Policy = explicitPolicy
	explicitRequest, err := impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(quorumPolicyFixtureBindingBytes("identity.impersonation.request.binding.v1"))
	if legacyRequest.Digest() != want || explicitRequest.Digest() != want {
		t.Fatalf("one-approval binding no longer matches historical v1 bytes: legacy=%x explicit=%x want=%x", legacyRequest.Digest(), explicitRequest.Digest(), want)
	}
}

func TestPolicyQuorumChangesRequestBindingWithSeparateDomain(t *testing.T) {
	input := requestInput(t)
	legacy, err := impersonation.NewRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[32]byte]bool{legacy.Digest(): true}
	for _, required := range []int{2, 3, 32} {
		t.Run(strconv.Itoa(required), func(t *testing.T) {
			policy, err := impersonation.NewPolicyWithQuorum("support", 3, required)
			if err != nil {
				t.Fatal(err)
			}
			input.Policy = policy
			request, err := impersonation.NewRequest(input)
			if err != nil {
				t.Fatal(err)
			}
			if request.Policy() != policy || request.Input().Policy != policy {
				t.Fatal("request lost its immutable quorum policy")
			}
			canonical := quorumPolicyFixtureBindingBytes("identity.impersonation.request.binding.v2")
			canonical = binary.BigEndian.AppendUint64(canonical, uint64(required))
			want := sha256.Sum256(canonical)
			if request.Digest() != want {
				t.Fatalf("quorum request lacks v2 domain and exact required count: got=%x want=%x", request.Digest(), want)
			}
			if seen[request.Digest()] {
				t.Fatal("different required counts share a request binding")
			}
			seen[request.Digest()] = true
		})
	}
}

// Fixed pre-quorum fixture bytes independently preserve the historical binding;
// they do not call production digest helpers or derive fields from the request.
func quorumPolicyFixtureBindingBytes(domain string) []byte {
	var canonical []byte
	appendString := func(value string) {
		canonical = binary.BigEndian.AppendUint64(canonical, uint64(len(value)))
		canonical = append(canonical, value...)
	}
	appendString(domain)
	appendString("tenant")
	appendString("actor")
	appendString("target")
	canonical = binary.BigEndian.AppendUint64(canonical, 7)
	canonical = binary.BigEndian.AppendUint64(canonical, 2)
	appendString("address:read")
	appendString("profile:read")
	reasonDigest := sha256.Sum256([]byte("sensitive support reason"))
	canonical = append(canonical, reasonDigest[:]...)
	canonical = binary.BigEndian.AppendUint64(canonical, uint64(15*time.Minute))
	appendString("support")
	canonical = binary.BigEndian.AppendUint64(canonical, 3)
	return canonical
}
