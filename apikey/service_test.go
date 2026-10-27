package apikey_test

import (
	"net/netip"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
)

func TestUserOwnedCreationHasNoOwnerOrActorOverrideAndRejectsMalformedIntent(t *testing.T) {
	key, _ := identity.NewIdempotencyKey([]byte("api-key-create-original"))
	r := apikey.CreateRequest{Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")}, IdempotencyKey: key, Name: "automation", Permissions: []string{"invoice.read"}, ExpiresAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Network: "192.0.2.1"}
	if r.Validate() != nil {
		t.Fatal("valid bounded intent rejected")
	}
	for _, change := range []func(*apikey.CreateRequest){
		func(r *apikey.CreateRequest) { r.Authentication.TenantID = "" },
		func(r *apikey.CreateRequest) { r.Authentication.Bearer = auth.BearerCredential{} },
		func(r *apikey.CreateRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		func(r *apikey.CreateRequest) { r.Permissions = []string{"invoice.read", "invoice.read"} },
		func(r *apikey.CreateRequest) { r.ExpiresAt = time.Time{} },
		func(r *apikey.CreateRequest) { r.Network = "spoofed" },
	} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("malformed original intent accepted")
		}
	}
}

func FuzzManagementNetworkBounds(f *testing.F) {
	for _, network := range []string{"192.0.2.1", "::1", "::ffff:192.0.2.1", "", "spoofed", "fe80::1%en0"} {
		f.Add(network)
	}
	f.Fuzz(func(t *testing.T, network string) {
		key, _ := identity.NewIdempotencyKey([]byte("bounded-network-intent"))
		r := apikey.Rotation{Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")}, IdempotencyKey: key, KeyID: "key-a", ExpectedVersion: 1, Network: network}
		if r.Validate() != nil {
			return
		}
		ip, err := netip.ParseAddr(network)
		if err != nil || len(network) > 45 || ip.Zone() != "" || ip.Unmap().String() != network || ip.IsUnspecified() || ip.IsMulticast() {
			t.Fatal("noncanonical trusted network admitted")
		}
		if apikey.Revocation(r).Validate() != nil {
			t.Fatal("revocation changed trusted network semantics")
		}
	})
}

func TestRecoveryAdmitsOnlyExactOriginalSelfManagementScope(t *testing.T) {
	r := apikey.RecoveryRequest{Authentication: apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")}, Query: identity.RecoveryQuery{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: "identity.apikey.rotate", RecordID: "key-a"}}
	if r.Validate() != nil {
		t.Fatal("original self scope rejected")
	}
	for _, change := range []func(*apikey.RecoveryRequest){
		func(r *apikey.RecoveryRequest) { r.Query.TenantID = "other" },
		func(r *apikey.RecoveryRequest) { r.Query.ActorID = "other" },
		func(r *apikey.RecoveryRequest) { r.Query.ActorKind = authorization.SubjectAPIKey },
		func(r *apikey.RecoveryRequest) { r.Query.OperationID = "identity.apikey.verify" },
		func(r *apikey.RecoveryRequest) { r.Query.AnonymousFlowID = "AQEBAQEBAQEBAQEBAQEBAQ" },
		func(r *apikey.RecoveryRequest) { r.Query.CommandID = "" },
	} {
		bad := r
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("foreign or reinterpreted original accepted")
		}
	}
}
