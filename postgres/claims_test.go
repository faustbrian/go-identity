package postgres

import (
	"strings"
	"testing"
)

func TestClaimInputBounds(t *testing.T) {
	good := claimRequest{commandID: "AAAAAAAAAAAAAAAAAAAAAQ", tenant: "tenant-a", purpose: "identity.user.create", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	if !validClaim(good, keys) {
		t.Fatal("valid prepared claim rejected")
	}
	for _, alter := range []func(*claimRequest){
		func(q *claimRequest) { q.commandID = "AAAAAAAAAAAAAAAAAAAAAA" },
		func(q *claimRequest) { q.tenant = "bad tenant" },
		func(q *claimRequest) { q.purpose = "" },
		func(q *claimRequest) { q.purpose = "Identity.User.Create" },
		func(q *claimRequest) { q.purpose = "1identity" },
		func(q *claimRequest) { q.purpose = strings.Repeat("a", 129) },
		func(q *claimRequest) { q.canonical = nil },
		func(q *claimRequest) { q.canonical = make([]byte, (1<<20)+1) },
		func(q *claimRequest) { q.safeFields = nil },
		func(q *claimRequest) { q.safeFields = make([]byte, 65537) },
	} {
		q := good
		alter(&q)
		if validClaim(q, keys) {
			t.Fatal("invalid claim admitted")
		}
	}
	for _, keys := range []claimKeys{
		{}, {current: 1}, {current: 1, retained: map[uint32][32]byte{1: {}}},
		{current: 1, retained: map[uint32][32]byte{0: {1}, 1: {1}}},
		{current: 2, retained: map[uint32][32]byte{1: {1}}},
	} {
		if validClaim(good, keys) {
			t.Fatal("invalid retained-key configuration admitted")
		}
	}
}
