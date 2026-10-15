package emailhttp

import (
	"net/url"
	"strings"
	"testing"
)

func TestAddressQueryKeepsOnlyBoundedSelfReadParameters(t *testing.T) {
	for _, c := range []struct {
		get    bool
		values url.Values
		valid  bool
		limit  uint32
	}{
		{values: url.Values{}, valid: true},
		{get: true, values: url.Values{"addressID": {"owned-address"}}, valid: true},
		{values: url.Values{"limit": {"100"}, "cursor": {"opaque-position"}}, valid: true, limit: 100},
		{get: true, values: url.Values{}},
		{get: true, values: url.Values{"addressID": {""}}},
		{get: true, values: url.Values{"addressID": {"one", "two"}}},
		{get: true, values: url.Values{"addressID": {"owned"}, "userID": {"other"}}},
		{values: url.Values{"tenantID": {"other"}}},
		{values: url.Values{"limit": {"0"}}},
		{values: url.Values{"limit": {"101"}}},
		{values: url.Values{"limit": {"01"}}},
		{values: url.Values{"limit": {"+1"}}},
		{values: url.Values{"limit": {"18446744073709551616"}}},
		{values: url.Values{"limit": {"1", "2"}}},
		{values: url.Values{"cursor": {""}}},
		{values: url.Values{"cursor": {strings.Repeat("x", 513)}}},
	} {
		out, err := decodeAddressQuery(c.values, c.get)
		if (err == nil) != c.valid || err == nil && out.limit != c.limit {
			t.Fatal("address query widened self scope or bounds", c.get, c.valid)
		}
	}
}
