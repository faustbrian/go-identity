package emailhttp

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/email"
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

type administrativeQueryCapability struct {
	selected bool
	panic    bool
}

func (s administrativeQueryCapability) AdministrativeQueriesConfigured() bool {
	if s.panic {
		panic("private")
	}
	return s.selected
}
func (administrativeQueryCapability) AddressGet(context.Context, email.AddressGetRequest) (email.AddressGetResult, error) {
	return email.AddressGetResult{}, nil
}
func (administrativeQueryCapability) AddressList(context.Context, email.AddressListRequest) (email.AddressListResult, error) {
	return email.AddressListResult{}, nil
}

func TestAdministrativeQueryRequiresNativeAuditCapabilityAndClosedWireSelection(t *testing.T) {
	var native *email.AddressQueryService
	for _, c := range []struct {
		service AddressQueryService
		want    bool
	}{
		{nil, false}, {native, false}, {administrativeQueryCapability{}, false}, {administrativeQueryCapability{selected: true}, true}, {administrativeQueryCapability{selected: true, panic: true}, false},
	} {
		if administrativeQueriesConfigured(c.service) != c.want {
			t.Fatal("audit capability failed open")
		}
	}
	for _, get := range []bool{false, true} {
		for _, selected := range []bool{false, true} {
			wire := addressQueryWire(AddressQueryConfig{AdministrativeTargets: selected}, get)
			if bytes.Contains(wire.Definition, []byte(`"name":"targetSubjectID"`)) != selected {
				t.Fatal("wire advertised unselected target scope")
			}
		}
	}
}

func TestAddressQueryRequiresExplicitAdministrativeSelection(t *testing.T) {
	for _, get := range []bool{false, true} {
		for _, mode := range []string{"enabled", "disabled", "duplicate", "empty", "alias", "tenant"} {
			values := url.Values{"targetSubjectID": {"other-user"}}
			if get {
				values.Set("addressID", "owned-address")
			}
			enabled := mode != "disabled"
			switch mode {
			case "duplicate":
				values["targetSubjectID"] = []string{"other-user", "another"}
			case "empty":
				values.Set("targetSubjectID", "")
			case "alias":
				values.Set("userID", "other-user")
			case "tenant":
				values.Set("tenantID", "foreign")
			}
			_, err := decodeAddressQuery(values, get, enabled)
			if (err == nil) != (mode == "enabled") {
				t.Fatal("administrative selector widened or disappeared", get, mode, err)
			}
		}
	}
}
