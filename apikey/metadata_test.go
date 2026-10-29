package apikey_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/apikey"
)

func metadataAuthentication() apikey.Authentication {
	return apikey.Authentication{TenantID: "tenant-a", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE")}
}

func TestMetadataRequestsBindExplicitOwnerAndBoundPagination(t *testing.T) {
	get := apikey.GetRequest{Authentication: metadataAuthentication(), KeyID: "canonical-key"}
	if get.Validate() != nil {
		t.Fatal("valid self metadata request denied")
	}
	get.OrganizationID = "organization-a"
	if get.Validate() != nil {
		t.Fatal("explicit organization target denied")
	}
	for _, change := range []func(*apikey.GetRequest){
		func(r *apikey.GetRequest) { r.KeyID = "" },
		func(r *apikey.GetRequest) { r.Authentication = apikey.Authentication{} },
		func(r *apikey.GetRequest) { r.OrganizationID = "invalid organization" },
		func(r *apikey.GetRequest) { r.CorrelationID = strings.Repeat("a", 129) },
	} {
		bad := get
		change(&bad)
		if !errors.Is(bad.Validate(), apikey.ErrInvalid) {
			t.Fatal("invalid metadata request accepted")
		}
	}
	list := apikey.ListRequest{Authentication: metadataAuthentication(), ConfigurationIDs: []string{"legacy", "modern"}, Limit: 200}
	if list.Validate() != nil {
		t.Fatal("valid bounded page denied")
	}
	for _, change := range []func(*apikey.ListRequest){
		func(r *apikey.ListRequest) { r.Limit = 0 },
		func(r *apikey.ListRequest) { r.Limit = 201 },
		func(r *apikey.ListRequest) { r.ConfigurationIDs = []string{"modern", "legacy"} },
		func(r *apikey.ListRequest) { r.ConfigurationIDs = []string{"modern", "modern"} },
		func(r *apikey.ListRequest) { r.ConfigurationIDs = []string{""} },
		func(r *apikey.ListRequest) { r.ConfigurationIDs = make([]string, 17) },
		func(r *apikey.ListRequest) { r.Cursor = strings.Repeat("x", 513) },
		func(r *apikey.ListRequest) { r.OrganizationID = "invalid organization" },
	} {
		bad := list
		change(&bad)
		if !errors.Is(bad.Validate(), apikey.ErrInvalid) {
			t.Fatal("unbounded or ambiguous metadata page accepted")
		}
	}
}

func TestMetadataRequestsRetainCredentialRedaction(t *testing.T) {
	get := apikey.GetRequest{Authentication: metadataAuthentication(), KeyID: "sensitive-key"}
	list := apikey.ListRequest{Authentication: metadataAuthentication(), Limit: 1, Cursor: "sensitive-cursor"}
	for _, value := range []any{get, list} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, "sensitive") || strings.Contains(got, "AAAA") || strings.Contains(got, "tenant-a") {
				t.Fatal("metadata request diagnostics disclosed scope or credential")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, apikey.ErrDisclosure) {
			t.Fatal("metadata request allowed implicit credential serialization")
		}
	}
}

func FuzzMetadataPageShape(f *testing.F) {
	f.Add("modern", "cursor", uint16(1))
	f.Add("", "", uint16(0))
	f.Fuzz(func(t *testing.T, configuration, cursor string, limit uint16) {
		r := apikey.ListRequest{Authentication: metadataAuthentication(), ConfigurationIDs: []string{configuration}, Cursor: cursor, Limit: limit}
		if r.Validate() == nil && (len(configuration) == 0 || len(configuration) > 128 || len(cursor) > 512 || limit == 0 || limit > 200) {
			t.Fatal("unbounded page shape accepted")
		}
	})
}
