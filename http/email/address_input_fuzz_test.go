package emailhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func FuzzAddressReadQuery(f *testing.F) {
	for _, raw := range []string{"", "addressID=owned-address", "targetSubjectID=other-user", "addressID=owned-address&targetSubjectID=other-user", "targetSubjectID=other&targetSubjectID=second", "targetSubjectID=%00", "limit=100&cursor=opaque", "limit=01", "limit=1&LIMIT=2", "userID=other", "addressID=%00", "cursor=%FF", "limit=18446744073709551616"} {
		f.Add(raw, true)
		f.Add(raw, false)
	}
	f.Fuzz(func(t *testing.T, raw string, get bool) {
		if len(raw) > 2048 {
			return
		}
		d, err := identityhttp.NewRequestDecoder(identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 4096, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 8, MaximumDepth: 4})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "https://app.example/v1/email/address-list", nil)
		r.URL.RawQuery = raw
		r.RequestURI = r.URL.RequestURI()
		values, err := d.Query(r)
		if err != nil {
			return
		}
		for _, admin := range []bool{false, true} {
			out, err := decodeAddressQuery(values, get, admin)
			if err != nil {
				continue
			}
			if len(out.target) > 128 || !admin && out.target != "" || out.limit > 100 || len(out.cursor) > 512 || get && (out.id == "" || len(out.id) > 128 || out.limit != 0 || out.cursor != "") || !get && out.id != "" {
				t.Fatal("query escaped selected native read bounds")
			}
		}
	})
}
