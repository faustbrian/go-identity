package postgres

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func TestOrganizationRecordRetainsIndependentOwnerWithoutCreator(t *testing.T) {
	c, record := recordFixture(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: record.Owner.Spec().TenantID, Kind: apikey.OwnerOrganization, OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	record.Owner = owner
	wire, err := encodeRecord(record, c)
	if err != nil {
		t.Fatal("organization record cannot persist without borrowing a creator", err)
	}
	restored, err := decodeRecord(wire, c)
	if err != nil || !reflect.DeepEqual(restored, record) || restored.Owner.Spec().UserID != "" {
		t.Fatal("stored organization owner/epoch changed", err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(wire, []byte(`"UserID":""`), []byte(`"UserID":"creator"`), 1),
		bytes.Replace(wire, []byte(`"OrganizationID":"01ARZ3NDEKTSV4RRFFQ69G5FAX"`), []byte(`"OrganizationID":""`), 1),
		bytes.Replace(wire, []byte(`"Kind":2`), []byte(`"Kind":1`), 1),
		append(bytes.Clone(wire), 0),
	} {
		if _, err := decodeRecord(bad, c); err == nil {
			t.Fatal("organization storage accepted invented or ambiguous owner identity")
		}
	}
}
