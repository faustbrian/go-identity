package reference

import (
	"reflect"
	"testing"
	"time"
)

func TestUserStatusRequestIntentBindsEffectNotCredential(t *testing.T) {
	expires := time.Date(2026, 11, 28, 12, 0, 0, 123000, time.UTC)
	input := AdminUserStatusRequest{
		TenantID: "tenant-a", UserID: "target-a", ExpectedVersion: 4, ExpectedAuthorityVersion: 3,
		Reason: "security", ExpiresAt: expires,
	}
	frozen, err := userStatusRequestIntent(input, 9)
	if err != nil {
		t.Fatal(err)
	}
	fields, ok := frozen.Fields()
	if !ok || len(fields) != 7 {
		t.Fatal("status key intent omitted one of its fixed effect fields")
	}
	for _, change := range []func(*AdminUserStatusRequest){
		func(r *AdminUserStatusRequest) { r.TenantID = "tenant-b" },
		func(r *AdminUserStatusRequest) { r.UserID = "target-b" },
		func(r *AdminUserStatusRequest) { r.ExpectedVersion++ },
		func(r *AdminUserStatusRequest) { r.ExpectedAuthorityVersion++ },
		func(r *AdminUserStatusRequest) { r.Reason = "moderation" },
		func(r *AdminUserStatusRequest) { r.ExpiresAt = r.ExpiresAt.Add(time.Microsecond) },
		func(r *AdminUserStatusRequest) { r.ExpiresAt = time.Time{} },
	} {
		changed := input
		change(&changed)
		intent, err := userStatusRequestIntent(changed, 9)
		if err != nil {
			t.Fatal(err)
		}
		next, _ := intent.Fields()
		if reflect.DeepEqual(fields, next) {
			t.Fatal("changed effect input matched the original request-key intent")
		}
	}
	changedPolicy, err := userStatusRequestIntent(input, 10)
	if err != nil {
		t.Fatal(err)
	}
	revised, _ := changedPolicy.Fields()
	if reflect.DeepEqual(fields, revised) {
		t.Fatal("different status policy matched original request-key intent")
	}
}
