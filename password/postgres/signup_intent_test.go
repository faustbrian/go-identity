package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

// SU05: original correlation commits every submitted intent without retaining
// a recoverable password or allowing normalization to merge distinct secrets.
func TestSignupIntentBindsRawCustodyAndAllRequestedIntent(t *testing.T) {
	owner := &Repository{}
	r, _, _, _ := nativeSignupFlow(t)
	r.IdempotencyKey, _ = identity.NewIdempotencyKey(bytes.Repeat([]byte{51}, 32))
	r.AllowedFields = []identity.AttributeUpdate{{Name: "name", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "synthetic"}}}, {Name: "locale", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "en"}}}}
	policy := password.RegistrationPolicy{Enabled: true, MinimumBytes: 8, MaximumBytes: 128, RequireVerifiedEmail: true}
	key, profile := [32]byte{1}, [32]byte{2}
	original, err := owner.signupRequestIntent(context.Background(), r, key, profile, policy)
	fields, valid := original.Fields()
	if err != nil || !valid {
		t.Fatal("valid original intent denied")
	}
	for _, mutate := range []func(*password.SignupRequest){
		func(r *password.SignupRequest) { r.TenantID = "foreign"; r.Caller.Request.Tenant = "foreign" },
		func(r *password.SignupRequest) { r.Caller.Request.Subject.ID = "foreign" },
		func(r *password.SignupRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectAPIKey },
		func(r *password.SignupRequest) { r.Email = "changed@example.test" },
		func(r *password.SignupRequest) { r.PreAuthID = "AgICAgICAgICAgICAgICAg" },
		func(r *password.SignupRequest) { r.Origin = "https://other.test" },
		func(r *password.SignupRequest) { r.CallbackURL = "" },
		func(r *password.SignupRequest) { r.Network = "192.0.2.2" },
		func(r *password.SignupRequest) { r.Device = "other-device" },
		func(r *password.SignupRequest) {
			r.Cookie = auth.NewBearerCredential("ZGVmaW5pdGVseS1hLXN5bnRoZXRpYy1jb29raWUtMTI")
		},
		func(r *password.SignupRequest) {
			r.RememberPolicy, _ = session.ResolveRememberPolicy(session.PersistentSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
		},
		func(r *password.SignupRequest) { r.AllowedFields[0].Value.Scalar.String = "changed" },
		func(r *password.SignupRequest) {
			secret, _ := primitive.NewSecret([]byte("synthetic-password"))
			t.Cleanup(secret.Destroy)
			r.Password = secret
		},
	} {
		bad := r
		bad.AllowedFields = append([]identity.AttributeUpdate(nil), r.AllowedFields...)
		mutate(&bad)
		changed, err := owner.signupRequestIntent(context.Background(), bad, key, profile, policy)
		got, _ := changed.Fields()
		if err != nil || reflect.DeepEqual(fields, got) {
			t.Fatal("changed original intent did not obtain a distinct commitment")
		}
	}
	// Whole-field submission order is not a semantic change, but list order is.
	reordered := r
	reordered.AllowedFields = []identity.AttributeUpdate{r.AllowedFields[1], r.AllowedFields[0]}
	again, err := owner.signupRequestIntent(context.Background(), reordered, key, profile, policy)
	got, _ := again.Fields()
	if err != nil || !reflect.DeepEqual(fields, got) {
		t.Fatal("equivalent field ordering remapped original intent")
	}
	wire, _ := json.Marshal(fields)
	if bytes.Contains(wire, []byte("synthetic")) || bytes.Contains(wire, []byte("example.test")) || bytes.Contains(wire, []byte(r.Cookie.Token())) {
		t.Fatal("original intent retained plaintext custody")
	}
	if r.Password.Len() == 0 {
		t.Fatal("intent destroyed caller password")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := owner.signupRequestIntent(ctx, r, key, profile, policy); err != context.Canceled {
		t.Fatal("intent lost cancellation")
	}
	if _, err := owner.signupRequestIntent(context.Background(), r, [32]byte{}, profile, policy); err == nil {
		t.Fatal("missing dedicated intent key accepted")
	}
	if _, err := owner.signupRequestIntent(context.Background(), r, key, [32]byte{}, policy); err == nil {
		t.Fatal("missing configuration commitment accepted")
	}
	for _, selection := range []struct{ key, profile [32]byte }{{[32]byte{3}, profile}, {key, [32]byte{4}}} {
		other, err := owner.signupRequestIntent(context.Background(), r, selection.key, selection.profile, policy)
		got, _ := other.Fields()
		if err != nil || reflect.DeepEqual(fields, got) {
			t.Fatal("different key/configuration reused original intent")
		}
	}
	for _, size := range []int{7, 8, 128, 129} {
		candidate, _ := primitive.NewSecret(bytes.Repeat([]byte{32}, size))
		changed := r
		changed.Password = candidate
		_, err := owner.signupRequestIntent(context.Background(), changed, key, profile, policy)
		candidate.Destroy()
		if (size == 8 || size == 128) != (err == nil) {
			t.Fatal("inclusive raw password byte limits changed")
		}
	}
	policy.Enabled = false
	if _, err := owner.signupRequestIntent(context.Background(), r, key, profile, policy); err != password.ErrRegistrationDisabled {
		t.Fatal("disabled signup admitted intent")
	}
}
