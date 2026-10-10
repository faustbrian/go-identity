package password_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

// QA input/custody/remember partitions: validation cannot consume either secret,
// select a user, restart a flow, normalize a password or allocate a retry key.
func signinInput(t testing.TB) password.SigninRequest {
	t.Helper()
	secret, err := primitive.NewSecret([]byte(" raw\x00synthetic-ä-password "))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Destroy)
	id, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: 7 * 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 5 * time.Minute, FreshFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	r := password.SigninRequest{TenantID: "tenant", PreAuthID: id, Cookie: auth.NewBearerCredential(cookie), Identifier: " Synthetic@example.test ", Password: secret, Remember: remember, Origin: "https://example.test", CallbackURL: "https://example.test/after", Network: "192.0.2.1", Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "public-ingress"}, Tenant: "tenant", Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}}
	return r
}

func TestSigninRequestOriginalCustody(t *testing.T) {
	r := signinInput(t)
	secret, cookie, remember := r.Password, r.Cookie.Token(), r.Remember
	if err := r.Validate(); err != nil {
		t.Fatal("valid input denied", err)
	}
	if r.Cookie.Token() != cookie || r.Remember != remember || string(r.Identifier) != " Synthetic@example.test " {
		t.Fatal("original input changed")
	}
	for _, n := range []int{1, 4096, 4097} {
		bounded := r
		bounded.Identifier = identifier.Input(strings.Repeat("i", n))
		if (bounded.Validate() == nil) != (n <= 4096) {
			t.Fatal("identifier byte boundary")
		}
	}
	noRedirect := r
	noRedirect.CallbackURL = ""
	if err := noRedirect.Validate(); err != nil {
		t.Fatal("explicit no redirect denied", err)
	}
	for _, size := range []int{1, 1 << 20, 1<<20 + 1} {
		owned, err := primitive.NewSecret([]byte(strings.Repeat("p", size)))
		if size > 1<<20 && err != nil {
			continue // The primitive owner denies oversized custody before the request.
		}
		if err != nil {
			t.Fatal("password fixture", err)
		}
		bounded := r
		bounded.Password = owned
		accepted := bounded.Validate() == nil
		owned.Destroy()
		if accepted != (size <= 1<<20) {
			t.Fatal("password byte boundary")
		}
	}
	for _, change := range []func(*password.SigninRequest){
		func(r *password.SigninRequest) { r.TenantID = "" },
		func(r *password.SigninRequest) { r.PreAuthID = "invalid" },
		func(r *password.SigninRequest) { r.Cookie = auth.BearerCredential{} },
		func(r *password.SigninRequest) { r.Cookie = auth.NewBearerCredential(cookie + "=") },
		func(r *password.SigninRequest) { r.Identifier = "" },
		func(r *password.SigninRequest) { r.Identifier = "\xff" },
		func(r *password.SigninRequest) { r.Password = primitive.Secret{} },
		func(r *password.SigninRequest) { r.Remember = session.RememberPolicy{} },
		func(r *password.SigninRequest) { r.Caller.Request.Tenant = "foreign" },
		func(r *password.SigninRequest) { r.Caller.PolicyRevision = 0 },
		func(r *password.SigninRequest) {
			r.Caller.Request.Environment.Time = time.Unix(1, 0).In(time.FixedZone(strings.Repeat("z", 129), 0))
		},
		func(r *password.SigninRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectGroup },
		func(r *password.SigninRequest) { r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65) },
		func(r *password.SigninRequest) {
			r.Caller.Request.Subject.Groups = []authorization.SubjectID{authorization.SubjectID(strings.Repeat("g", 129))}
		},
		func(r *password.SigninRequest) {
			r.Caller.Request.Attributes = authorization.Attributes{"oversized": authorization.StringValue(strings.Repeat("a", 4097))}
		},
		func(r *password.SigninRequest) {
			r.Caller.Request.Subject.Attributes = authorization.Attributes{authorization.AttributeName(strings.Repeat("k", 129)): authorization.BoolValue(true)}
		},
		func(r *password.SigninRequest) {
			r.Caller.Request.Environment.Attributes = authorization.Attributes{"set": authorization.StringSetValue([]string{strings.Repeat("v", 4097)})}
		},
		func(r *password.SigninRequest) {
			r.Caller.Request.Action = authorization.Action(strings.Repeat("x", 129))
		},
		func(r *password.SigninRequest) { r.Origin = "" },
		func(r *password.SigninRequest) { r.Origin = "https://example.test\n" },
		func(r *password.SigninRequest) { r.Origin = strings.Repeat("x", 2049) },
		func(r *password.SigninRequest) { r.CallbackURL = strings.Repeat("x", 2049) },
		func(r *password.SigninRequest) { r.Network = "192.0.2.001" },
		func(r *password.SigninRequest) { r.Network = strings.Repeat("x", 129) },
		func(r *password.SigninRequest) { r.Device = "device\n" },
	} {
		bad := r
		change(&bad)
		if !errors.Is(bad.Validate(), password.ErrPasswordWork) {
			t.Fatal("invalid input admitted")
		}
	}
	for _, field := range []string{"CommandID", "IdempotencyKey", "UserID", "Proof", "Now", "Assurance"} {
		if _, found := reflect.TypeOf(r).FieldByName(field); found {
			t.Fatal("caller selects authority or replay identity")
		}
	}
	for _, value := range []any{r, &r} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%d"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "Synthetic") || strings.Contains(out, "example.test") || strings.Contains(out, cookie) || strings.Contains(out, "192.0.2.1") {
				t.Fatal("diagnostic disclosure")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, password.ErrSensitiveSerialization) {
			t.Fatal("implicit request export")
		}
	}
	if raw, err := r.MarshalText(); len(raw) != 0 || !errors.Is(err, password.ErrSensitiveSerialization) {
		t.Fatal("implicit text export")
	}
	if strings.Contains(r.LogValue().String(), "example.test") {
		t.Fatal("structured log disclosure")
	}
	if err := secret.Use(func(raw []byte) error {
		if string(raw) != " raw\x00synthetic-ä-password " {
			t.Error("password changed")
		}
		return nil
	}); err != nil {
		t.Fatal("validation consumed custody", err)
	}
	secret.Destroy()
	if !errors.Is(r.Validate(), password.ErrPasswordWork) {
		t.Fatal("destroyed secret admitted")
	}
}

// Fuzz new admission against the identifier owner's raw-input oracle. This
// does not claim native URL, policy or account authentication.
func FuzzSigninRequestIdentifier(f *testing.F) {
	r := signinInput(f)
	for _, input := range []string{"", "x", "\xff", " Ä@example.test ", strings.Repeat("x", 4096), strings.Repeat("x", 4097)} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		request := r
		request.Identifier = identifier.Input(raw)
		_, ownerErr := identifier.NewInput(raw)
		if (request.Validate() == nil) != (ownerErr == nil) {
			t.Fatal("identifier owner admission differs")
		}
		if string(request.Identifier) != raw {
			t.Fatal("validation normalized identifier")
		}
	})
}

func TestSigninCallerNestedBounds(t *testing.T) {
	r := signinInput(t)
	r.Caller.Request.Environment.Time = time.Unix(1, 0).UTC()
	if err := r.Validate(); err != nil {
		t.Fatal("UTC evaluation context denied", err)
	}
	setters := []func(*password.SigninRequest, authorization.Attributes){
		func(r *password.SigninRequest, a authorization.Attributes) { r.Caller.Request.Attributes = a },
		func(r *password.SigninRequest, a authorization.Attributes) { r.Caller.Request.Subject.Attributes = a },
		func(r *password.SigninRequest, a authorization.Attributes) { r.Caller.Request.Resource.Attributes = a },
		func(r *password.SigninRequest, a authorization.Attributes) {
			r.Caller.Request.Environment.Attributes = a
		},
	}
	for _, set := range setters {
		items := make([]string, 65)
		for i := range items {
			items[i] = fmt.Sprint(i)
		}
		for _, bad := range []authorization.Attributes{
			{"": authorization.BoolValue(true)},
			{"missing": {}},
			{authorization.AttributeName(strings.Repeat("k", 129)): authorization.BoolValue(true)},
			{"string": authorization.StringValue(strings.Repeat("v", 4097))},
			{"string": authorization.StringValue("\xff")},
			{"set": authorization.StringSetValue(items)},
			{"set": authorization.StringSetValue([]string{strings.Repeat("v", 4097)})},
			{"set": authorization.StringSetValue([]string{"\xff"})},
			{"ip": authorization.IPValue(netip.MustParseAddr("fe80::1").WithZone(strings.Repeat("z", 129)))},
			{"ip": authorization.IPValue(netip.MustParseAddr("fe80::1").WithZone("\xff"))},
			{"ip": authorization.IPValue(netip.MustParseAddr("fe80::1").WithZone("z\n"))},
		} {
			request := r
			set(&request, bad)
			if !errors.Is(request.Validate(), password.ErrPasswordWork) {
				t.Fatal("unbounded nested caller admitted")
			}
		}
		for _, count := range []int{64, 65} {
			attrs := authorization.Attributes{}
			for i := 0; i < count; i++ {
				attrs[authorization.AttributeName(fmt.Sprint(i))] = authorization.BoolValue(true)
			}
			request := r
			set(&request, attrs)
			if (request.Validate() == nil) != (count == 64) {
				t.Fatal("attribute count boundary")
			}
		}
		request := r
		set(&request, authorization.Attributes{authorization.AttributeName(strings.Repeat("k", 128)): authorization.StringValue(strings.Repeat("v", 4096)), "set": authorization.StringSetValue(items[:64]), "ip": authorization.IPValue(netip.MustParseAddr("fe80::1").WithZone(strings.Repeat("z", 128))), "zone-free-ip": authorization.IPValue(netip.MustParseAddr("2001:db8::1"))})
		if err := request.Validate(); err != nil {
			t.Fatal("inclusive nested bounds denied", err)
		}
	}
	for _, count := range []int{64, 65} {
		request := r
		request.Caller.Request.Subject.Groups = make([]authorization.SubjectID, count)
		for i := range request.Caller.Request.Subject.Groups {
			request.Caller.Request.Subject.Groups[i] = authorization.SubjectID(strings.Repeat("g", 128))
		}
		if (request.Validate() == nil) != (count == 64) {
			t.Fatal("group count/byte boundary")
		}
	}
}
