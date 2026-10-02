package postgres

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

func codecBinding() identity.CommandBinding {
	return identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAABA", TenantID: "tenant-a", UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ActorID: "actor-a", ActorKind: authorization.SubjectUser, OperationID: "identity.user.create", PolicyID: "policy", PolicyVersion: 1, SchemaID: "fields", SchemaVersion: 1, CorrelationID: "correlation"}
}

func codecCreation(t *testing.T, attrs []identity.AttributeUpdate) identity.Command {
	t.Helper()
	c, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: attrs})
	if e != nil {
		t.Fatal("creation fixture invalid")
	}
	return c
}

func TestCommandCodecCreation(t *testing.T) {
	key := [32]byte{1}
	a := identity.AttributeUpdate{Name: "z", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "synthetic-private-value"}}}
	b := identity.AttributeUpdate{Name: "a", Value: identity.AttributeValue{Kind: identity.AttributeInt64, Scalar: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: math.MinInt64}}}
	first, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{a, b}), key)
	if e != nil {
		t.Fatal("typed encoding failed")
	}
	reversed, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{b, a}), key)
	if e != nil || !bytes.Equal(first.canonical, reversed.canonical) {
		t.Fatal("equivalent whole-field replacements changed fingerprint")
	}
	if bytes.Contains(first.canonical, []byte(a.Value.Scalar.String)) || bytes.Contains(first.safeFields, []byte(a.Value.Scalar.String)) {
		t.Fatal("private field leaked into encoding")
	}
	if !bytes.Contains(first.safeFields, []byte(codecBinding().UserID)) {
		t.Fatal("directory ID was transformed")
	}
	a.Value.Scalar.String = "different-synthetic-value"
	changed, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{a, b}), key)
	if e != nil || bytes.Equal(first.canonical, changed.canonical) || !bytes.Equal(first.safeFields, changed.safeFields) {
		t.Fatal("payload not bound independently of safe scope")
	}
	rotated, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{a, b}), [32]byte{2})
	if e != nil || bytes.Equal(changed.canonical, rotated.canonical) {
		t.Fatal("secret digest not keyed")
	}
	for _, invalid := range []identity.Command{{}} {
		if _, e := prepareClaim(invalid, key); e == nil {
			t.Fatal("zero command accepted")
		}
	}
	if _, e := prepareClaim(codecCreation(t, nil), [32]byte{}); e == nil {
		t.Fatal("zero key accepted")
	}
}

func TestCommandCodecEmptyFields(t *testing.T) {
	a, e := prepareClaim(codecCreation(t, nil), [32]byte{1})
	if e != nil {
		t.Fatal("nil fields")
	}
	b, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{}), [32]byte{1})
	if e != nil || !bytes.Equal(a.canonical, b.canonical) {
		t.Fatal("empty field representation changed logical command")
	}
}

func TestCommandCodecTimesAndLists(t *testing.T) {
	for _, tm := range []time.Time{time.Unix(-1, 999999000), time.Unix(100, 1000).In(time.FixedZone("offset", 3600))} {
		attr := identity.AttributeUpdate{Name: "at", Value: identity.AttributeValue{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: tm}}}
		p, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{attr}), [32]byte{1})
		if e != nil {
			t.Fatal("exact time rejected")
		}
		attr.Value.Scalar.Time = tm.UTC()
		q, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{attr}), [32]byte{1})
		if e != nil || !bytes.Equal(p.canonical, q.canonical) {
			t.Fatal("UTC-equivalent timestamp changed fingerprint")
		}
	}
	for _, tm := range []time.Time{time.Unix(1, 1), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		attr := identity.AttributeUpdate{Name: "at", Value: identity.AttributeValue{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: tm}}}
		if _, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{attr}), [32]byte{1}); e == nil {
			t.Fatal("lossy PostgreSQL timestamp accepted")
		}
	}
	list := identity.AttributeUpdate{Name: "items", Value: identity.AttributeValue{Kind: identity.AttributeStringList, List: []identity.AttributeScalar{{Kind: identity.AttributeString, String: "first"}, {Kind: identity.AttributeString, String: "second"}}}}
	p, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{list}), [32]byte{1})
	if e != nil {
		t.Fatal("list rejected")
	}
	list.Value.List[0], list.Value.List[1] = list.Value.List[1], list.Value.List[0]
	q, e := prepareClaim(codecCreation(t, []identity.AttributeUpdate{list}), [32]byte{1})
	if e != nil || bytes.Equal(p.canonical, q.canonical) {
		t.Fatal("list order lost")
	}
}

func TestCommandCodecUTCRange(t *testing.T) {
	for _, tt := range []struct {
		local time.Time
		valid bool
	}{
		{time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("minus", -3600)), false},
		{time.Date(1, 1, 1, 0, 30, 0, 0, time.FixedZone("plus", 3600)), false},
		{time.Date(10000, 1, 1, 0, 30, 0, 0, time.FixedZone("plus", 3600)), true},
		{time.Date(0, 12, 31, 23, 30, 0, 0, time.FixedZone("minus", -3600)), true},
	} {
		for _, variant := range []string{"create", "update", "profile"} {
			var previous []byte
			for _, tm := range []time.Time{tt.local, tt.local.UTC()} {
				attr := identity.AttributeUpdate{Name: "at", Value: identity.AttributeValue{Kind: identity.AttributeTime, Scalar: identity.AttributeScalar{Kind: identity.AttributeTime, Time: tm}}}
				bind := codecBinding()
				var c identity.Command
				var e error
				switch variant {
				case "create":
					c = codecCreation(t, []identity.AttributeUpdate{attr})
				case "update":
					bind.OperationID = "identity.user.update-admin"
					c, e = identity.NewUserUpdateCommand(identity.UpdateUserCommand{Binding: bind, ExpectedVersion: 1, Attributes: []identity.AttributeUpdate{attr}})
				case "profile":
					bind.OperationID = "identity.profile.update"
					bind.ActorID = identity.ActorID(bind.UserID)
					c, e = identity.NewProfileUpdateCommand(identity.ProfileUpdateCommand{Binding: bind, ExpectedVersion: 1, AdditionalFields: []identity.AttributeUpdate{attr}})
				}
				if e != nil {
					t.Fatal("direct typed fixture rejected")
				}
				p, e := prepareClaim(c, [32]byte{1})
				if (e == nil) != tt.valid {
					t.Fatal("UTC storage range depends on supplied timezone")
				}
				if tt.valid {
					if previous != nil && !bytes.Equal(previous, p.canonical) {
						t.Fatal("equivalent UTC instant changed encoding")
					}
					previous = p.canonical
				}
			}
		}
	}
}

func FuzzCommandCodec(f *testing.F) {
	f.Add("synthetic", int64(-1))
	f.Add("", int64(0))
	f.Add("é", int64(math.MinInt64))
	f.Fuzz(func(t *testing.T, s string, n int64) {
		if len(s) > 4096 {
			return
		}
		attrs := []identity.AttributeUpdate{{Name: "a", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: s}}}, {Name: "b", Value: identity.AttributeValue{Kind: identity.AttributeInt64, Scalar: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: n}}}}
		c, e := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: codecBinding(), Status: identity.StatusActive, Attributes: attrs})
		if e != nil {
			return
		}
		p, e := prepareClaim(c, [32]byte{1})
		if e != nil {
			t.Fatal("valid bounded command rejected")
		}
		attrs[0], attrs[1] = attrs[1], attrs[0]
		c = codecCreation(t, attrs)
		q, e := prepareClaim(c, [32]byte{1})
		if e != nil || !bytes.Equal(p.canonical, q.canonical) || len(p.canonical) > 1<<20 {
			t.Fatal("encoding invariant failed")
		}
	})
}

func TestCommandCodecVariants(t *testing.T) {
	bind := codecBinding()
	bind.OperationID = "identity.user.update-admin"
	attrs := []identity.AttributeUpdate{{Name: "enabled", Value: identity.AttributeValue{Kind: identity.AttributeBool, Scalar: identity.AttributeScalar{Kind: identity.AttributeBool}}}}
	update, e := identity.NewUserUpdateCommand(identity.UpdateUserCommand{Binding: bind, ExpectedVersion: 1, Attributes: attrs})
	if e != nil {
		t.Fatal("update fixture")
	}
	changed, e := identity.NewUserUpdateCommand(identity.UpdateUserCommand{Binding: bind, ExpectedVersion: 2, Attributes: attrs})
	if e != nil {
		t.Fatal("update fixture")
	}
	p, e := prepareClaim(update, [32]byte{1})
	if e != nil {
		t.Fatal("update codec")
	}
	q, e := prepareClaim(changed, [32]byte{1})
	if e != nil || bytes.Equal(p.canonical, q.canonical) {
		t.Fatal("version fence omitted")
	}
	bind.OperationID = "identity.profile.update"
	bind.ActorID = identity.ActorID(bind.UserID)
	profile, e := identity.NewProfileUpdateCommand(identity.ProfileUpdateCommand{Binding: bind, ExpectedVersion: 1, Name: "Synthetic Name"})
	if e != nil {
		t.Fatal("profile fixture")
	}
	p, e = prepareClaim(profile, [32]byte{1})
	if e != nil || bytes.Contains(p.canonical, []byte("Synthetic Name")) {
		t.Fatal("profile codec exposed name")
	}
	bind.OperationID = "identity.user.suspend"
	bind.SchemaID = "identity-lifecycle"
	status, e := identity.NewUserStatusCommand(identity.UserStatusCommand{Binding: bind, ExpectedVersion: 1, ExpectedAuthorityVersion: 2, StatusPolicyVersion: 3, TargetStatus: identity.StatusSuspended, Reason: "security", ExpiresAt: time.Unix(100, 1000)})
	if e != nil {
		t.Fatal("status fixture")
	}
	p, e = prepareClaim(status, [32]byte{1})
	if e != nil || !bytes.Contains(p.canonical, []byte("expected_authority_version")) {
		t.Fatal("authority fence omitted")
	}
}

func TestCanonicalCBORVectors(t *testing.T) {
	// RFC 8949 Appendix A integer/array examples, plus profile map ordering.
	for _, tt := range []struct {
		value []byte
		hex   string
	}{
		{cborUint(0), "00"}, {cborUint(23), "17"}, {cborUint(24), "1818"}, {cborUint(256), "190100"}, {cborUint(65536), "1a00010000"}, {cborUint(math.MaxUint64), "1bffffffffffffffff"},
		{cborInt(-1), "20"}, {cborInt(-1000), "3903e7"}, {cborInt(math.MinInt64), "3b7fffffffffffffff"},
		{cborArray([][]byte{cborUint(1), cborUint(2), cborUint(3)}), "83010203"},
		{cborMap(map[string][]byte{"aa": cborUint(2), "b": cborUint(1)}), "a261620162616102"},
	} {
		want, _ := hex.DecodeString(tt.hex)
		if !bytes.Equal(tt.value, want) {
			t.Fatal("canonical CBOR vector mismatch")
		}
	}
}

func TestSecretFraming(t *testing.T) {
	a, e := commandSecret([32]byte{1}, "attributes.a", []byte("bc"), 4096)
	if e != nil {
		t.Fatal("digest failed")
	}
	// Independent Ruby/OpenSSL framing oracle, using synthetic inputs only.
	want, _ := hex.DecodeString("fb056ba66bbf6a5da238d0844dea8513e4a966fb55824fc16eefa8a6732e0813")
	if !bytes.Equal(a, want) {
		t.Fatal("secret domain/length framing differs from fixed oracle")
	}
	b, e := commandSecret([32]byte{1}, "attributes.ab", []byte("c"), 4096)
	if e != nil || bytes.Equal(a, b) {
		t.Fatal("field path/secret boundary collision")
	}
	for _, tt := range []struct {
		path   string
		secret []byte
		bound  int
	}{{"", nil, 1}, {string(bytes.Repeat([]byte{'a'}, 4097)), nil, 1}, {"a", []byte{1, 2}, 1}, {"a", nil, -1}, {string([]byte{255}), nil, 1}} {
		if _, e := commandSecret([32]byte{1}, tt.path, tt.secret, tt.bound); e == nil {
			t.Fatal("unbounded secret accepted")
		}
	}
}
