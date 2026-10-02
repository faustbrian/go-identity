package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func featureCodecSpec() identity.FeatureCommandSpec {
	b := codecBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", "session-a"
	return identity.FeatureCommandSpec{Binding: b, Operation: identity.FeatureOperation{Owner: "identity/session", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}, Fields: []identity.FeatureField{
		{Name: "authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: math.MaxUint64}},
		{Name: "context", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-private-context"}},
		{Name: "metadata", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("synthetic-binary-metadata")}},
		{Name: "remember", Value: identity.FeatureValue{Kind: identity.FeatureBool}},
		{Name: "duration", Value: identity.FeatureValue{Kind: identity.FeatureInt64, Int64: math.MinInt64}},
		{Name: "at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Unix(-1, 999999000)}},
	}}
}

func featureCodecCommand(t *testing.T, s identity.FeatureCommandSpec) identity.Command {
	t.Helper()
	c, err := identity.NewFeatureCommand(s)
	if err != nil {
		t.Fatal("feature fixture", err)
	}
	return c
}

func TestFeatureCommandCodecCanonicalPrivacyAndKey(t *testing.T) {
	s := featureCodecSpec()
	key := [32]byte{1}
	p, err := prepareClaim(featureCodecCommand(t, s), key)
	if err != nil {
		t.Fatal("feature intent rejected", err)
	}
	if p.commandID != s.Binding.CommandID || p.tenant != s.Binding.TenantID || p.purpose != s.Binding.OperationID || p.source == nil {
		t.Fatal("claim scope lost")
	}
	if !validClaim(p, claimKeys{current: 1, retained: map[uint32][32]byte{1: key}}) {
		t.Fatal("prepared claim invalid")
	}
	for _, private := range [][]byte{[]byte(s.Fields[1].Value.Text), s.Fields[2].Value.Bytes} {
		if bytes.Contains(p.canonical, private) || bytes.Contains(p.safeFields, private) {
			t.Fatal("private value leaked")
		}
	}
	// Independent literal scalar bytes and HMAC framing, not encoder self-comparison.
	value := []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	path := []byte("feature.authority")
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("identity-command-secret-v1"))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(path))))
	mac.Write(path)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(value))))
	mac.Write(value)
	if !bytes.Contains(p.canonical, mac.Sum(nil)) {
		t.Fatal("unsigned scalar/framing changed")
	}
	for i, j := 0, len(s.Fields)-1; i < j; i, j = i+1, j-1 {
		s.Fields[i], s.Fields[j] = s.Fields[j], s.Fields[i]
	}
	q, err := prepareClaim(featureCodecCommand(t, s), key)
	if err != nil || !bytes.Equal(p.canonical, q.canonical) || !bytes.Equal(p.safeFields, q.safeFields) {
		t.Fatal("named field order affected intent")
	}
	rotated, err := prepareClaim(featureCodecCommand(t, s), [32]byte{2})
	if err != nil || bytes.Equal(p.canonical, rotated.canonical) || !bytes.Equal(p.safeFields, rotated.safeFields) {
		t.Fatal("rotation did not rekey only private intent")
	}
	old, err := prepareClaim(*rotated.source, key)
	if err != nil || !bytes.Equal(old.canonical, p.canonical) {
		t.Fatal("retained-key replay changed original intent")
	}
	if _, err := prepareClaim(featureCodecCommand(t, s), [32]byte{}); err == nil {
		t.Fatal("zero key admitted")
	}
}

func TestFeatureCommandCodecBindsCompleteIntent(t *testing.T) {
	s := featureCodecSpec()
	p, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Uint64-- },
		func(s *identity.FeatureCommandSpec) { s.Fields[1].Value.Text = "other-synthetic-context" },
		func(s *identity.FeatureCommandSpec) { s.Fields[2].Value.Bytes = []byte("other-synthetic-metadata") },
		func(s *identity.FeatureCommandSpec) { s.Fields[3].Value.Bool = true },
		func(s *identity.FeatureCommandSpec) { s.Fields[4].Value.Int64++ },
		func(s *identity.FeatureCommandSpec) {
			s.Fields[5].Value.Time = s.Fields[5].Value.Time.Add(time.Microsecond)
		},
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "other.authority" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/password" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.RecordRequirement = identity.FeatureRecordOmitted
			s.Binding.RecordID = ""
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion++; s.Binding.SchemaVersion++ },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "other-schema"
			s.Binding.SchemaID = "other-schema"
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.session.rotate"
			s.Binding.OperationID = s.Operation.OperationID
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.PolicyVersion++ },
		func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other-actor" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other-tenant" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "other-user" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "empty", Value: identity.FeatureValue{Kind: identity.FeatureText}})
		},
	} {
		changed := featureCodecSpec()
		mutate(&changed)
		q, err := prepareClaim(featureCodecCommand(t, changed), [32]byte{1})
		if err != nil || bytes.Equal(p.canonical, q.canonical) {
			t.Fatal("behavior-bearing intent omitted", err)
		}
	}
	for _, v := range []identity.FeatureValue{{Kind: identity.FeatureUint64}, {Kind: identity.FeatureInt64}, {Kind: identity.FeatureBool}, {Kind: identity.FeatureText}, {Kind: identity.FeatureBytes}} {
		s.Fields = []identity.FeatureField{{Name: "zero", Value: v}}
		q, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		s.Fields = nil
		absent, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		if err != nil || bytes.Equal(q.canonical, absent.canonical) {
			t.Fatal("explicit zero became absent")
		}
	}
}

func TestFeatureCommandCodecUTCAndAdmissionRemainClosed(t *testing.T) {
	s := featureCodecSpec()
	p, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	s.Fields[5].Value.Time = s.Fields[5].Value.Time.In(time.FixedZone("display", 3600))
	q, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil || !bytes.Equal(p.canonical, q.canonical) {
		t.Fatal("display zone affected instant")
	}
	input := featureRegistryInput()
	registry, err := NewContributorRegistry([]Contributor{input})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry, keys: claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}}
	prepared, err := c.PrepareCommandPlan(s.Binding, featureCodecCommand(t, s), CommandPlan{})
	if err == nil || prepared.Digest != ([32]byte{}) {
		t.Fatal("codec enabled execution admission")
	}
}

func TestFeatureScalarLiteralEncodingAndDistinctKinds(t *testing.T) {
	for _, tt := range []struct {
		v    identity.FeatureValue
		want []byte
	}{
		{identity.FeatureValue{Kind: identity.FeatureText, Text: "é"}, []byte{0x62, 0xc3, 0xa9}},
		{identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{0, 255}}, []byte{0x42, 0, 255}},
		{identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: math.MaxUint64}, []byte{0x1b, 255, 255, 255, 255, 255, 255, 255, 255}},
		{identity.FeatureValue{Kind: identity.FeatureInt64, Int64: math.MinInt64}, []byte{0x3b, 0x7f, 255, 255, 255, 255, 255, 255, 255}},
		{identity.FeatureValue{Kind: identity.FeatureBool}, []byte{0xf4}},
		{identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}, []byte{0xf5}},
		{identity.FeatureValue{Kind: identity.FeatureTime, Time: time.Unix(-1, 999999000)}, []byte{0x20}},
	} {
		got, err := encodeFeatureValue(tt.v)
		if err != nil || !bytes.Equal(got, tt.want) {
			t.Fatal("literal scalar encoding", tt.v.Kind)
		}
	}
	for _, v := range []identity.FeatureValue{{}, {Kind: identity.FeatureTime}, {Kind: identity.FeatureTime, Time: time.Unix(1, 1)}} {
		if _, err := encodeFeatureValue(v); err == nil {
			t.Fatal("invalid scalar encoded")
		}
	}
	s := featureCodecSpec()
	var unsigned []byte
	for _, v := range []identity.FeatureValue{{Kind: identity.FeatureUint64}, {Kind: identity.FeatureInt64}} {
		s.Fields = []identity.FeatureField{{Name: "same", Value: v}}
		p, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if unsigned != nil && bytes.Equal(unsigned, p.canonical) {
			t.Fatal("equal integer bytes erased explicit kind")
		}
		unsigned = p.canonical
	}
	for _, kind := range []identity.FeatureKind{identity.FeatureText, identity.FeatureBytes} {
		v := identity.FeatureValue{Kind: kind}
		if kind == identity.FeatureText {
			v.Text = string(bytes.Repeat([]byte{'x'}, 8192))
		} else {
			v.Bytes = bytes.Repeat([]byte{1}, 8192)
		}
		s.Fields = []identity.FeatureField{{Name: "maximum", Value: v}}
		if _, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1}); err != nil {
			t.Fatal("maximum scalar rejected", err)
		}
	}
}

func FuzzFeatureCommandCodec(f *testing.F) {
	f.Add("synthetic", uint64(math.MaxUint64), int64(math.MinInt64))
	f.Add("", uint64(0), int64(0))
	f.Fuzz(func(t *testing.T, text string, u uint64, n int64) {
		if len(text) > 8192 {
			return
		}
		s := featureCodecSpec()
		s.Fields = []identity.FeatureField{{Name: "text", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: text}}, {Name: "unsigned", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: u}}, {Name: "signed", Value: identity.FeatureValue{Kind: identity.FeatureInt64, Int64: n}}}
		c, err := identity.NewFeatureCommand(s)
		if err != nil {
			return
		}
		p, err := prepareClaim(c, [32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		s.Fields[0], s.Fields[2] = s.Fields[2], s.Fields[0]
		q, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
		if err != nil || !bytes.Equal(p.canonical, q.canonical) || len(p.canonical) > 1<<20 {
			t.Fatal("bounded canonical intent changed")
		}
	})
}
