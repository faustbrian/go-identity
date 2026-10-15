package identity

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
)

func attributeField(name string, kind AttributeKind) FieldPolicy {
	return FieldPolicy{Name: name, Kind: kind, Cardinality: CardinalityScalar,
		Normalization: NormalizeNone, InputPermission: FieldWrite,
		OutputPermission: FieldRead, WriteAuthorization: FieldWriteSelf,
		Sensitivity: SensitivityPersonal, MigrationVersion: 1}
}

func attributeFixture(t *testing.T, fields ...FieldPolicy) (*AttributeProcessor, AttributePrepareRequest) {
	t.Helper()
	f := newQueryFixture(t)
	p, err := NewAttributeProcessor(AttributeSchema{ID: "profile", Version: 1, Fields: fields}, f.service.authorize,
		func(ctx context.Context, policy NormalizationPolicy, value AttributeScalar) (AttributeScalar, error) {
			return value, nil
		},
		AttributeProcessorConfig{Clock: queryClock{}, MaximumDuration: time.Second, PolicyVersion: 1,
			ValidateCanonicalUserID: func(context.Context, UserID) error { return nil },
			ValidateValue:           func(context.Context, FieldPolicy, AttributeValue) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	r := AttributePrepareRequest{TenantID: "tenant-a", UserID: "actor-a", SchemaVersion: 1, Context: f.request.Context}
	r.Context.Request.Action = "identity.profile.update"
	r.Context.Request.Resource.ID = "actor-a"
	return p, r
}

func TestAttributesPreserveLosslessZeroValuesAndCallerOwnership(t *testing.T) {
	fields := []FieldPolicy{attributeField("counter", AttributeInt64), attributeField("enabled", AttributeBool), attributeField("label", AttributeString), attributeField("tags", AttributeStringList)}
	fields[3].Cardinality = CardinalityList
	p, r := attributeFixture(t, fields...)
	r.Updates = []AttributeUpdate{
		{Name: "counter", Value: AttributeValue{Kind: AttributeInt64, Scalar: AttributeScalar{Kind: AttributeInt64, Int64: math.MaxInt64}}},
		{Name: "enabled", Value: AttributeValue{Kind: AttributeBool, Scalar: AttributeScalar{Kind: AttributeBool}}},
		{Name: "label", Value: AttributeValue{Kind: AttributeString, Scalar: AttributeScalar{Kind: AttributeString}}},
		{Name: "tags", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "one"}}}},
	}
	got, err := p.Prepare(context.Background(), r)
	if err != nil || len(got) != 4 || got[0].Value.Scalar.Int64 != math.MaxInt64 || got[1].Value.Scalar.Bool || got[2].Value.Scalar.String != "" || got[3].Value.List[0].String != "one" {
		t.Fatalf("prepared attributes = %+v, %v", got, err)
	}
	got[3].Value.List[0].String = "changed"
	if r.Updates[3].Value.List[0].String != "one" {
		t.Fatal("prepared values alias caller data")
	}
}

func attributeString(value string) AttributeValue {
	return AttributeValue{Kind: AttributeString, Scalar: AttributeScalar{Kind: AttributeString, String: value}}
}

func TestAttributesDefaultsOnlyOnCreateAndConfigurationIsCopied(t *testing.T) {
	field := attributeField("tags", AttributeStringList)
	field.Cardinality = CardinalityList
	field.Default = AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "default"}}}
	p, req := attributeFixture(t, field)
	field.Default.List[0].String = "mutated"
	got, err := p.Prepare(context.Background(), req)
	if err != nil || len(got) != 0 {
		t.Fatalf("update filled a default: %+v, %v", got, err)
	}
	req.Context.Request.Action = "identity.user.create"
	got, err = p.Prepare(context.Background(), req)
	if err != nil || len(got) != 1 || got[0].Value.List[0].String != "default" {
		t.Fatalf("create defaults: %+v, %v", got, err)
	}
	got[0].Value.List[0].String = "result mutation"
	got, err = p.Prepare(context.Background(), req)
	if err != nil || got[0].Value.List[0].String != "default" {
		t.Fatal("returned defaults mutate processor state")
	}
	req.Updates = []AttributeUpdate{{Name: "tags", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{}}}}
	got, err = p.Prepare(context.Background(), req)
	if err != nil || len(got[0].Value.List) != 0 || got[0].Value.List == nil {
		t.Fatal("explicit empty list was treated as absence")
	}
}

func TestAttributesRejectUnknownDuplicateStaleAndMalformedValues(t *testing.T) {
	p, req := attributeFixture(t, attributeField("name", AttributeString))
	for name, modify := range map[string]func(*AttributePrepareRequest){
		"unknown":        func(r *AttributePrepareRequest) { r.Updates[0].Name = "undeclared" },
		"duplicate":      func(r *AttributePrepareRequest) { r.Updates = append(r.Updates, r.Updates[0]) },
		"version":        func(r *AttributePrepareRequest) { r.SchemaVersion++ },
		"oversized":      func(r *AttributePrepareRequest) { r.Updates[0].Value.Scalar.String = strings.Repeat("a", 4097) },
		"invalid utf8":   func(r *AttributePrepareRequest) { r.Updates[0].Value.Scalar.String = "\xff" },
		"mixed arms":     func(r *AttributePrepareRequest) { r.Updates[0].Value.Scalar.Bool = true },
		"absent":         func(r *AttributePrepareRequest) { r.Updates[0].Value = AttributeValue{} },
		"kind":           func(r *AttributePrepareRequest) { r.Updates[0].Value.Kind = AttributeBool },
		"list on scalar": func(r *AttributePrepareRequest) { r.Updates[0].Value.List = []AttributeScalar{} },
		"tenant":         func(r *AttributePrepareRequest) { r.TenantID = "another" },
		"target":         func(r *AttributePrepareRequest) { r.UserID = "another" },
		"action":         func(r *AttributePrepareRequest) { r.Context.Request.Action = "identity.user.delete" },
		"count":          func(r *AttributePrepareRequest) { r.Updates = make([]AttributeUpdate, 129) },
	} {
		t.Run(name, func(t *testing.T) {
			r := req
			r.Context = req.Context.Clone()
			r.Updates = []AttributeUpdate{{Name: "name", Value: attributeString("valid")}}
			modify(&r)
			got, err := p.Prepare(context.Background(), r)
			if got != nil || err == nil || strings.Contains(err.Error(), "valid") && err.Error() != "identity: invalid input" {
				t.Fatalf("malformed admitted: %+v %v", got, err)
			}
		})
	}
}

func TestAttributesSchemaRejectsContradictions(t *testing.T) {
	base := attributeField("field", AttributeString)
	for name, change := range map[string]func(*FieldPolicy){
		"name":                  func(f *FieldPolicy) { f.Name = "bad field" },
		"reserved":              func(f *FieldPolicy) { f.Name = "status" },
		"non ascii":             func(f *FieldPolicy) { f.Name = "é" },
		"zero kind":             func(f *FieldPolicy) { f.Kind = "" },
		"cardinality":           func(f *FieldPolicy) { f.Cardinality = CardinalityList },
		"normalization":         func(f *FieldPolicy) { f.Normalization = "unknown" },
		"nontext normalization": func(f *FieldPolicy) { f.Kind = AttributeBool; f.Normalization = NormalizeEmail },
		"input":                 func(f *FieldPolicy) { f.InputPermission = "" },
		"output":                func(f *FieldPolicy) { f.OutputPermission = "" },
		"write":                 func(f *FieldPolicy) { f.WriteAuthorization = "" },
		"sensitivity":           func(f *FieldPolicy) { f.Sensitivity = "" },
		"secret readable":       func(f *FieldPolicy) { f.Sensitivity = SensitivitySecret },
		"secret index": func(f *FieldPolicy) {
			f.Sensitivity = SensitivitySecret
			f.OutputPermission = FieldDenied
			f.Indexed = true
		},
		"migration": func(f *FieldPolicy) { f.MigrationVersion = 2 },
		"default kind": func(f *FieldPolicy) {
			f.Default = AttributeValue{Kind: AttributeBool, Scalar: AttributeScalar{Kind: AttributeBool}}
		},
		"absent default with arm": func(f *FieldPolicy) { f.Default.Scalar.String = "private" },
	} {
		t.Run(name, func(t *testing.T) {
			f := base
			change(&f)
			if (AttributeSchema{ID: "schema", Version: 1, Fields: []FieldPolicy{f}}).Validate() == nil {
				t.Fatal("invalid schema accepted")
			}
		})
	}
	for _, schema := range []AttributeSchema{{}, {ID: "schema", Version: 1}, {ID: "schema", Version: 1, Fields: []FieldPolicy{base, base}}, {ID: "schema", Version: 1, Fields: make([]FieldPolicy, 129)}} {
		if schema.Validate() == nil {
			t.Fatal("invalid schema accepted")
		}
	}
	secret := base
	secret.Sensitivity = SensitivitySecret
	secret.OutputPermission = FieldDenied
	if (AttributeSchema{ID: "schema", Version: 1, Fields: []FieldPolicy{secret}}).Validate() != nil {
		t.Fatal("non-indexed unreadable secret metadata rejected")
	}
}

type attributeDecisionFunc func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

type attributeClockFunc func() time.Time

func (f attributeClockFunc) Now() time.Time { return f() }

func (f attributeDecisionFunc) Decide(ctx context.Context, in authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, in)
}

func TestAttributesUseRealPolicyForEveryFieldAndReplaceReservedMetadata(t *testing.T) {
	a := attributeField("admin", AttributeString)
	a.WriteAuthorization = FieldWriteAdministrator
	b := attributeField("system", AttributeString)
	b.WriteAuthorization = FieldWriteSystem
	p, r := attributeFixture(t, a, b)
	r.Updates = []AttributeUpdate{{Name: "admin", Value: attributeString("private-value")}, {Name: "system", Value: attributeString("private-value")}}
	r.Context.Request.Resource.Attributes = authorization.Attributes{"identity.field": authorization.StringValue("spoof"), "identity.field.write_class": authorization.StringValue("self"), "identity.fields.first": authorization.StringSetValue([]string{"spoof"}), "identity.schema.version": authorization.IntValue(99)}
	original := r.Context.Clone()
	seen := []string{}
	p.authorize = attributeDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded policy")
		}
		if !dc.Request.Environment.Time.Equal((queryClock{}).Now()) {
			t.Fatal("untrusted policy time")
		}
		if v, _ := dc.Request.Resource.Attributes["identity.schema.version"].Int(); v != 1 {
			t.Fatal("spoofed schema metadata")
		}
		field, _ := dc.Request.Resource.Attributes["identity.field"].String()
		seen = append(seen, field)
		if field == "" {
			if _, exists := dc.Request.Resource.Attributes["identity.field.write_class"]; exists {
				t.Fatal("forged field class retained at operation admission")
			}
		} else {
			class, _ := dc.Request.Resource.Attributes["identity.field.write_class"].String()
			if field == "admin" && class != "administrator" || field == "system" && class != "system" {
				t.Fatal("wrong field write class")
			}
		}
		for _, v := range dc.Request.Resource.Attributes {
			if text, ok := v.String(); ok && text == "private-value" {
				t.Fatal("policy context discloses field content")
			}
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	got, err := p.Prepare(context.Background(), r)
	if err != nil || len(got) != 2 || !reflect.DeepEqual(seen, []string{"", "admin", "system"}) || !reflect.DeepEqual(original, r.Context) {
		t.Fatalf("field policy: %+v %v %v", got, err, seen)
	}
	p.authorize = attributeDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		field, _ := dc.Request.Resource.Attributes["identity.field"].String()
		if field == "system" {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("administrator/system class granted authority without policy")
	}
}

func TestAttributesInputAndSelfPermissionsNeverGrantAuthority(t *testing.T) {
	for _, permission := range []FieldPermission{FieldDenied, FieldRead} {
		f := attributeField("name", AttributeString)
		f.InputPermission = permission
		p, r := attributeFixture(t, f)
		r.Updates = []AttributeUpdate{{Name: "name", Value: attributeString("x")}}
		if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
			t.Fatal("non-writable input admitted")
		}
	}
	p, r := attributeFixture(t, attributeField("name", AttributeString))
	r.Updates = []AttributeUpdate{{Name: "name", Value: attributeString("x")}}
	r.Context.Request.Subject.ID = "different-user"
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("self field written by a different user")
	}
	r.Context.Request.Subject.ID = authorization.SubjectID(r.UserID)
	r.Context.Request.Subject.Kind = authorization.SubjectAPIKey
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("API key identifier impersonates self")
	}
}

func TestAttributesNormalizationBoundsCancellationAndRedaction(t *testing.T) {
	f := attributeField("name", AttributeString)
	f.Normalization = NormalizeCaseFold
	p, r := attributeFixture(t, f)
	r.Updates = []AttributeUpdate{{Name: "name", Value: attributeString("SOURCE")}}
	p.normalize = func(ctx context.Context, policy NormalizationPolicy, s AttributeScalar) (AttributeScalar, error) {
		if policy != NormalizeCaseFold || s.String != "SOURCE" {
			t.Fatal("normalization binding")
		}
		s.String = "canonical"
		return s, nil
	}
	got, err := p.Prepare(context.Background(), r)
	if err != nil || got[0].Value.Scalar.String != "canonical" || r.Updates[0].Value.Scalar.String != "SOURCE" {
		t.Fatal("normalization/ownership failure")
	}
	for _, normalize := range []NormalizeAttributeFunc{
		func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
			return AttributeScalar{Kind: AttributeString, String: strings.Repeat("s", 4097)}, nil
		},
		func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
			return AttributeScalar{Kind: AttributeBool}, nil
		},
		func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
			return AttributeScalar{}, errors.New("sensitive source")
		},
		func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
			panic("sensitive source")
		},
	} {
		p.normalize = normalize
		got, err := p.Prepare(context.Background(), r)
		if got != nil || err == nil || strings.Contains(err.Error(), "source") {
			t.Fatal("invalid normalization result escaped")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.normalize = func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
		cancel()
		return AttributeScalar{Kind: AttributeString, String: "safe"}, nil
	}
	got, err = p.Prepare(ctx, r)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled normalization disclosed output")
	}
}

func TestAttributesRejectAggregateBudgetBeforeCallbacks(t *testing.T) {
	fields := []FieldPolicy{attributeField("a", AttributeStringList), attributeField("b", AttributeString)}
	fields[0].Cardinality = CardinalityList
	p, r := attributeFixture(t, fields...)
	list := make([]AttributeScalar, 64)
	for i := range list {
		list[i] = AttributeScalar{Kind: AttributeString, String: strings.Repeat("a", 4096)}
	}
	r.Updates = []AttributeUpdate{{Name: "a", Value: AttributeValue{Kind: AttributeStringList, List: list}}, {Name: "b", Value: attributeString("b")}}
	p.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		t.Fatal("oversize request reached policy")
		return authorization.Decision{}, nil
	})
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("unbounded aggregate admitted")
	}
	fields[0].Default = r.Updates[0].Value
	fields[1].Default = attributeString("b")
	if (AttributeSchema{ID: "schema", Version: 1, Fields: fields}).Validate() == nil {
		t.Fatal("oversize defaults admitted")
	}
}

func TestAttributesPrepareConcurrentCallerOwnedLists(t *testing.T) {
	f := attributeField("tags", AttributeStringList)
	f.Cardinality = CardinalityList
	p, r := attributeFixture(t, f)
	r.Updates = []AttributeUpdate{{Name: "tags", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "unchanged"}}}}}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				got, err := p.Prepare(context.Background(), r)
				if err != nil || got[0].Value.List[0].String != "unchanged" {
					t.Error("concurrent value corruption")
					return
				}
				got[0].Value.List[0].String = "private"
			}
		}()
	}
	group.Wait()
	if r.Updates[0].Value.List[0].String != "unchanged" {
		t.Fatal("concurrent result aliases input")
	}
}

func TestAttributesAllScalarArmsAndListBounds(t *testing.T) {
	for _, v := range []AttributeValue{
		attributeString(""),
		{Kind: AttributeBool, Scalar: AttributeScalar{Kind: AttributeBool, Bool: true}},
		{Kind: AttributeInt64, Scalar: AttributeScalar{Kind: AttributeInt64, Int64: math.MinInt64}},
		{Kind: AttributeTime, Scalar: AttributeScalar{Kind: AttributeTime, Time: time.Date(2026, 1, 1, 12, 0, 0, 0, time.FixedZone("offset", 3600))}},
		{Kind: AttributeStringList, List: []AttributeScalar{}},
	} {
		f := attributeField("value", v.Kind)
		f.Cardinality = cardinalityFor(v.Kind)
		p, r := attributeFixture(t, f)
		r.Updates = []AttributeUpdate{{Name: "value", Value: v}}
		got, err := p.Prepare(context.Background(), r)
		if err != nil || len(got) != 1 {
			t.Fatalf("valid arm rejected: %v", err)
		}
		if v.Kind == AttributeTime && (got[0].Value.Scalar.Time.Location() != time.UTC || !got[0].Value.Scalar.Time.Equal(v.Scalar.Time)) {
			t.Fatal("time not preserved in UTC")
		}
	}
	for _, v := range []AttributeValue{
		{Kind: AttributeBool, Scalar: AttributeScalar{Kind: AttributeBool, String: "inactive"}},
		{Kind: AttributeInt64, Scalar: AttributeScalar{Kind: AttributeInt64, Bool: true}},
		{Kind: AttributeTime, Scalar: AttributeScalar{Kind: AttributeTime}},
		{Kind: AttributeTime, Scalar: AttributeScalar{Kind: AttributeTime, String: "inactive", Time: time.Now()}},
		{Kind: AttributeStringList},
		{Kind: AttributeStringList, List: make([]AttributeScalar, 65)},
		{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeBool}}},
		{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString}}, Scalar: AttributeScalar{Kind: AttributeString}},
	} {
		f := attributeField("value", v.Kind)
		f.Cardinality = cardinalityFor(v.Kind)
		p, r := attributeFixture(t, f)
		r.Updates = []AttributeUpdate{{Name: "value", Value: v}}
		if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
			t.Fatal("malformed arm admitted")
		}
	}
}

func TestAttributesFailClosedDependencyAndConfiguration(t *testing.T) {
	p, r := attributeFixture(t, attributeField("value", AttributeString))
	r.Updates = []AttributeUpdate{{Name: "value", Value: attributeString("secret")}}
	for _, outcome := range []authorization.Outcome{authorization.Deny, authorization.NotApplicable} {
		p.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: outcome, Revision: 1}, nil
		})
		if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
			t.Fatal("deny/default allowed")
		}
	}
	for _, decide := range []attributeDecisionFunc{
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{}, errors.New("secret")
		},
		func(context.Context, authorization.DecisionContext) (authorization.Decision, error) { panic("secret") },
	} {
		p.authorize = decide
		got, err := p.Prepare(context.Background(), r)
		if got != nil || err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("dependency failure leaked")
		}
	}
	p, _ = attributeFixture(t, attributeField("value", AttributeString))
	p.config.ValidateCanonicalUserID = func(context.Context, UserID) error { return errors.New("secret") }
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("canonicalizer failure leaked")
	}
	p, _ = attributeFixture(t, attributeField("value", AttributeString))
	p.config.Clock = attributeClockFunc(func() time.Time { return time.Time{} })
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("zero clock admitted")
	}
	if got, err := p.Prepare(nil, r); got != nil || err == nil {
		t.Fatal("nil context admitted")
	}
	var zero *AttributeProcessor
	if got, err := zero.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("nil processor admitted")
	}
	p, _ = attributeFixture(t, attributeField("value", AttributeString))
	for _, change := range []func(*AttributeProcessorConfig){func(c *AttributeProcessorConfig) { c.Clock = nil }, func(c *AttributeProcessorConfig) { c.PolicyVersion = 0 }, func(c *AttributeProcessorConfig) { c.MaximumDuration = 0 }, func(c *AttributeProcessorConfig) { c.MaximumDuration = time.Minute + 1 }, func(c *AttributeProcessorConfig) { c.ValidateCanonicalUserID = nil }} {
		config := p.config
		change(&config)
		if got, err := NewAttributeProcessor(p.schema, p.authorize, p.normalize, config); got != nil || err == nil {
			t.Fatal("bad configuration admitted")
		}
	}
	if got, err := NewAttributeProcessor(p.schema, nil, p.normalize, p.config); got != nil || err == nil {
		t.Fatal("nil policy admitted")
	}
	if got, err := NewAttributeProcessor(p.schema, p.authorize, nil, p.config); got != nil || err == nil {
		t.Fatal("nil normalizer admitted")
	}
}

func TestAttributesNormalizationListsAndTotalExpansion(t *testing.T) {
	f := attributeField("list", AttributeStringList)
	f.Cardinality = CardinalityList
	f.Normalization = NormalizeUnicodeNFC
	p, r := attributeFixture(t, f, attributeField("other", AttributeString))
	list := make([]AttributeScalar, 64)
	for i := range list {
		list[i] = AttributeScalar{Kind: AttributeString, String: "small"}
	}
	r.Updates = []AttributeUpdate{{Name: "list", Value: AttributeValue{Kind: AttributeStringList, List: list}}, {Name: "other", Value: attributeString("x")}}
	p.normalize = func(ctx context.Context, policy NormalizationPolicy, s AttributeScalar) (AttributeScalar, error) {
		s.String = strings.Repeat("b", 4096)
		return s, nil
	}
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("aggregate normalization expansion admitted")
	}
	if r.Updates[0].Value.List[0].String != "small" {
		t.Fatal("failed normalization changed input")
	}
	p.normalize = func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
		return AttributeScalar{}, errors.New("private")
	}
	if got, err := p.Prepare(context.Background(), r); got != nil || err == nil {
		t.Fatal("failed list normalization admitted")
	}
	p.normalize = func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
		return AttributeScalar{Kind: AttributeString, String: "normalized"}, nil
	}
	got, err := p.Prepare(context.Background(), r)
	if err != nil || got[0].Value.List[63].String != "normalized" {
		t.Fatal("list normalization not applied to every element")
	}
}

func TestAttributesCancellationAtEveryDependency(t *testing.T) {
	for _, boundary := range []string{"before", "canonical", "authorize", "list-normalize"} {
		t.Run(boundary, func(t *testing.T) {
			f := attributeField("list", AttributeStringList)
			f.Cardinality = CardinalityList
			f.Normalization = NormalizeEmail
			p, r := attributeFixture(t, f)
			r.Updates = []AttributeUpdate{{Name: "list", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "private"}}}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch boundary {
			case "before":
				cancel()
			case "canonical":
				p.config.ValidateCanonicalUserID = func(context.Context, UserID) error { cancel(); return nil }
			case "authorize":
				p.authorize = attributeDecisionFunc(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
					cancel()
					return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
				})
			case "list-normalize":
				p.normalize = func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
					cancel()
					return AttributeScalar{Kind: AttributeString, String: "private"}, nil
				}
			}
			got, err := p.Prepare(ctx, r)
			if got != nil || !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled dependency returned values")
			}
		})
	}
}

func FuzzAttributeScalarAdmission(f *testing.F) {
	for _, seed := range []string{"", "a", "\xff", strings.Repeat("a", 4096), strings.Repeat("a", 4097)} {
		f.Add(seed, false, int64(0))
	}
	f.Fuzz(func(t *testing.T, text string, otherArm bool, integer int64) {
		if len(text) > 8192 {
			t.Skip()
		}
		p, r := attributeFixture(t, attributeField("value", AttributeString))
		r.Updates = []AttributeUpdate{{Name: "value", Value: AttributeValue{Kind: AttributeString, Scalar: AttributeScalar{Kind: AttributeString, String: text, Bool: otherArm, Int64: integer}}}}
		got, err := p.Prepare(context.Background(), r)
		valid := len(text) <= 4096 && utf8.ValidString(text) && !otherArm && integer == 0
		if valid {
			if err != nil || len(got) != 1 || got[0].Value.Scalar.String != text {
				t.Fatal("valid string not preserved")
			}
		} else if got != nil || err == nil {
			t.Fatal("invalid tagged string admitted")
		}
	})
}

func TestAttributesCustomValidationSeesNormalizedValuesAndCannotMutateThem(t *testing.T) {
	f := attributeField("tags", AttributeStringList)
	f.Cardinality = CardinalityList
	f.Normalization = NormalizeCaseFold
	p, r := attributeFixture(t, f)
	r.Updates = []AttributeUpdate{{Name: "tags", Value: AttributeValue{Kind: AttributeStringList, List: []AttributeScalar{{Kind: AttributeString, String: "RAW"}}}}}
	p.normalize = func(context.Context, NormalizationPolicy, AttributeScalar) (AttributeScalar, error) {
		return AttributeScalar{Kind: AttributeString, String: "normalized"}, nil
	}
	p.config.ValidateValue = func(ctx context.Context, field FieldPolicy, value AttributeValue) error {
		if _, ok := ctx.Deadline(); !ok || field.Name != "tags" || value.List[0].String != "normalized" {
			t.Fatal("custom validation received wrong boundary")
		}
		value.List[0].String = "attempted mutation"
		return nil
	}
	got, err := p.Prepare(context.Background(), r)
	if err != nil || got[0].Value.List[0].String != "normalized" {
		t.Fatal("validator rewrote prepared values")
	}
	p.config.ValidateValue = func(context.Context, FieldPolicy, AttributeValue) error {
		return errors.New("sensitive validation detail")
	}
	got, err = p.Prepare(context.Background(), r)
	if got != nil || err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("invalid custom field disclosed")
	}
}
