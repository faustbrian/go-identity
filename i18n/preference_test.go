package i18n

import (
	"context"
	"errors"
	identity "github.com/faustbrian/go-identity"
	"math"
	"testing"
	"time"
)

type preferenceStoreFixture struct {
	get func(context.Context, PreferenceKey) (Preference, error)
	set func(context.Context, PreferenceCommand) (Preference, error)
}

func (s preferenceStoreFixture) GetPreference(ctx context.Context, key PreferenceKey) (Preference, error) {
	return s.get(ctx, key)
}
func (s preferenceStoreFixture) SetPreference(ctx context.Context, cmd PreferenceCommand) (Preference, error) {
	return s.set(ctx, cmd)
}
func preferenceCommandFixture(t *testing.T) PreferenceCommand {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return PreferenceCommand{Key: PreferenceKey{TenantID: "tenant", SubjectID: "subject"}, Locale: "fi", ConsentNoticeVersion: 1, CommandID: id}
}
func preferenceResult(cmd PreferenceCommand) Preference {
	return Preference{TenantID: cmd.Key.TenantID, SubjectID: cmd.Key.SubjectID, Locale: cmd.Locale, Version: cmd.ExpectedVersion + 1, ConsentNoticeVersion: cmd.ConsentNoticeVersion}
}

func TestPreferencePolicyRejectsUnsupportedAndInvalidCommandsBeforeWrites(t *testing.T) {
	writes := 0
	store := preferenceStoreFixture{set: func(ctx context.Context, cmd PreferenceCommand) (Preference, error) {
		writes++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
			t.Error("unbounded context")
		}
		return preferenceResult(cmd), nil
	}}
	supported := []Locale{"en", "fi"}
	policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: store, Supported: supported, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	supported[0] = "de"
	cmd := preferenceCommandFixture(t)
	for _, mutate := range []func(*PreferenceCommand){
		func(c *PreferenceCommand) { c.Locale = "de" }, func(c *PreferenceCommand) { c.Locale = "FI" },
		func(c *PreferenceCommand) { c.Key.TenantID = "" }, func(c *PreferenceCommand) { c.Key.SubjectID = "bad subject" },
		func(c *PreferenceCommand) { c.CommandID = "" }, func(c *PreferenceCommand) { c.ConsentNoticeVersion = 0 },
		func(c *PreferenceCommand) { c.ExpectedVersion = math.MaxUint64 },
	} {
		bad := cmd
		mutate(&bad)
		if result, err := policy.SetPreference(context.Background(), bad); err == nil || result.Version != 0 {
			t.Fatal("invalid preference accepted")
		}
	}
	if writes != 0 {
		t.Fatal("validation performed writes")
	}
	result, err := policy.SetPreference(context.Background(), cmd)
	if err != nil || result != preferenceResult(cmd) || writes != 1 {
		t.Fatal("validated mutation changed binding", err)
	}
}

func TestPreferencePolicyRejectsWrongProjectionAndPreservesUnknownOutcome(t *testing.T) {
	cmd := preferenceCommandFixture(t)
	for _, mutate := range []func(*Preference){
		func(p *Preference) { p.TenantID = "other" }, func(p *Preference) { p.SubjectID = "other" },
		func(p *Preference) { p.Locale = "en" }, func(p *Preference) { p.Version = 3 }, func(p *Preference) { p.ConsentNoticeVersion = 2 },
	} {
		store := preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) {
			p := preferenceResult(cmd)
			mutate(&p)
			return p, nil
		}}
		policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: store, Supported: []Locale{"en", "fi"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		result, err := policy.SetPreference(context.Background(), cmd)
		var unknown PreferenceOutcomeUnknownError
		if result.Version != 0 || !errors.As(err, &unknown) || unknown.CommandID != cmd.CommandID {
			t.Fatal("invalid write result claimed committed/rolled back")
		}
	}
	for _, store := range []PreferenceStore{
		preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) { panic("private diagnostic") }},
		preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) {
			return Preference{}, errors.New("private diagnostic")
		}},
	} {
		policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: store, Supported: []Locale{"fi"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_, err = policy.SetPreference(context.Background(), cmd)
		var unknown PreferenceOutcomeUnknownError
		if !errors.As(err, &unknown) || unknown.CommandID != cmd.CommandID {
			t.Fatal("callback failure lost unknown outcome")
		}
	}
}

func TestPreferenceReadsDoNotPersistFallbackOrCrossTenantData(t *testing.T) {
	key := PreferenceKey{TenantID: "tenant", SubjectID: "subject"}
	store := preferenceStoreFixture{get: func(context.Context, PreferenceKey) (Preference, error) {
		return Preference{}, PreferenceNotFoundError{}
	}, set: func(context.Context, PreferenceCommand) (Preference, error) {
		t.Fatal("read persisted fallback")
		return Preference{}, nil
	}}
	policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: store, Supported: []Locale{"en"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.GetPreference(context.Background(), key); err == nil {
		t.Fatal("missing preference became fallback")
	}
	store.get = func(context.Context, PreferenceKey) (Preference, error) {
		return Preference{TenantID: "other", SubjectID: "subject", Locale: "en", Version: 1, ConsentNoticeVersion: 1}, nil
	}
	policy, err = NewPreferencePolicy(PreferencePolicyConfig{Store: store, Supported: []Locale{"en"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := policy.GetPreference(context.Background(), key); err == nil || result.Version != 0 {
		t.Fatal("cross-tenant result exposed")
	}
}

func TestCanonicalConstructorsAndFallbackChain(t *testing.T) {
	messages := []Message{{ID: "other", Template: "Other"}}
	en, err := NewCatalog("en", messages)
	if err != nil {
		t.Fatal(err)
	}
	messages[0].Template = "changed"
	fi, err := NewCatalog("fi", []Message{{ID: "denied", Template: "Estetty"}})
	if err != nil {
		t.Fatal(err)
	}
	if en.Version != 1 || en.Messages[0].Template != "Other" {
		t.Fatal("catalog constructor did not freeze input")
	}
	registry := NewErrorRegistry()
	if err := registry.Register("id", "denied", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	if resolver, err := NewResolver([]Catalog{en, fi}, []string{"en", "fi"}, registry, nil); err == nil || resolver != nil {
		t.Fatal("nil preferences accepted")
	}
	if err := registry.Register("other", "other", ParameterSchema{}); err != nil {
		t.Fatal("failed constructor sealed registry")
	}
	store := preferenceStoreFixture{get: func(context.Context, PreferenceKey) (Preference, error) {
		return Preference{}, PreferenceNotFoundError{}
	}, set: func(context.Context, PreferenceCommand) (Preference, error) {
		t.Fatal("resolution persisted fallback")
		return Preference{}, nil
	}}
	resolver, err := NewResolver([]Catalog{en, fi}, []string{"en", "fi"}, registry, store)
	if err != nil {
		t.Fatal(err)
	}
	fallbacks := []ResolveInput{{Default: "en", Error: &registryError{identity: "id"}}, {Default: "en", AcceptLanguage: "en", Error: &registryError{identity: "id"}}}
	for _, input := range fallbacks {
		result, err := resolver.Resolve(context.Background(), input)
		if err != nil || result.Locale != "fi" || result.Message != "Estetty" {
			t.Fatal("configured fallback translation not selected", err)
		}
	}
	if _, err := resolver.Resolve(context.Background(), ResolveInput{Default: "en", AcceptLanguage: "*;q=0", Error: &registryError{identity: "id"}}); err == nil {
		t.Fatal("fallback ignored exclusion")
	}
	policy, ok := resolver.(PreferenceResolver)
	if !ok {
		t.Fatal("constructor discarded preference service")
	}
	if _, err := policy.GetPreference(context.Background(), PreferenceKey{TenantID: "tenant", SubjectID: "subject"}); err == nil {
		t.Fatal("preference facade changed absence")
	}
}

func TestPreferenceCancellationAndExplicitNoWriteOutcomes(t *testing.T) {
	cmd := preferenceCommandFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	invoked := false
	policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) {
		invoked = true
		return preferenceResult(cmd), nil
	}}, Supported: []Locale{"fi"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.SetPreference(ctx, cmd); !errors.Is(err, context.Canceled) || invoked {
		t.Fatal("pre-invocation cancellation performed mutation")
	}
	for _, committed := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) {
			cancel()
			if committed {
				return preferenceResult(cmd), nil
			}
			return Preference{}, context.Canceled
		}}, Supported: []Locale{"fi"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		result, err := policy.SetPreference(ctx, cmd)
		if committed {
			if err != nil || result.Version != 1 {
				t.Fatal("late cancellation discarded durable committed result")
			}
		} else {
			var unknown PreferenceOutcomeUnknownError
			if !errors.As(err, &unknown) || unknown.CommandID != cmd.CommandID || !errors.Is(err, context.Canceled) || result.Version != 0 {
				t.Fatal("late cancellation implied rollback")
			}
		}
	}
	policy, err = NewPreferencePolicy(PreferencePolicyConfig{Store: preferenceStoreFixture{set: func(context.Context, PreferenceCommand) (Preference, error) {
		return Preference{}, PreferenceConflictError{}
	}}, Supported: []Locale{"fi"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var conflict PreferenceConflictError
	if _, err := policy.SetPreference(context.Background(), cmd); !errors.As(err, &conflict) {
		t.Fatal("explicit no-write conflict lost")
	}
}

type nilPreferenceFixture struct{}

func (*nilPreferenceFixture) GetPreference(context.Context, PreferenceKey) (Preference, error) {
	panic("nil store must not be invoked")
}
func (*nilPreferenceFixture) SetPreference(context.Context, PreferenceCommand) (Preference, error) {
	panic("nil store must not be invoked")
}

func TestPreferenceAndFallbackConstructionBoundaries(t *testing.T) {
	var typedNil *nilPreferenceFixture
	if policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: typedNil, Supported: []Locale{"en"}, Timeout: time.Second}); err == nil || policy != nil {
		t.Fatal("typed nil store admitted")
	}
	store := preferenceStoreFixture{}
	for _, config := range []PreferencePolicyConfig{
		{Store: store, Supported: []Locale{"en"}, Timeout: 0},
		{Store: store, Supported: []Locale{"en"}, Timeout: 31 * time.Second},
		{Store: store, Supported: []Locale{"en", "en"}, Timeout: time.Second},
		{Store: store, Supported: []Locale{"EN"}, Timeout: time.Second},
	} {
		if policy, err := NewPreferencePolicy(config); err == nil || policy != nil {
			t.Fatal("invalid policy admitted")
		}
	}
	en, err := NewCatalog("en", []Message{{ID: "message", Template: "English"}})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewErrorRegistry()
	if err := registry.Register("id", "message", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	for _, chain := range [][]string{nil, make([]string, 17), {"en", "en"}, {"EN"}, {"fi"}} {
		if resolver, err := NewResolver([]Catalog{en}, chain, registry, store); err == nil || resolver != nil {
			t.Fatal("invalid fallback admitted")
		}
	}
	if err := registry.Register("other", "message", ParameterSchema{}); err != nil {
		t.Fatal("failed fallback construction sealed registry")
	}
	fi, err := NewCatalog("fi", []Message{{ID: "message", Template: "Finnish"}})
	if err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{en, fi})
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Fallbacks: []Locale{"en", "fi"}})
	if err != nil {
		t.Fatal(err)
	}
	changed := []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "other", Template: "Other"}}}, {Locale: "fi", Version: 2, Messages: []Message{{ID: "message", Template: "Finnish"}}}}
	if err := catalogs.Replace(1, changed); err == nil {
		t.Fatal("initial admitted fallback translation removed")
	}
	result, err := core.I18nResolve(context.Background(), I18nResolveRequest{Input: ResolveInput{Default: "en", Error: &registryError{identity: "id"}}})
	if err != nil || result.Localized.Locale != "en" || result.Localized.Message != "English" {
		t.Fatal("direct localization operation lost immutable default", err)
	}
}

func FuzzPreferenceMutation(f *testing.F) {
	f.Add("tenant", "subject", "fi", "AQEBAQEBAQEBAQEBAQEBAQ", uint64(0), uint64(1))
	f.Fuzz(func(t *testing.T, tenant, subject, locale, command string, version, notice uint64) {
		policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: preferenceStoreFixture{set: func(_ context.Context, cmd PreferenceCommand) (Preference, error) { return preferenceResult(cmd), nil }}, Supported: []Locale{"fi", "en"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		cmd := PreferenceCommand{Key: PreferenceKey{TenantID: identity.TenantID(tenant), SubjectID: identity.UserID(subject)}, Locale: locale, CommandID: identity.CommandID(command), ExpectedVersion: version, ConsentNoticeVersion: notice}
		result, err := policy.SetPreference(context.Background(), cmd)
		if err != nil {
			if result.Version != 0 {
				t.Fatal("invalid command returned partial projection")
			}
			return
		}
		if result.TenantID != cmd.Key.TenantID || result.SubjectID != cmd.Key.SubjectID || result.Locale != cmd.Locale || result.Version != version+1 || result.ConsentNoticeVersion != notice {
			t.Fatal("mutation changed authority binding")
		}
	})
}
