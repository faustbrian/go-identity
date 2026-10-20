package postgres

import (
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// This closed vocabulary freezes initiation in the existing command journal.
// It is deliberately not a JSON escape, cookie bearer or execution authority.
func preAuthIssueOperation() identity.FeatureOperation {
	return session.PreAuthIssueOperation()
}

func mapPreAuthIssue(b identity.CommandBinding, record session.PreAuthTransaction) (identity.Command, error) {
	s, err := record.Bindings()
	op := preAuthIssueOperation()
	if err != nil || b.ValidateFor(op) != nil || s.Version != 1 || b.TenantID != s.Binding.Intent.TenantID || b.AnonymousFlowID != string(s.Binding.ID) || b.RecordID != string(s.Binding.ID) || b.PolicyID != s.Binding.Intent.PolicyID || b.PolicyVersion != s.Binding.Intent.PolicyVersion {
		return identity.Command{}, session.ErrInvalidPreAuthTransaction
	}
	i := s.Binding.Intent
	remember, _ := i.Remember.Bindings()
	fields := make([]identity.FeatureField, 0, 20)
	add := func(name string, v identity.FeatureValue) {
		fields = append(fields, identity.FeatureField{Name: name, Value: v})
	}
	text := func(name, v string) { add(name, identity.FeatureValue{Kind: identity.FeatureText, Text: v}) }
	number := func(name string, v uint64) { add(name, identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}) }
	duration := func(name string, v time.Duration) {
		add(name, identity.FeatureValue{Kind: identity.FeatureInt64, Int64: int64(v)})
	}
	text("flow.id", string(s.Binding.ID))
	text("flow.tenant", string(i.TenantID))
	text("flow.policy", i.PolicyID)
	number("flow.policy.version", i.PolicyVersion)
	text("flow.action", i.Action)
	text("flow.origin", i.Origin)
	text("flow.callback", i.CallbackURL)
	add("flow.nonce", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.Nonce[:]})
	text("flow.issued", s.Binding.IssuedAt.UTC().Format(storedTimeLayout))
	text("flow.expires", s.Binding.ExpiresAt.UTC().Format(storedTimeLayout))
	number("flow.version", s.Version)
	number("cookie.version", uint64(s.Cookie.KeyVersion))
	add("cookie.digest", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: s.Cookie.Sum[:]})
	if i.Purpose == session.PreAuthSessionIssuance {
		number("remember.choice", uint64(remember.Choice))
		duration("remember.absolute", remember.AbsoluteTTL)
		duration("remember.idle", remember.IdleTTL)
		duration("remember.refresh", remember.RefreshAfter)
		duration("remember.fresh", remember.FreshFor)
	} else {
		number("flow.purpose", uint64(i.Purpose))
	}
	if i.IdentifierBinding != ([32]byte{}) {
		add("flow.identifier", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: i.IdentifierBinding[:]})
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
}

func nativePreAuthIssue(command identity.Command) (identity.CommandBinding, session.PreAuthTransaction, error) {
	bad := func() (identity.CommandBinding, session.PreAuthTransaction, error) {
		return identity.CommandBinding{}, session.PreAuthTransaction{}, session.ErrInvalidPreAuthTransaction
	}
	p, ok := command.Feature()
	if !ok || p.Operation != preAuthIssueOperation() {
		return bad()
	}
	values := make(map[string]identity.FeatureValue, len(p.Fields))
	for _, f := range p.Fields {
		values[f.Name] = f.Value
	}
	valid := true
	take := func(name string, kind identity.FeatureKind) identity.FeatureValue {
		v, ok := values[name]
		delete(values, name)
		if !ok || v.Kind != kind {
			valid = false
		}
		return v
	}
	text := func(name string) string { return take(name, identity.FeatureText).Text }
	number := func(name string) uint64 { return take(name, identity.FeatureUint64).Uint64 }
	duration := func(name string) time.Duration { return time.Duration(take(name, identity.FeatureInt64).Int64) }
	instant := func(name string) time.Time {
		raw := text(name)
		v, err := time.Parse(storedTimeLayout, raw)
		if err != nil || v.UTC().Format(storedTimeLayout) != raw {
			valid = false
		}
		return v
	}
	s := session.PreAuthTransactionSpec{Version: 1}
	b := &s.Binding
	b.ID = identity.PreAuthTransactionID(text("flow.id"))
	b.Intent = session.PreAuthIntent{TenantID: identity.TenantID(text("flow.tenant")), Action: text("flow.action"), Origin: text("flow.origin"), CallbackURL: text("flow.callback"), PolicyID: text("flow.policy"), PolicyVersion: number("flow.policy.version")}
	nonce := take("flow.nonce", identity.FeatureBytes).Bytes
	if len(nonce) != len(b.Intent.Nonce) {
		valid = false
	} else {
		copy(b.Intent.Nonce[:], nonce)
	}
	b.IssuedAt, b.ExpiresAt = instant("flow.issued"), instant("flow.expires")
	s.Version = number("flow.version")
	key := number("cookie.version")
	if key > uint64(^uint32(0)) {
		valid = false
	}
	s.Cookie.KeyVersion = uint32(key)
	digest := take("cookie.digest", identity.FeatureBytes).Bytes
	if len(digest) != len(s.Cookie.Sum) {
		valid = false
	} else {
		copy(s.Cookie.Sum[:], digest)
	}
	if _, present := values["flow.purpose"]; present {
		purpose := number("flow.purpose")
		if purpose != uint64(session.PreAuthPhonePasswordRecovery) {
			return bad()
		}
		b.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	}
	if b.Intent.Purpose == session.PreAuthSessionIssuance {
		choice := number("remember.choice")
		if choice > 255 {
			return bad()
		}
		remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.RememberChoice(choice), AbsoluteTTL: duration("remember.absolute"), IdleTTL: duration("remember.idle"), RefreshAfter: duration("remember.refresh"), FreshFor: duration("remember.fresh")})
		if err != nil {
			return bad()
		}
		b.Intent.Remember = remember
	}
	if !valid {
		return bad()
	}
	if _, present := values["flow.identifier"]; present {
		identifier := take("flow.identifier", identity.FeatureBytes).Bytes
		if len(identifier) != len(b.Intent.IdentifierBinding) {
			return bad()
		}
		copy(b.Intent.IdentifierBinding[:], identifier)
		if !valid || b.Intent.IdentifierBinding == ([32]byte{}) {
			return bad()
		}
	}
	if len(values) != 0 {
		return bad()
	}
	record, err := session.NewPreAuthTransaction(s)
	if err != nil {
		return bad()
	}
	// Re-encoding requires exact scope, closed scalars and original version.
	// In particular narrowing an integer cannot turn corrupt input into custody.
	canonical, err := mapPreAuthIssue(p.Binding, record)
	if err != nil {
		return bad()
	}
	expected, _ := canonical.Feature()
	if !reflect.DeepEqual(p, expected) {
		return bad()
	}
	return p.Binding, record, nil
}
