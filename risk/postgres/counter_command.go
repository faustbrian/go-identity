package postgres

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// PrepareCommandCounters adds a closed native counter projection to an existing
// protected feature command. Subject is trusted server-resolved input, not an
// HTTP request: subject/actor/resource must equal the command's canonical binding.
// PrimaryTime is supplied primary UTC microsecond time; reservation rechecks it
// without renewal. Raw network/session values stay only in the opaque command,
// not persisted columns or the frozen plan. This pure method grants no allowance,
// authorization or commitment. The feature owner must validate its own schema
// including these reserved fields. Zero/disabled repository fails redacted.
func (r *Repository) PrepareCommandCounters(c identity.Command, subject risk.Subject, primaryTime time.Time) (identity.Command, identitypostgres.CommandCounterPlan, error) {
	fail := func() (identity.Command, identitypostgres.CommandCounterPlan, error) {
		return identity.Command{}, identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	s, ok := c.Feature()
	if !ok || r == nil || r.counters == nil {
		return fail()
	}
	for _, f := range s.Fields {
		if strings.HasPrefix(f.Name, "counter.") {
			return fail()
		}
	}
	scope := risk.Context{Tenant: string(s.Binding.TenantID), Operation: risk.Action(s.Binding.OperationID), Attempt: string(s.Binding.CommandID)}
	admission, e := r.counters.Policy.Admit(scope.Operation)
	if e != nil {
		return fail()
	}
	if admission.Profile.Class == risk.CredentialMutation && subject.User != string(s.Binding.UserID) || admission.Profile.Class == risk.Privileged && (subject.Actor != string(s.Binding.ActorID) || subject.Resource != s.Binding.RecordID) {
		return fail()
	}
	native, e := r.counterPolicy.Prepare(scope, subject, primaryTime)
	if e != nil {
		return fail()
	}
	b := native.Bindings()
	if b.PolicyVersion != r.policy {
		return fail()
	}
	versions := make([]byte, 4*len(b.Targets[0].Keys))
	for i, k := range b.Targets[0].Keys {
		binary.BigEndian.PutUint32(versions[i*4:], k.Version)
	}
	s.Fields = append(s.Fields, textField("counter.network", subject.Network), textField("counter.session", subject.Session), identity.FeatureField{Name: "counter.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: primaryTime}}, identity.FeatureField{Name: "counter.key-versions", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: versions}})
	mapped, e := identity.NewFeatureCommand(s)
	if e != nil {
		return fail()
	}
	plan, e := counterPlan(b)
	if e != nil {
		return fail()
	}
	return mapped, plan, nil
}
func counterPlan(b risk.CounterBinding) (identitypostgres.CommandCounterPlan, error) {
	raw, e := hex.DecodeString(b.Fingerprint)
	if e != nil || len(raw) != 32 {
		return identitypostgres.CommandCounterPlan{}, risk.ErrInvalidCounterCommand
	}
	p := identitypostgres.CommandCounterPlan{PolicyVersion: b.PolicyVersion}
	copy(p.Fingerprint[:], raw)
	return p, nil
}

type restoredCounter struct {
	command risk.CounterCommand
	policy  risk.CommandCounterPolicy
	current risk.CounterBinding
	scope   risk.Context
	subject risk.Subject
}

// ValidateCommandCounters reconstructs exact native scope and its original
// retained-key projection without IO. Historical key subsets remain decodable
// during rotation, but only current complete history admits a new charge.
func (r *Repository) ValidateCommandCounters(c identity.Command, p identitypostgres.CommandCounterPlan) error {
	_, e := r.restoreCounter(c, p)
	return e
}
func (r *Repository) restoreCounter(c identity.Command, p identitypostgres.CommandCounterPlan) (restoredCounter, error) {
	fail := func() (restoredCounter, error) { return restoredCounter{}, risk.ErrInvalidCounterCommand }
	s, ok := c.Feature()
	if !ok || r == nil || r.counters == nil || p.PolicyVersion != r.policy {
		return fail()
	}
	scope := risk.Context{Tenant: string(s.Binding.TenantID), Operation: risk.Action(s.Binding.OperationID), Attempt: string(s.Binding.CommandID)}
	a, e := r.counters.Policy.Admit(scope.Operation)
	if e != nil {
		return fail()
	}
	subject := risk.Subject{}
	switch a.Profile.Class {
	case risk.CredentialMutation:
		subject.User = string(s.Binding.UserID)
	case risk.Privileged:
		subject.Actor = string(s.Binding.ActorID)
		subject.Resource = s.Binding.RecordID
	default:
		return fail()
	}
	var at time.Time
	var versions []byte
	count := 0
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "counter.") {
			continue
		}
		count++
		switch f.Name {
		case "counter.network":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			subject.Network = f.Value.Text
		case "counter.session":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			subject.Session = f.Value.Text
		case "counter.prepared-at":
			if f.Value.Kind != identity.FeatureTime {
				return fail()
			}
			at = f.Value.Time
		case "counter.key-versions":
			if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) < 4 || len(f.Value.Bytes) > 16 || len(f.Value.Bytes)%4 != 0 {
				return fail()
			}
			versions = f.Value.Bytes
		default:
			return fail()
		}
	}
	if count != 4 {
		return fail()
	}
	current, e := r.counterPolicy.Prepare(scope, subject, at)
	if e != nil {
		return fail()
	}
	b := current.Bindings()
	var selected []risk.CounterDigestKey
	for off := 0; off < len(versions); off += 4 {
		version := binary.BigEndian.Uint32(versions[off:])
		if version == 0 || off > 0 && binary.BigEndian.Uint32(versions[off-4:]) <= version {
			return fail()
		}
		found := false
		for i, k := range b.Targets[0].Keys {
			if k.Version == version {
				selected = append(selected, r.counters.Keys[i])
				found = true
				break
			}
		}
		if !found {
			return fail()
		}
	}
	cfg := risk.CommandCounterPolicyConfig{Policy: r.counters.Policy, Keys: selected}
	policy, e := risk.NewCommandCounterPolicy(cfg)
	if e != nil {
		return fail()
	}
	original, e := policy.Prepare(scope, subject, at)
	if e != nil {
		return fail()
	}
	expected, e := counterPlan(original.Bindings())
	if e != nil || expected != p {
		return fail()
	}
	return restoredCounter{command: original, policy: policy, current: b, scope: scope, subject: subject}, nil
}
