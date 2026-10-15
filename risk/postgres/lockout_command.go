package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// LockoutMutationConfig enables one native transition owner. Authorization is
// the existing concurrency-safe, revision-fenced policy service; it runs only
// outside Work and must honor cancellation. AuthorityNamespace identifies the
// existing authorization owner's actor epochs and must uniquely identify the
// selected principal kinds. Role changes must atomically advance that epoch.
// AdmissionTTL is explicit, microsecond-exact and at most twenty seconds;
// MaximumDuration bounds preparation callbacks to at most five seconds. There
// is no inferred trigger or duration. Retain signing keys for pending commands.
// SigningKeys are copied nonzero HMAC-SHA256 keys, separate from bearer keys.
type LockoutMutationConfig struct {
	Authorization            authorization.Service
	PolicyID                 string
	PolicyRevision           uint64
	AuthorityNamespace       string
	MaximumLockoutDuration   time.Duration
	AdmissionTTL             time.Duration
	MaximumDuration          time.Duration
	SigningKeys              map[uint32][32]byte
	CurrentSigningKeyVersion uint32
}

func (LockoutMutationConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.LockoutMutationConfig(redacted)")
}
func (LockoutMutationConfig) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (LockoutMutationConfig) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

type lockoutMutationState struct {
	config LockoutMutationConfig
	policy risk.LockoutPolicy
}

func newLockoutMutationState(c LockoutMutationConfig, counters risk.CommandCounterPolicy) (*lockoutMutationState, error) {
	if c.Authorization == nil || !executorID(c.PolicyID) || !executorID(c.AuthorityNamespace) || c.PolicyRevision == 0 || c.AdmissionTTL <= 0 || c.AdmissionTTL > 20*time.Second || c.AdmissionTTL%time.Microsecond != 0 || c.MaximumDuration <= 0 || c.MaximumDuration > 5*time.Second || c.MaximumDuration > c.AdmissionTTL || len(c.SigningKeys) == 0 || len(c.SigningKeys) > 16 || c.CurrentSigningKeyVersion == 0 {
		return nil, risk.ErrInvalidPolicy
	}
	v := reflect.ValueOf(c.Authorization)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil, risk.ErrInvalidPolicy
		}
	}
	keys := make(map[uint32][32]byte, len(c.SigningKeys))
	for version, key := range c.SigningKeys {
		if version == 0 || key == ([32]byte{}) {
			return nil, risk.ErrInvalidPolicy
		}
		keys[version] = key
	}
	if _, ok := keys[c.CurrentSigningKeyVersion]; !ok {
		return nil, risk.ErrInvalidPolicy
	}
	c.SigningKeys = keys
	p, err := risk.NewLockoutPolicy(risk.LockoutPolicyConfig{Counters: counters, MaximumDuration: c.MaximumLockoutDuration})
	if err != nil {
		return nil, err
	}
	return &lockoutMutationState{config: c, policy: p}, nil
}

// LockoutCommandRequest is trusted server-resolved input, never transport JSON.
// Binding identifies the administrative command, Request.Scope.Operation the
// independently restricted operation. First start uses RecordID=CommandID;
// later transitions retain the same opaque record ID and exact expected version.
// AuthorityVersion is the current actor epoch, not a policy decision. Scope is
// authenticated policy context; no caller-supplied risk bypass is accepted.
type LockoutCommandRequest struct {
	Binding          identity.CommandBinding
	Scope            authorization.DecisionContext
	Request          risk.LockoutRequest
	AuthorityVersion uint64
}

func (LockoutCommandRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.LockoutCommandRequest(redacted)")
}
func (LockoutCommandRequest) MarshalJSON() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}
func (LockoutCommandRequest) MarshalText() ([]byte, error) {
	return nil, risk.ErrSensitiveSerialization
}

// LockoutOperation returns a closed native schema, not mutation authority.
// Native operation IDs use hyphens; canonical audit actions use underscores.
// Neither ID is an alias accepted by risk evaluation. Unknown mode returns zero.
func LockoutOperation(mode risk.LockoutMode) identity.FeatureOperation {
	var operation string
	switch mode {
	case risk.StartLockout:
		operation = "identity.risk.start-lockout"
	case risk.EndLockout:
		operation = "identity.risk.end-lockout"
	default:
		return identity.FeatureOperation{}
	}
	return identity.FeatureOperation{Owner: "identity/risk", OperationID: operation, SchemaID: "identity-risk-lockout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func isLockoutOperation(op identity.FeatureOperation) bool {
	return op == LockoutOperation(risk.StartLockout) || op == LockoutOperation(risk.EndLockout)
}

// PrepareLockoutCommand checks current policy outside any transaction and seals
// the complete immutable request. PrimaryTime must be the original primary read
// instant obtained before policy evaluation; never use a request/process clock,
// rewrite it on retry or add network delay to it. Native apply rechecks primary
// expiry and current actor epoch under lock. Preparation grants no commitment.
// This adapter mapping is for trusted owned workflows, not application glue;
// retain the returned command unchanged for replay/ambiguous outcome recovery.
func (r *Repository) PrepareLockoutCommand(ctx context.Context, q LockoutCommandRequest, primaryTime time.Time) (command identity.Command, err error) {
	defer func() {
		if recover() != nil {
			command = identity.Command{}
			err = identity.UnavailableError{}
		}
	}()
	if ctx == nil || r == nil || r.lockoutMutation == nil {
		return identity.Command{}, risk.ErrInvalidCounterCommand
	}
	n := r.lockoutMutation
	b, request := q.Binding, q.Request
	op := LockoutOperation(request.Mode)
	if b.ValidateFor(op) != nil || b.PolicyID != n.config.PolicyID || b.PolicyVersion != r.policy || q.AuthorityVersion == 0 || string(b.TenantID) != request.Scope.Tenant || string(b.CommandID) != request.Scope.Attempt || string(b.UserID) != request.Subject.User || string(b.ActorID) != request.Actor || request.ExpectedVersion == 0 && b.RecordID != string(b.CommandID) {
		return identity.Command{}, risk.ErrInvalidCounterCommand
	}
	if _, e := identity.ParseSubjectID(b.RecordID); e != nil {
		return identity.Command{}, risk.ErrInvalidCounterCommand
	}
	if _, e := n.policy.Prepare(request, primaryTime); e != nil {
		return identity.Command{}, e
	}
	dc := q.Scope
	a := dc.Request
	if dc.Validate() != nil || dc.PolicyRevision != authorization.Revision(n.config.PolicyRevision) || dc.CorrelationID != b.CorrelationID || a.Tenant != authorization.TenantID(b.TenantID) || a.Action != authorization.Action(b.OperationID) || a.Subject.ID != authorization.SubjectID(b.ActorID) || a.Subject.Kind != b.ActorKind || a.Resource.Type != "identity.user" || a.Resource.ID != authorization.ResourceID(b.UserID) || !boundedLockoutCaller(dc) {
		return identity.Command{}, identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, n.config.MaximumDuration)
	defer cancel()
	dc = dc.Clone()
	dc.Request.Environment.Time = time.Now().UTC()
	decision, e := n.config.Authorization.Decide(bounded, dc)
	if bounded.Err() != nil {
		return identity.Command{}, bounded.Err()
	}
	if e != nil {
		return identity.Command{}, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return identity.Command{}, identity.ForbiddenError{}
	}
	fields := []identity.FeatureField{textField("lockout.target-operation", string(request.Scope.Operation)), textField("lockout.network", request.Subject.Network), textField("lockout.session", request.Subject.Session), uintField("lockout.expected-version", request.ExpectedVersion), uintField("lockout.duration-us", uint64(request.Duration/time.Microsecond)), uintField("lockout.authority-version", q.AuthorityVersion), uintField("lockout.policy-revision", n.config.PolicyRevision), uintField("lockout.signing-version", uint64(n.config.CurrentSigningKeyVersion)), {Name: "lockout.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: primaryTime}}}
	c, e := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields})
	if e != nil {
		return identity.Command{}, e
	}
	s, _ := c.Feature()
	proof := lockoutSignature(n.config.SigningKeys[n.config.CurrentSigningKeyVersion], s)
	s.Fields = append(s.Fields, bytesField("lockout.signature", proof))
	return identity.NewFeatureCommand(s)
}

func boundedLockoutCaller(dc authorization.DecisionContext) bool {
	// Reuse the bounded existing executor policy shape without its operation
	// restriction; this projection is only local admission, never permission.
	copy := dc
	copy.Request.Action = authorization.Action(IssueOperation().OperationID)
	return boundedExecutorCaller(copy)
}

type restoredLockout struct {
	request   risk.LockoutRequest
	command   risk.LockoutCommand
	at        time.Time
	authority uint64
	signing   uint32
}

func (r *Repository) restoreLockout(c identity.Command) (restoredLockout, error) {
	fail := func() (restoredLockout, error) { return restoredLockout{}, risk.ErrInvalidCounterCommand }
	s, ok := c.Feature()
	if !ok || r == nil || r.lockoutMutation == nil || !isLockoutOperation(s.Operation) || len(s.Fields) != 10 || s.Binding.PolicyID != r.lockoutMutation.config.PolicyID || s.Binding.PolicyVersion != r.policy {
		return fail()
	}
	b := s.Binding
	if _, e := identity.ParseSubjectID(b.RecordID); e != nil {
		return fail()
	}
	n := restoredLockout{request: risk.LockoutRequest{Actor: string(b.ActorID), Scope: risk.Context{Tenant: string(b.TenantID), Attempt: string(b.CommandID)}, Subject: risk.Subject{User: string(b.UserID)}}}
	if s.Operation == LockoutOperation(risk.StartLockout) {
		n.request.Mode = risk.StartLockout
	} else {
		n.request.Mode = risk.EndLockout
	}
	var signature []byte
	var signing uint64
	unsigned := s
	unsigned.Fields = nil
	for _, f := range s.Fields {
		if f.Name != "lockout.signature" {
			unsigned.Fields = append(unsigned.Fields, f)
		}
		switch f.Name {
		case "lockout.target-operation":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			n.request.Scope.Operation = risk.Action(f.Value.Text)
		case "lockout.network":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			n.request.Subject.Network = f.Value.Text
		case "lockout.session":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			n.request.Subject.Session = f.Value.Text
		case "lockout.expected-version":
			if f.Value.Kind != identity.FeatureUint64 {
				return fail()
			}
			n.request.ExpectedVersion = f.Value.Uint64
		case "lockout.duration-us":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 > uint64((1<<63-1)/int64(time.Microsecond)) {
				return fail()
			}
			n.request.Duration = time.Duration(f.Value.Uint64) * time.Microsecond
		case "lockout.authority-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 {
				return fail()
			}
			n.authority = f.Value.Uint64
		case "lockout.policy-revision":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != r.lockoutMutation.config.PolicyRevision {
				return fail()
			}
		case "lockout.signing-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || f.Value.Uint64 > uint64(^uint32(0)) {
				return fail()
			}
			signing = f.Value.Uint64
		case "lockout.prepared-at":
			if f.Value.Kind != identity.FeatureTime {
				return fail()
			}
			n.at = f.Value.Time
		case "lockout.signature":
			if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
				return fail()
			}
			signature = f.Value.Bytes
		default:
			return fail()
		}
	}
	key, ok := r.lockoutMutation.config.SigningKeys[uint32(signing)]
	if !ok {
		return fail()
	}
	expected := lockoutSignature(key, unsigned)
	if !hmac.Equal(signature, expected[:]) {
		return fail()
	}
	n.signing = uint32(signing)
	if n.request.ExpectedVersion == 0 && b.RecordID != string(b.CommandID) {
		return fail()
	}
	n.command, _ = r.lockoutMutation.policy.Prepare(n.request, n.at)
	if n.command.Bindings().Target.Dimension != risk.SubjectDimension {
		return fail()
	}
	return n, nil
}

func lockoutSignature(key [32]byte, s identity.FeatureCommandSpec) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-risk-lockout-command-v1\x00"))
	b := bindingDigest(s.Binding)
	_, _ = mac.Write(b[:])
	for _, f := range s.Fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(f.Name)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(f.Name))
		_, _ = mac.Write([]byte{byte(f.Value.Kind)})
		var raw []byte
		var value [8]byte
		switch f.Value.Kind {
		case identity.FeatureText:
			raw = []byte(f.Value.Text)
		case identity.FeatureUint64:
			binary.BigEndian.PutUint64(value[:], f.Value.Uint64)
			raw = value[:]
		case identity.FeatureTime:
			binary.BigEndian.PutUint64(value[:], uint64(f.Value.Time.UnixMicro()))
			raw = value[:]
		}
		binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(raw)
	}
	return [32]byte(mac.Sum(nil))
}

// Stable intent excludes preparation time so historical result disclosure can
// compare an unchanged request without issuing a new permission or retry seal.
// All effect-bearing input remains keyed; raw network/session facts are never
// persisted in the domain-version table.
func lockoutIntentDigest(key [32]byte, b identity.CommandBinding, r risk.LockoutRequest, authority uint64) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-risk-lockout-original-intent-v1\x00"))
	d := bindingDigest(b)
	_, _ = mac.Write(d[:])
	for _, s := range []string{string(r.Scope.Operation), r.Subject.Network, r.Subject.Session, string(r.Mode)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(s)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(s))
	}
	for _, n := range []uint64{r.ExpectedVersion, uint64(r.Duration), authority} {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], n)
		_, _ = mac.Write(raw[:])
	}
	return [32]byte(mac.Sum(nil))
}

func lockoutEvents(mode risk.LockoutMode) (string, string) {
	if mode == risk.StartLockout {
		return "identity.risk.start_lockout", "risk.lockout_started.v1"
	}
	return "identity.risk.end_lockout", "risk.lockout_ended.v1"
}

func (r *Repository) validateLockoutFeature(c identity.Command, p identitypostgres.CommandPlan) error {
	n, e := r.restoreLockout(c)
	if e != nil {
		return e
	}
	s, _ := c.Feature()
	audit, event := lockoutEvents(n.request.Mode)
	if p.SubjectType != "risk_lockout" || p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != s.Operation || p.Lifecycle == nil || p.Lifecycle.EventType != event || p.Lifecycle.EventIndex != 0 || p.Lifecycle.BeforeVersion != n.request.ExpectedVersion || p.Lifecycle.AfterVersion != n.request.ExpectedVersion+1 || p.Capability != nil || p.RiskEvidence != nil || p.CommandCounters != nil || len(p.Audits) != 1 {
		return risk.ErrInvalidCounterCommand
	}
	a := p.Audits[0]
	if a.EventType != audit || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 {
		return risk.ErrInvalidCounterCommand
	}
	return nil
}
