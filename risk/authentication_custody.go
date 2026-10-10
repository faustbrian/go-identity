package risk

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
)

// AuthenticationAdmissionCustodyConfig is immutable native workflow startup
// composition, not request input. ConfigurationID versions callback/storage
// semantics that cannot be inferred from functions; change it whenever those
// semantics change. Every source must also have a pinned Version. Evaluation
// must own counted, audited evaluation. Keys are existing risk integrity/linkage
// keys: highest version prepares, retained versions restore. No new journal,
// evidence issuer, mutation owner, clock or provider is configured here.
type AuthenticationAdmissionCustodyConfig struct {
	Evaluation      Evaluator
	ConfigurationID string
	Keys            []EvidenceKey
}

// AuthenticationAdmissionCustody authenticates original Authentication facts
// for the existing native preparation journal. It owns no durable state or
// permission to authenticate a caller. It starts no goroutine and is safe for
// concurrent use under the evaluator's immutable callback contract.
type AuthenticationAdmissionCustody struct{ state *authenticationCustody }

func (AuthenticationAdmissionCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.AuthenticationAdmissionCustody(redacted)")
}
func (AuthenticationAdmissionCustody) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (AuthenticationAdmissionCustody) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

type authenticationCustody struct {
	evaluation Evaluator
	identity   string
	keys       []EvidenceKey
	current    EvidenceKey
}

// NewAuthenticationAdmissionCustody validates and copies startup configuration
// without clock, source, counter, audit or storage IO. Zero is invalid.
func NewAuthenticationAdmissionCustody(c AuthenticationAdmissionCustodyConfig) (AuthenticationAdmissionCustody, error) {
	e := c.Evaluation.state
	if e == nil || e.audit == nil || e.counters.state == nil || !scopeID(c.ConfigurationID) || len(c.Keys) < 1 || len(c.Keys) > 16 {
		return AuthenticationAdmissionCustody{}, ErrInvalidPolicy
	}
	for _, source := range e.sources {
		if source.Version == "" {
			return AuthenticationAdmissionCustody{}, ErrInvalidPolicy
		}
	}
	s := &authenticationCustody{evaluation: c.Evaluation, identity: c.ConfigurationID, keys: slices.Clone(c.Keys)}
	seen := make(map[uint32]bool, len(s.keys))
	for _, k := range s.keys {
		if k.version == 0 || k.signing == ([32]byte{}) || k.digest == ([32]byte{}) || seen[k.version] {
			return AuthenticationAdmissionCustody{}, ErrInvalidPolicy
		}
		seen[k.version] = true
		if k.version > s.current.version {
			s.current = k
		}
	}
	return AuthenticationAdmissionCustody{state: s}, nil
}

// PreparedAuthenticationAdmission is a signed native-only projection for an
// owning workflow's authenticated encrypted output. It is not transport input,
// a public decision response, one-use RiskEvidence or an authentication proof.
// CounterFingerprint and ProofDigest retain original counted/audit identity;
// normalized Signals retain original scope, factor facts and exclusive expiry.
// Store this only through the existing encrypted preparation owner, never in a
// separate admission table. Public fields grant nothing without Restore.
type PreparedAuthenticationAdmission struct {
	Scope                                       Context
	Signals                                     []Signal
	KeyVersion                                  uint32
	PolicyVersion                               uint64
	CounterFingerprint                          string
	ConfigurationDigest, ProofDigest, Signature [32]byte
}

func (PreparedAuthenticationAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedAuthenticationAdmission(redacted)")
}
func (PreparedAuthenticationAdmission) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (PreparedAuthenticationAdmission) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// AuthenticationAdmission is opaque invocation-local custody. Copies cannot
// renew original facts. It grants abuse admission only: the workflow still owns
// current account/flow/recipient authorization and atomic domain effects.
type AuthenticationAdmission struct {
	owner    *authenticationCustody
	prepared PreparedAuthenticationAdmission
}

func (AuthenticationAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.AuthenticationAdmission(redacted)")
}
func (AuthenticationAdmission) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AuthenticationAdmission) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Prepared returns an owned signed native projection; zero returns zero.
// Mutation of this copy cannot alter the original admission.
func (a AuthenticationAdmission) Prepared() PreparedAuthenticationAdmission {
	p := a.prepared
	p.Signals = slices.Clone(p.Signals)
	return p
}

// Prepare retains only a genuine original counted/audited Allow from this exact
// evaluator and bound trusted scope/dimensions. It performs only bounded local
// checks and MAC work; it does not re-evaluate providers, mutate counters, emit
// another decision audit, or issue a durable artifact. Expired/foreign/zero
// input denies. Cancellation remains attributable; callback failures redact.
func (s AuthenticationAdmissionCustody) Prepare(ctx context.Context, result EvaluateResult, scope Context, subject Subject) (AuthenticationAdmission, error) {
	if ctx == nil {
		return AuthenticationAdmission{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return AuthenticationAdmission{}, err
	}
	if s.state == nil {
		return AuthenticationAdmission{}, ErrInvalidAuthenticationAdmission
	}
	e := s.state.evaluation
	if err := e.RequireAuthenticationAdmission(ctx, result, scope, subject); err != nil {
		return AuthenticationAdmission{}, err
	}
	provenance := result.provenance
	// The private captured delivery, not caller-replaced public Audit metadata,
	// owns original audited provenance.
	d := provenance.audit
	if d.outcome != audit.AppendCommitted || d.record.ID() == "" {
		return AuthenticationAdmission{}, ErrInvalidAuthenticationAdmission
	}
	key := s.state.current
	p := PreparedAuthenticationAdmission{Scope: provenance.context, Signals: slices.Clone(provenance.signals), KeyVersion: key.version, PolicyVersion: result.PolicyVersion, CounterFingerprint: result.counter.result.state.fingerprint}
	p.ConfigurationDigest = s.state.configuration(key)
	snapshot := result.counter.result.state.snapshot
	proofFields := []string{p.CounterFingerprint, string(d.commandID), d.record.ID(), strconv.Itoa(len(snapshot))}
	for _, counter := range snapshot {
		proofFields = append(proofFields, counter.Kind, strconv.FormatUint(counter.Value, 10), evidenceTime(counter.ObservedAt), evidenceTime(counter.WindowStartedAt), evidenceTime(counter.WindowExpiresAt))
	}
	p.ProofDigest = evidenceMAC(key.digest, "identity-risk-authentication-counted-audit-v1", proofFields)
	p.Signature = authenticationSignature(key, p)
	return s.Restore(ctx, p, scope, subject)
}

// Restore authenticates bounded retained native custody under the same pinned
// configuration and retained key, then checks original facts at trusted current
// time without IO. Changed policy/source/counter key/configuration, foreign
// dimensions, tampering or original expiry denies. Reconstruction creates no
// EvaluateResult provenance and cannot authorize another counter mutation.
func (s AuthenticationAdmissionCustody) Restore(ctx context.Context, p PreparedAuthenticationAdmission, scope Context, subject Subject) (AuthenticationAdmission, error) {
	bad := func() (AuthenticationAdmission, error) {
		return AuthenticationAdmission{}, ErrInvalidAuthenticationAdmission
	}
	if ctx == nil {
		return AuthenticationAdmission{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return AuthenticationAdmission{}, err
	}
	if s.state == nil || len(p.Signals) < 1 || len(p.Signals) > 32 || p.KeyVersion == 0 || p.ProofDigest == ([32]byte{}) || !validTime(p.Scope.Now) || p.Scope.Tenant != scope.Tenant || p.Scope.Operation != scope.Operation || p.Scope.Attempt != scope.Attempt {
		return bad()
	}
	e := s.state.evaluation
	a, err := e.state.counters.admitScope(p.Scope, BeforeCredential)
	if err != nil || a.Profile.Class != Authentication || a.PolicyVersion != p.PolicyVersion {
		return bad()
	}
	command, err := e.state.counters.prepareAdmitted(p.Scope, subject, BeforeCredential, a, p.Scope.Now)
	if err != nil || command.state.binding.Fingerprint != p.CounterFingerprint {
		return bad()
	}
	var key EvidenceKey
	for _, k := range s.state.keys {
		if k.version == p.KeyVersion {
			key = k
			break
		}
	}
	if key.version == 0 || s.state.configuration(key) != p.ConfigurationDigest {
		return bad()
	}
	// Assess performs all signal bounds/scope/uniqueness checks before hashing.
	original, err := e.state.policy.Assess(ctx, p.Scope, p.Signals)
	if ctx.Err() != nil {
		return AuthenticationAdmission{}, ctx.Err()
	}
	if err != nil || original.Decision.Action != Allow {
		return bad()
	}
	want := authenticationSignature(key, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return bad()
	}
	p.Signals = slices.Clone(p.Signals)
	admission := AuthenticationAdmission{owner: s.state, prepared: p}
	if err := admission.Check(ctx); err != nil {
		return AuthenticationAdmission{}, err
	}
	return admission, nil
}

// Check is bounded and IO-free. It ignores caller time/factor overrides and uses
// the evaluator clock to re-assess the unchanged original normalized facts.
// Backward clocks, exact expiry, cancellation and failed clocks deny. This
// neither refreshes observations nor substitutes current primary authority.
func (a AuthenticationAdmission) Check(ctx context.Context) (err error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.owner == nil {
		return ErrInvalidAuthenticationAdmission
	}
	defer func() {
		if recover() != nil {
			err = ErrInvalidAuthenticationAdmission
		}
	}()
	now := a.owner.evaluation.state.clock()
	return a.CheckAt(ctx, now)
}

// CheckAt re-assesses this opaque authenticated admission at a trusted server
// observation, such as the owning transaction's primary database time. Never
// supply request-controlled time. Unlike Check, it invokes no configured clock,
// source, counter or audit callback, so it can run while the owner holds locks.
// The original facts and exclusive expiry remain unchanged; backward or invalid
// observations deny. Nil contexts and cancellation retain their existing errors.
// This establishes neither current account authority nor one-time consumption.
// It is bounded, IO-free and safe for concurrent use.
func (a AuthenticationAdmission) CheckAt(ctx context.Context, now time.Time) error {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.owner == nil {
		return ErrInvalidAuthenticationAdmission
	}
	p := a.prepared
	if !validTime(now) || now.Before(p.Scope.Now) {
		return ErrInvalidAuthenticationAdmission
	}
	c := p.Scope
	c.Now = now
	assessment, err := a.owner.evaluation.state.policy.Assess(ctx, c, p.Signals)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || assessment.Decision.Action != Allow {
		return ErrInvalidAuthenticationAdmission
	}
	return nil
}

func authenticationSignature(k EvidenceKey, p PreparedAuthenticationAdmission) [32]byte {
	// Policy bounds every signal before hashing. Encode every typed field using
	// length-framed MAC inputs and canonical UTC instants: accepted timestamps
	// can have locations that JSON cannot encode, and encoding failure must never
	// remove facts from integrity protection.
	fields := []string{p.Scope.Tenant, string(p.Scope.Operation), p.Scope.Attempt, evidenceTime(p.Scope.Now), strconv.FormatBool(p.Scope.IndependentFactor), strconv.FormatUint(uint64(p.KeyVersion), 10), strconv.FormatUint(p.PolicyVersion, 10), p.CounterFingerprint, string(p.ConfigurationDigest[:]), string(p.ProofDigest[:]), strconv.Itoa(len(p.Signals))}
	for _, signal := range p.Signals {
		fields = append(fields, signal.Tenant, string(signal.Operation), signal.Attempt, signal.Name, strconv.Itoa(int(signal.State)), strconv.Itoa(int(signal.Trust)), evidenceTime(signal.ObservedAt), evidenceTime(signal.ExpiresAt), strconv.FormatInt(int64(signal.RetryAfter), 10), strconv.FormatUint(signal.BreachCount, 10), strconv.Itoa(int(signal.Failure)), evidenceTime(signal.ProviderValidUntil), evidenceTime(signal.CheckedAt))
	}
	return evidenceMAC(k.signing, "identity-risk-authentication-preparation-v1", fields)
}

func (s *authenticationCustody) configuration(k EvidenceKey) [32]byte {
	e := s.evaluation.state
	policy := e.policy.state
	shape, _ := json.Marshal(struct {
		Version  uint64
		Limits   VelocityLimits
		Profiles map[ProfileClass]Profile
		HIBPTTL  time.Duration
		HIBP     map[Action]bool
	}{policy.version, policy.limits, policy.profiles, policy.hibpTTL, policy.hibpOperations})
	defer clear(shape)
	fields := []string{s.identity, string(shape), strconv.FormatInt(int64(e.timeout), 10), strconv.FormatInt(int64(e.counters.state.timeout), 10), e.audit.config.PolicyID, strconv.FormatInt(int64(e.audit.config.Timeout), 10), strconv.Itoa(int(e.audit.config.Delivery.Mode)), strconv.FormatBool(e.independentFactor != nil)}
	names := make([]string, 0, len(e.sources))
	for name := range e.sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		source := e.sources[name]
		fields = append(fields, name, source.Version, strconv.FormatInt(int64(source.Timeout), 10), strconv.FormatBool(source.Expensive))
	}
	for _, key := range e.counters.state.keys {
		fields = append(fields, strconv.FormatUint(uint64(key.version), 10), string(key.secret))
	}
	return evidenceMAC(k.digest, "identity-risk-authentication-configuration-v1", fields)
}
