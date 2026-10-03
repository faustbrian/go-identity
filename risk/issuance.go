package risk

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidEvidenceRequest rejects incomplete or phase-mismatched trusted intent.
	ErrInvalidEvidenceRequest = errors.New("risk: invalid evidence request")
	// ErrInvalidEvidenceExecution rejects foreign, corrupt or unbound native outcomes.
	ErrInvalidEvidenceExecution = errors.New("risk: invalid evidence execution")
	// ErrEvidenceUnavailable redacts native executor diagnostics; outcome is unknown.
	ErrEvidenceUnavailable = errors.New("risk: evidence unavailable")
)

// EvidenceKey owns independent 256-bit HMAC-SHA-256 integrity and linkage keys.
// The highest configured version issues; every retained version stays verifiable.
// Keys are immutable copied startup data, never request input. Go cannot promise
// memory erasure; automatic formatting/serialization does not expose material.
type EvidenceKey struct {
	version         uint32
	signing, digest [32]byte
}

// NewEvidenceKey copies exactly two distinct 32-byte keys under a nonzero version.
func NewEvidenceKey(version uint32, signing, digest []byte) (EvidenceKey, error) {
	if version == 0 || len(signing) != 32 || len(digest) != 32 || hmac.Equal(signing, digest) {
		return EvidenceKey{}, ErrInvalidPolicy
	}
	k := EvidenceKey{version: version}
	copy(k.signing[:], signing)
	copy(k.digest[:], digest)
	if k.signing == ([32]byte{}) || k.digest == ([32]byte{}) {
		return EvidenceKey{}, ErrInvalidPolicy
	}
	return k, nil
}
func (EvidenceKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceKey(redacted)")
}
func (EvidenceKey) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceKey) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// PhoneEvidenceRequest is trusted phone-workflow input, not transport input or
// the final canonical Service request. Actor is the authorized server caller;
// it is bound, not authenticated by this structural value. CommandID is one
// canonical nonzero 128-bit identity command ID. Phase derives purpose; raw
// facts, decisions and caller-selected failure policy have no representation.
type PhoneEvidenceRequest struct {
	CommandID, Actor string
	Recovery         CarrierRequest
	Subject          Subject
}

func (PhoneEvidenceRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PhoneEvidenceRequest(redacted)")
}
func (PhoneEvidenceRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (PhoneEvidenceRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EvidenceOutcome is a coordinator-attested result, not a database guess.
// Missing is legal only for Resolve before evaluation. Failed requires proof
// of noncommit. Unknown cannot disclose a reference, retry or rerun providers.
type EvidenceOutcome uint8

const (
	EvidenceMissing EvidenceOutcome = iota + 1
	EvidenceDenied
	EvidenceFailed
	EvidenceUnknown
	EvidenceCommitted
)

// RiskEvidenceRef is an opaque phone-recovery bearer. Reveal is explicit custody
// transfer to the authorized response encoder or encrypted native journal.
// Parsing or possession grants no authority: the later durable reservation and
// atomic protected-command consumption are still required. Zero reveals empty.
type RiskEvidenceRef struct{ value string }

func (r RiskEvidenceRef) Reveal() string { return r.value }

// ParseRiskEvidenceRef admits only the bounded canonical opaque wire syntax.
// It grants no cryptographic, durable or recovery authority; the native adapter
// must pass the original record through NewEvidenceExecution and later reserve.
func ParseRiskEvidenceRef(value string) (RiskEvidenceRef, error) {
	if len(value) < 93 || len(value) > 103 {
		return RiskEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "re1" || len(parts[2]) != 43 || len(parts[3]) != 43 {
		return RiskEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	version, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || version == 0 || parts[1] != strconv.FormatUint(version, 10) {
		return RiskEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	for _, part := range parts[2:] {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(decoded) != 32 {
			return RiskEvidenceRef{}, ErrInvalidEvidenceExecution
		}
	}
	return RiskEvidenceRef{value: value}, nil
}
func (RiskEvidenceRef) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.RiskEvidenceRef(redacted)")
}
func (RiskEvidenceRef) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (RiskEvidenceRef) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// RiskEvidence is the safe operation projection. Fields are metadata, not
// mutable authorization. Original expiry survives every replay and cache copy.
type RiskEvidence struct {
	Reference           RiskEvidenceRef
	Purpose             string
	IssuedAt, ExpiresAt time.Time
	MaxUses             uint8
}

// PhoneEvidenceResult returns only durability classification and safe evidence.
// All noncommitted outcomes have zero Evidence; no decision/source internals leak.
type PhoneEvidenceResult struct {
	Outcome  EvidenceOutcome
	Evidence RiskEvidence
}

func (PhoneEvidenceResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PhoneEvidenceResult(redacted)")
}

// EvidenceIntent is immutable core-owned exact request intent. Resolve must
// authorize the caller and compare this intent before any provider work. Its
// per-retained-key digests allow rotation without losing old-command recovery.
// It never contains caller-provided facts or a provisional issued artifact.
type EvidenceIntent struct{ state *evidenceIntent }
type evidenceIntent struct {
	keys          []EvidenceKey
	configuration []string
	request       PhoneEvidenceRequest
	purpose       string
	native        *EvidenceIntentBinding
}

func (EvidenceIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceIntent(redacted)")
}
func (EvidenceIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EvidenceIntentBinding is the bounded native adapter projection. Phone/network,
// attempt and pre-auth values are included only in scoped keyed IntentDigest;
// they must not become raw journal columns. This is not an operation result.
type EvidenceIntentBinding struct {
	RecoveryOperation                          Action
	CommandID, Tenant, Subject, Actor, Purpose string
	Phase                                      IssuancePhase
	PolicyVersion                              uint64
	KeyVersion                                 uint32
	IntentDigest                               [32]byte
}

func (EvidenceIntentBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceIntentBinding(redacted)")
}

// Bindings returns owned current/retained native lookup projections. Order is
// configured order, not authority precedence; each version has its own digest.
func (i EvidenceIntent) Bindings() []EvidenceIntentBinding {
	if i.state == nil {
		return nil
	}
	if i.state.native != nil {
		return []EvidenceIntentBinding{*i.state.native}
	}
	r := i.state.request
	b := r.Recovery.Binding
	result := make([]EvidenceIntentBinding, 0, len(i.state.keys))
	for _, k := range i.state.keys {
		result = append(result, EvidenceIntentBinding{CommandID: r.CommandID, Tenant: b.Tenant, Subject: b.Subject, Actor: r.Actor, Purpose: i.state.purpose, Phase: r.Recovery.Phase, RecoveryOperation: b.RecoveryOperation, PolicyVersion: b.PolicyVersion, KeyVersion: k.version, IntentDigest: intentDigest(i, k)})
	}
	return result
}

// EvidenceRecord is only a trusted native persistence projection. Reference
// must be envelope-encrypted before storage; no raw number/network/provider body
// is represented. Digests/signatures/native records never cross operation results.
// Times are original database UTC microsecond instants. KeyVersion identifies
// the paired independently keyed integrity/linkage profile, not policy version.
type EvidenceRecord struct {
	Reference                                 RiskEvidenceRef
	IntentDigest, ProofDigest, EvidenceDigest [32]byte
	KeyVersion                                uint32
	IssuedAt, ExpiresAt                       time.Time
}

func (EvidenceRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceRecord(redacted)")
}
func (EvidenceRecord) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceRecord) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EvidenceIssue is opaque successful owned-evaluation input to the native
// contributor. It cannot be built from public metadata or caller facts. Copies
// share immutable provenance/randomness. It is provisional, not issued evidence.
type EvidenceIssue struct{ state *evidenceIssue }
type evidenceIssue struct {
	intent                EvidenceIntent
	preparedAt, expiresAt time.Time
	proof                 [32]byte
	nonce                 [32]byte
	key                   EvidenceKey
}

// PreparedEvidence is a bounded signed native command projection, never a
// caller-input or public operation result. The signature authenticates complete
// owned evaluation/intent and its original exclusive interval. Random nonce is
// not a bearer without the separate database-time-bound integrity MAC. Native
// adapters may encode these typed scalars in the sole coordinator command;
// raw phone/network/provider input and a private command ledger are unnecessary.
type PreparedEvidence struct {
	Binding                       EvidenceIntentBinding
	ProofDigest, Nonce, Signature [32]byte
	PreparedAt, ExpiresAt         time.Time
}

func (PreparedEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.PreparedEvidence(redacted)")
}
func (PreparedEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (PreparedEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Prepared returns a copied signed projection for the native command mapper.
// Zero returns zero. It is never sufficient for protected recovery consumption.
func (i EvidenceIssue) Prepared() PreparedEvidence {
	if i.state == nil {
		return PreparedEvidence{}
	}
	s := i.state
	var binding EvidenceIntentBinding
	for _, b := range s.intent.Bindings() {
		if b.KeyVersion == s.key.version {
			binding = b
			break
		}
	}
	p := PreparedEvidence{Binding: binding, ProofDigest: s.proof, Nonce: s.nonce, PreparedAt: s.preparedAt, ExpiresAt: s.expiresAt}
	p.Signature = preparedEvidenceSignature(s.key, p)
	return p
}

// RestoreIssue authenticates a retained typed native command without callbacks,
// IO, freshness renewal or caller facts. Only the configured official adapter
// invokes this pure bridge during shared-Work execution. Signature success
// restores provisional issue input, not durable issuance or one-use authority.
func (s PhoneEvidenceIssuer) RestoreIssue(p PreparedEvidence) (EvidenceIssue, error) {
	if s.state == nil || !validPreparedEvidence(p) || p.Binding.PolicyVersion != s.state.carrier.state.version {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	var k EvidenceKey
	for _, key := range s.state.keys {
		if key.version == p.Binding.KeyVersion {
			k = key
			break
		}
	}
	if k.version == 0 {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	return k.RestoreIssue(p)
}

// RestoreIssue verifies a signed native projection with this copied startup
// key, avoiding an adapter/issuer construction cycle. It performs no IO or
// policy decision and restores provisional input only. The native adapter must
// independently check current configured policy and its exact shared-Work scope;
// key possession or this constructor never grants durable consumption authority.
func (k EvidenceKey) RestoreIssue(p PreparedEvidence) (EvidenceIssue, error) {
	if k.version == 0 || k.signing == ([32]byte{}) || k.digest == ([32]byte{}) || k.version != p.Binding.KeyVersion || !validPreparedEvidence(p) {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	want := preparedEvidenceSignature(k, p)
	if !hmac.Equal(want[:], p.Signature[:]) {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	b := p.Binding
	r := PhoneEvidenceRequest{CommandID: b.CommandID, Actor: b.Actor, Recovery: CarrierRequest{Phase: b.Phase, Binding: PhoneRecoveryScope{Tenant: b.Tenant, Subject: b.Subject, RecoveryOperation: b.RecoveryOperation, PolicyVersion: b.PolicyVersion}}}
	i := EvidenceIntent{state: &evidenceIntent{keys: []EvidenceKey{k}, request: r, purpose: b.Purpose, native: &b}}
	return EvidenceIssue{state: &evidenceIssue{intent: i, preparedAt: p.PreparedAt, expiresAt: p.ExpiresAt, proof: p.ProofDigest, nonce: p.Nonce, key: k}}, nil
}

// Every variable-width input is rejected before creating a MAC input slice or
// hashing. A valid integrity signature never substitutes for native admission.
func validPreparedEvidence(p PreparedEvidence) bool {
	b := p.Binding
	if !validEvidenceCommandID(b.CommandID) || !scopeID(b.Tenant) || !scopeID(b.Subject) || !scopeID(b.Actor) || b.PolicyVersion == 0 || b.KeyVersion == 0 || b.IntentDigest == ([32]byte{}) || p.ProofDigest == ([32]byte{}) || !databaseEvidenceTime(p.PreparedAt) || !databaseEvidenceTime(p.ExpiresAt) || !p.ExpiresAt.After(p.PreparedAt) || p.ExpiresAt.Sub(p.PreparedAt) > 2*time.Minute {
		return false
	}
	switch b.Phase {
	case PhoneResetInitiation:
		return b.RecoveryOperation == "identity.phone.password-reset-request" && b.Purpose == "phone-password-reset-initiate"
	case PhoneResetCompletion:
		return b.RecoveryOperation == "identity.phone.password-reset-complete" && b.Purpose == "phone-password-reset-complete"
	default:
		return false
	}
}

func preparedEvidenceSignature(k EvidenceKey, p PreparedEvidence) [32]byte {
	b := p.Binding
	return evidenceMAC(k.signing, "identity-risk-evidence-prepared-v1", []string{b.CommandID, b.Tenant, b.Subject, b.Actor, b.Purpose, string(b.Phase), string(b.RecoveryOperation), strconv.FormatUint(b.PolicyVersion, 10), strconv.FormatUint(uint64(b.KeyVersion), 10), base64.RawURLEncoding.EncodeToString(b.IntentDigest[:]), base64.RawURLEncoding.EncodeToString(p.ProofDigest[:]), base64.RawURLEncoding.EncodeToString(p.Nonce[:]), evidenceTime(p.PreparedAt), evidenceTime(p.ExpiresAt)})
}

func (EvidenceIssue) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceIssue(redacted)")
}
func (EvidenceIssue) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceIssue) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Intent returns the frozen request binding; zero returns zero.
func (i EvidenceIssue) Intent() EvidenceIntent {
	if i.state == nil {
		return EvidenceIntent{}
	}
	return i.state.intent
}

// Materialize constructs the core-owned provisional bearer at authoritative
// database time inside the existing shared Work. It performs no IO, callback or
// fresh read. Original source expiry caps database issuance; late/backdated time
// fails. The adapter must atomically journal this and the coordinator receipt;
// no public reference may be disclosed before proven commit. Repeated calls at
// the same time return the exact same candidate, never renewed source freshness.
func (i EvidenceIssue) Materialize(issuedAt time.Time) (EvidenceRecord, error) {
	if i.state == nil || !databaseEvidenceTime(issuedAt) || issuedAt.Before(i.state.preparedAt) || !issuedAt.Before(i.state.expiresAt) {
		return EvidenceRecord{}, ErrInvalidEvidenceExecution
	}
	s := i.state
	k := s.key
	r := EvidenceRecord{IntentDigest: intentDigest(s.intent, k), ProofDigest: s.proof, KeyVersion: k.version, IssuedAt: issuedAt, ExpiresAt: s.expiresAt}
	nonce := base64.RawURLEncoding.EncodeToString(s.nonce[:])
	signature := evidenceSignature(k, r, nonce)
	r.Reference = RiskEvidenceRef{value: "re1." + strconv.FormatUint(uint64(k.version), 10) + "." + nonce + "." + base64.RawURLEncoding.EncodeToString(signature[:])}
	r.EvidenceDigest = evidenceMAC(k.digest, "identity-risk-evidence-lookup-v1", []string{s.intent.state.request.Recovery.Binding.Tenant, s.intent.state.purpose, r.Reference.value})
	return r, nil
}

// EvidenceExecution is a native coordinator outcome bound to one exact intent.
// Its constructor verifies retained bearer integrity, not database durability.
// Only the official durable executor may attest authoritative outcome classes.
type EvidenceExecution struct{ state *evidenceExecution }
type evidenceExecution struct {
	intent  EvidenceIntent
	outcome EvidenceOutcome
	record  EvidenceRecord
}

func (EvidenceExecution) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceExecution(redacted)")
}

// NewEvidenceExecution authenticates bounded recovered native data under the
// core's exact retained intent/key set. Noncommit classes require zero record.
// Committed historical records may be expired; replay conserves original times
// but neither this function nor a signature grants reservation/consumption.
func NewEvidenceExecution(i EvidenceIntent, outcome EvidenceOutcome, r EvidenceRecord) (EvidenceExecution, error) {
	if i.state == nil || outcome < EvidenceMissing || outcome > EvidenceCommitted || outcome != EvidenceCommitted && r != (EvidenceRecord{}) {
		return EvidenceExecution{}, ErrInvalidEvidenceExecution
	}
	if outcome == EvidenceCommitted && !validEvidenceRecord(i, r) {
		return EvidenceExecution{}, ErrInvalidEvidenceExecution
	}
	return EvidenceExecution{state: &evidenceExecution{intent: i, outcome: outcome, record: r}}, nil
}

// EvidenceExecutor is the narrow native shared-coordinator composition seam.
// It must be the platform's durable adapter, not a consumer-written store or a
// second command ledger. Resolve authorizes caller/request and reconciles the
// same command on primary before reporting Missing or terminal outcomes.
// Execute maps frozen issue proof to the existing immutable feature command,
// journals through its generation-bound Work and encrypts the original native
// response atomically with the committed receipt. Unknown returns no artifact;
// no method may infer noncommit from timeout or retry providers/issue commands.
// Every method honors bounded context, closes resources and supports concurrency.
type EvidenceExecutor interface {
	Resolve(context.Context, EvidenceIntent) (EvidenceExecution, error)
	Execute(context.Context, EvidenceIssue) (EvidenceExecution, error)
}

// PhoneEvidenceIssuerConfig is immutable startup composition. Full evaluation
// requires its sole velocity owner and the enabled carrier subset under the
// same risk-policy version. Timeout is positive <=1m and covers native resolution,
// all sources/counters and execution. Keys contain 1..16 unique versions and
// independent secrets; highest version issues, retained versions recover.
type PhoneEvidenceIssuerConfig struct {
	Evaluation Evaluator
	Carrier    CarrierEvaluator
	Clock      func() time.Time
	Timeout    time.Duration
	Keys       []EvidenceKey
	Executor   EvidenceExecutor
}

// PhoneEvidenceIssuer owns phone-only core issuance orchestration, not the
// complete canonical risk Service, lockouts, CAPTCHA, or consumption. It starts
// no goroutine and owns no transaction/store/command ledger. Safe for concurrent
// calls when injected owners are. Callers must already be authorized workflows.
type PhoneEvidenceIssuer struct{ state *phoneEvidenceIssuer }
type phoneEvidenceIssuer struct {
	evaluation Evaluator
	carrier    CarrierEvaluator
	clock      func() time.Time
	timeout    time.Duration
	keys       []EvidenceKey
	current    EvidenceKey
	executor   EvidenceExecutor
}

// NewPhoneEvidenceIssuer rejects incomplete/overlapping composition without IO.
func NewPhoneEvidenceIssuer(c PhoneEvidenceIssuerConfig) (PhoneEvidenceIssuer, error) {
	if c.Evaluation.state == nil || c.Evaluation.state.counters.state == nil || c.Carrier.state == nil || !c.Carrier.state.enabled || c.Evaluation.state.policy.state.version != c.Carrier.state.version || c.Clock == nil || c.Timeout <= 0 || c.Timeout > time.Minute || c.Evaluation.state.timeout > c.Timeout || c.Carrier.state.timeLimit > c.Timeout || c.Executor == nil || len(c.Keys) < 1 || len(c.Keys) > 16 {
		return PhoneEvidenceIssuer{}, ErrInvalidPolicy
	}
	s := &phoneEvidenceIssuer{evaluation: c.Evaluation, carrier: c.Carrier, clock: c.Clock, timeout: c.Timeout, executor: c.Executor, keys: append([]EvidenceKey(nil), c.Keys...)}
	// Only typed-nil rejection uses reflection, never dependency discovery/wiring.
	v := reflect.ValueOf(c.Executor)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return PhoneEvidenceIssuer{}, ErrInvalidPolicy
		}
	}
	for _, source := range s.evaluation.state.sources {
		if !scopeID(source.Version) || len(source.Version) > 64 {
			return PhoneEvidenceIssuer{}, ErrInvalidPolicy
		}
	}
	for n, k := range s.keys {
		if k.version == 0 || k.signing == ([32]byte{}) || k.digest == ([32]byte{}) || k.signing == k.digest {
			return PhoneEvidenceIssuer{}, ErrInvalidPolicy
		}
		for _, previous := range s.keys[:n] {
			if previous.version == k.version || previous.signing == k.signing || previous.digest == k.digest || previous.signing == k.digest || previous.digest == k.signing {
				return PhoneEvidenceIssuer{}, ErrInvalidPolicy
			}
		}
		if k.version > s.current.version {
			s.current = k
		}
	}
	return PhoneEvidenceIssuer{state: s}, nil
}

func (s PhoneEvidenceIssuer) intent(r PhoneEvidenceRequest, now time.Time) (EvidenceIntent, error) {
	if s.state == nil || !validTime(now) || !scopeID(r.Actor) || !validEvidenceCommandID(r.CommandID) {
		return EvidenceIntent{}, ErrInvalidEvidenceRequest
	}
	purpose, ok := carrierPurpose(r.Recovery, s.state.carrier.state.version)
	if !ok {
		return EvidenceIntent{}, ErrInvalidEvidenceRequest
	}
	b := r.Recovery.Binding
	c := Context{Tenant: b.Tenant, Operation: b.RecoveryOperation, Attempt: b.Attempt, Now: now}
	// Prepare is local structural/key validation, not a store read/mutation.
	if _, err := s.state.evaluation.state.counters.Prepare(c, r.Subject, BeforeCredential); err != nil {
		return EvidenceIntent{}, ErrInvalidEvidenceRequest
	}
	var configuration []string
	for _, name := range s.state.evaluation.state.policy.state.profiles[Authentication].RequiredSignals {
		configuration = append(configuration, name, s.state.evaluation.state.sources[name].Version)
	}
	for _, source := range s.state.carrier.state.sources {
		configuration = append(configuration, string(source.Kind), source.Version)
	}
	return EvidenceIntent{state: &evidenceIntent{keys: s.state.keys, configuration: configuration, request: r, purpose: purpose}}, nil
}

func validEvidenceCommandID(command string) bool {
	if len(command) != 22 {
		return false
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(command)
	if err != nil || len(id) != 16 || base64.RawURLEncoding.EncodeToString(id) != command {
		return false
	}
	var nonzero byte
	for _, value := range id {
		nonzero |= value
	}
	return nonzero != 0
}

// Evaluate resolves prior command state before any counters/providers; only a
// proven absent command starts evaluation. It runs the exact phase-owned parent
// operation profile (never an exemption for the matrix's risk.evaluate default),
// requires full allow plus fresh owned carrier negatives, then dispatches once.
// Failed/Unknown/Denied reveal nothing. Native errors are redacted and conserve
// Unknown; recovery must use the same request, never mint replacement evidence.
func (s PhoneEvidenceIssuer) Evaluate(ctx context.Context, r PhoneEvidenceRequest) (PhoneEvidenceResult, error) {
	if s.state == nil || ctx == nil {
		return PhoneEvidenceResult{}, ErrInvalidEvidenceRequest
	}
	if err := ctx.Err(); err != nil {
		return PhoneEvidenceResult{}, err
	}
	start := s.state.clock()
	intent, err := s.intent(r, start)
	if err != nil {
		return PhoneEvidenceResult{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.state.timeout)
	defer cancel()
	recovered, err := s.state.executor.Resolve(bounded, intent)
	if err != nil || bounded.Err() != nil || evaluationTime(s.state.clock(), start, start, s.state.timeout) != nil {
		return unknownEvidence()
	}
	result, err := executionResult(intent, recovered)
	if err != nil {
		return PhoneEvidenceResult{}, err
	}
	if result.Outcome != EvidenceMissing {
		return result, nil
	}
	if err := bounded.Err(); err != nil {
		return PhoneEvidenceResult{}, err
	}
	last := s.state.clock()
	if err := evaluationTime(last, start, start, s.state.timeout); err != nil {
		return PhoneEvidenceResult{}, err
	}
	b := r.Recovery.Binding
	evaluated, err := s.state.evaluation.Evaluate(bounded, EvaluateRequest{Context: Context{Tenant: b.Tenant, Operation: b.RecoveryOperation, Attempt: b.Attempt}, Phase: NonIssuing, Subject: r.Subject})
	if err != nil {
		return PhoneEvidenceResult{}, err
	}
	if evaluated.Decision.Action != Allow {
		return PhoneEvidenceResult{Outcome: EvidenceDenied}, nil
	}
	carrier, err := s.state.carrier.Assess(bounded, r.Recovery)
	if err != nil {
		return PhoneEvidenceResult{}, err
	}
	if err := bounded.Err(); err != nil {
		return PhoneEvidenceResult{}, err
	}
	now := s.state.clock()
	if err := evaluationTime(now, last, start, s.state.timeout); err != nil {
		return PhoneEvidenceResult{}, err
	}
	issue, err := s.prepareIssue(intent, evaluated, carrier, now)
	if err != nil {
		return PhoneEvidenceResult{Outcome: EvidenceDenied}, nil
	}
	executed, err := s.state.executor.Execute(bounded, issue)
	if err != nil || bounded.Err() != nil || evaluationTime(s.state.clock(), now, start, s.state.timeout) != nil {
		return unknownEvidence()
	}
	result, err = executionResult(intent, executed)
	if err != nil || result.Outcome == EvidenceMissing {
		return PhoneEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
	}
	if result.Outcome == EvidenceCommitted {
		record := executed.state.record
		if record.KeyVersion != s.state.current.version || record.ProofDigest != issue.state.proof || !record.ExpiresAt.Equal(issue.state.expiresAt) || record.IssuedAt.Before(issue.state.preparedAt) {
			// Another exact submission may have committed after our absence read.
			// Integrity alone cannot distinguish its original response from a
			// substituted fresh result: require primary-authorized resolution of
			// that same retained record, under the original total deadline.
			replayed, resolveErr := s.state.executor.Resolve(bounded, intent)
			if resolveErr != nil || bounded.Err() != nil || evaluationTime(s.state.clock(), now, start, s.state.timeout) != nil {
				return unknownEvidence()
			}
			original, replayErr := executionResult(intent, replayed)
			if replayErr != nil || original.Outcome != EvidenceCommitted || replayed.state.record != record {
				return PhoneEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
			}
			return original, nil
		}
	}
	return result, nil
}

// Recover only resolves/reconciles exact primary command state. It cannot run
// providers, increment counters or issue, including when the command is Missing.
func (s PhoneEvidenceIssuer) Recover(ctx context.Context, r PhoneEvidenceRequest) (PhoneEvidenceResult, error) {
	if s.state == nil || ctx == nil {
		return PhoneEvidenceResult{}, ErrInvalidEvidenceRequest
	}
	if err := ctx.Err(); err != nil {
		return PhoneEvidenceResult{}, err
	}
	start := s.state.clock()
	i, err := s.intent(r, start)
	if err != nil {
		return PhoneEvidenceResult{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.state.timeout)
	defer cancel()
	e, err := s.state.executor.Resolve(bounded, i)
	if err != nil || bounded.Err() != nil || evaluationTime(s.state.clock(), start, start, s.state.timeout) != nil {
		return unknownEvidence()
	}
	return executionResult(i, e)
}

func unknownEvidence() (PhoneEvidenceResult, error) {
	return PhoneEvidenceResult{Outcome: EvidenceUnknown}, ErrEvidenceUnavailable
}
func executionResult(i EvidenceIntent, e EvidenceExecution) (PhoneEvidenceResult, error) {
	if e.state == nil || e.state.intent.state != i.state {
		return PhoneEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
	}
	r := PhoneEvidenceResult{Outcome: e.state.outcome}
	if r.Outcome == EvidenceCommitted {
		v := e.state.record
		if !validEvidenceRecord(i, v) {
			return PhoneEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
		}
		r.Evidence = RiskEvidence{Reference: v.Reference, Purpose: i.state.purpose, IssuedAt: v.IssuedAt, ExpiresAt: v.ExpiresAt, MaxUses: 1}
	}
	return r, nil
}

func (s PhoneEvidenceIssuer) prepareIssue(i EvidenceIntent, e EvaluateResult, c CarrierAssessment, now time.Time) (EvidenceIssue, error) {
	p := e.provenance
	if p == nil || p.owner != s.state.evaluation.state || e.counter == nil || e.counter.Outcome != CounterCommitted || e.Decision.Action != Allow || c.Validate(s.state.carrier, i.state.request.Recovery, now) != nil || p.context.Now.After(now) {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	expires := c.state.metadata.ExpiresAt
	fields := []string{string(i.state.request.Recovery.Phase), i.state.purpose, e.counter.result.state.fingerprint}
	for _, signal := range p.signals {
		if signal.State != SignalClean || signal.Trust != ServerVerified || !signal.ExpiresAt.After(now) || signal.ObservedAt.After(now) {
			return EvidenceIssue{}, ErrInvalidEvidenceExecution
		}
		expires = earlierEvidenceExpiry(expires, signal.ExpiresAt)
		expires = earlierEvidenceExpiry(expires, signal.ObservedAt.Add(s.state.carrier.state.lifetime))
		fields = append(fields, signal.Name, s.state.evaluation.state.sources[signal.Name].Version, strconv.Itoa(int(signal.State)), strconv.Itoa(int(signal.Trust)), evidenceTime(signal.ObservedAt), evidenceTime(signal.ExpiresAt))
	}
	for _, fact := range c.state.facts {
		fields = append(fields, string(fact.Kind), strconv.Itoa(int(fact.State)), fact.ProviderVersion, evidenceTime(fact.ObservedAt), evidenceTime(fact.ExpiresAt))
	}
	// Bind exact complete post-mutation snapshots, not only the public decision.
	for _, counter := range e.counter.result.state.snapshot {
		fields = append(fields, string(counter.Kind), strconv.FormatUint(counter.Value, 10), evidenceTime(counter.ObservedAt), evidenceTime(counter.WindowStartedAt), evidenceTime(counter.WindowExpiresAt))
	}
	expires = expires.UTC().Truncate(time.Microsecond)
	if !expires.After(now) {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	preparedAt := now.UTC().Truncate(time.Microsecond)
	if preparedAt.Before(now) {
		preparedAt = preparedAt.Add(time.Microsecond)
	}
	if !preparedAt.Before(expires) {
		return EvidenceIssue{}, ErrInvalidEvidenceExecution
	}
	state := &evidenceIssue{intent: i, preparedAt: preparedAt, expiresAt: expires, proof: evidenceMAC(s.state.current.digest, "identity-risk-evidence-proof-v1", fields), key: s.state.current}
	_, _ = rand.Read(state.nonce[:])
	return EvidenceIssue{state: state}, nil
}

func earlierEvidenceExpiry(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func evidenceTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func databaseEvidenceTime(t time.Time) bool {
	return validTime(t) && t.Location() == time.UTC && t.Nanosecond()%1000 == 0
}
func intentDigest(i EvidenceIntent, k EvidenceKey) [32]byte {
	if i.state.native != nil {
		if i.state.native.KeyVersion == k.version {
			return i.state.native.IntentDigest
		}
		return [32]byte{}
	}
	r := i.state.request
	b := r.Recovery.Binding
	v := r.Subject
	fields := []string{r.CommandID, r.Actor, b.Tenant, b.Subject, string(b.RecoveryOperation), b.CanonicalNumber, b.PreAuthTransaction, b.Attempt, strconv.FormatUint(b.PolicyVersion, 10), string(r.Recovery.Phase), i.state.purpose, v.Network, v.Device, v.IdentifierDigest, v.User, v.Session, v.Actor, v.Resource}
	fields = append(fields, i.state.configuration...)
	return evidenceMAC(k.digest, "identity-risk-evidence-intent-v1", fields)
}
func evidenceMAC(key [32]byte, domain string, fields []string) [32]byte {
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write([]byte(domain))
	_, _ = m.Write([]byte{0})
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = m.Write(length[:])
		_, _ = m.Write([]byte(field))
	}
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}
func evidenceSignature(k EvidenceKey, r EvidenceRecord, nonce string) [32]byte {
	return evidenceMAC(k.signing, "identity-risk-evidence-bearer-v1", []string{strconv.FormatUint(uint64(r.KeyVersion), 10), base64.RawURLEncoding.EncodeToString(r.IntentDigest[:]), base64.RawURLEncoding.EncodeToString(r.ProofDigest[:]), evidenceTime(r.IssuedAt), evidenceTime(r.ExpiresAt), nonce})
}
func validEvidenceRecord(i EvidenceIntent, r EvidenceRecord) bool {
	if !databaseEvidenceTime(r.IssuedAt) || !databaseEvidenceTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 2*time.Minute || r.ProofDigest == ([32]byte{}) {
		return false
	}
	if _, err := ParseRiskEvidenceRef(r.Reference.value); err != nil {
		return false
	}
	var k EvidenceKey
	for _, candidate := range i.state.keys {
		if candidate.version == r.KeyVersion {
			k = candidate
			break
		}
	}
	if k.version == 0 || r.IntentDigest != intentDigest(i, k) {
		return false
	}
	parts := strings.Split(r.Reference.value, ".")
	if len(parts) != 4 || parts[0] != "re1" || parts[1] != strconv.FormatUint(uint64(k.version), 10) || len(parts[2]) != 43 || len(parts[3]) != 43 {
		return false
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(nonce) != 32 {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(sig) != 32 {
		return false
	}
	want := evidenceSignature(k, r, parts[2])
	if !hmac.Equal(sig, want[:]) {
		return false
	}
	digest := evidenceMAC(k.digest, "identity-risk-evidence-lookup-v1", []string{i.state.request.Recovery.Binding.Tenant, i.state.purpose, r.Reference.value})
	return hmac.Equal(r.EvidenceDigest[:], digest[:])
}
