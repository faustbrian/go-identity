package risk

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// CaptchaOutcome is a bounded normalized provider fact, never a risk decision.
// Zero and unknown values are malformed. No outcome grants protected authority.
type CaptchaOutcome uint8

const (
	CaptchaSolved CaptchaOutcome = iota + 1
	CaptchaRejected
	CaptchaUnavailable
	CaptchaMalformed
	CaptchaThrottled
	CaptchaCancelled
	CaptchaAmbiguous
	CaptchaUnsupported
	CaptchaBindingMismatch
)

// CaptchaString preserves absent versus present-empty provider fields.
// Unavailable must have an empty Value. Available values remain bounded facts.
type CaptchaString struct {
	Available bool
	Value     string
}

// CaptchaCapabilities is the exact selected provider API/version/tier contract.
// A later official adapter must establish these claims, not client input.
type CaptchaCapabilities struct {
	Hostname, Origin, Action, Score, ChallengeTime bool
}

// CaptchaEvidenceRequest is trusted server input, not transport authorization.
// CommandID is canonical nonzero 128-bit identity-command syntax. Flow carries
// the protected operation, not an exemption for identity.risk.captcha-verify.
type CaptchaEvidenceRequest struct {
	CommandID string
	Flow      FlowContext
}

// CaptchaVerificationRequest borrows Token for one bounded configured callback.
// The callback must not retain or mutate it. Flow/CommandID are immutable trusted
// scope. No authoritative replay fingerprint or risk decision is provided.
type CaptchaVerificationRequest struct {
	CommandID string
	Flow      FlowContext
	Token     []byte
}

// CaptchaObservation is the core's normalized projection from an official
// provider-neutral verifier, never public caller input. Exact profile and flow
// must match the configured request. ObservedAt is original verification read
// beginning, not retrieval/promotion time; ExpiresAt is original exclusive
// validity. Unsupported fields must remain unavailable, never fabricated.
// ReasonCodes are at most 32 safe 1..64-byte ASCII classifications, not error
// text. Provider-native closed-union details remain with the verifier; raw
// responses, cdata, remote address and tokens have no representation here.
type CaptchaObservation struct {
	Flow                                             FlowContext
	CommandID                                        string
	Provider, Site, APIProfile, ConfigurationVersion string
	API, Version, Tier                               string
	Outcome                                          CaptchaOutcome
	Hostname, Origin, Action                         CaptchaString
	ScoreAvailable                                   bool
	Score                                            float64
	ChallengeTime, ObservedAt, ExpiresAt             time.Time
	ReasonCodes                                      []string
}

// CaptchaEvidenceIssuerConfig is immutable startup composition, copied at New.
// Replay is the sole fingerprint owner. API/version/tier and capability claims
// are pinned independently; the official verifier must validate that profile.
// A hostname or origin binding is mandatory. Supported hostname/origin/action
// fields require exact configured values; unsupported fields forbid them.
// Hostnames are canonical lowercase ASCII DNS names; origins are canonical
// HTTPS scheme/authority only. No wildcard, Unicode, implicit normalization or
// localhost HTTP profile exists here. ScoreThreshold, when selected, requires
// score support and finite [0,1] values. Lifetime is explicit 1s..2m;
// ChallengeMaxAge is 1s..5m exactly when challenge time is supported. Timeout is
// 1s..15s and includes resolution, verification and dispatch. Callbacks/clock
// must honor context, own resources and support concurrent calls. No defaults.
// Keys are 1..16 retained independent EvidenceKey pairs; highest version issues.
type CaptchaEvidenceIssuerConfig struct {
	Replay                    CaptchaReplayPolicy
	API, Version, Tier        string
	Capabilities              CaptchaCapabilities
	Hostnames, Origins        []string
	ExpectedAction            string
	ScoreThreshold            *float64
	Lifetime, ChallengeMaxAge time.Duration
	Timeout                   time.Duration
	Clock                     func() time.Time
	Verify                    func(context.Context, CaptchaVerificationRequest) (CaptchaObservation, error)
	Keys                      []EvidenceKey
	Executor                  CaptchaEvidenceExecutor
}

// CaptchaEvidenceIssuer owns CAPTCHA issuance decisions through one injected
// native coordinator executor. It neither authenticates a flow nor executes
// protected mutations. It starts no goroutine, holds no callback lock and owns
// no store, transaction or private ledger. Safe concurrently when owners are.
// Zero is invalid. This is not the complete canonical risk/CAPTCHA Service.
type CaptchaEvidenceIssuer struct{ state *captchaEvidenceIssuerState }
type captchaEvidenceIssuerState struct {
	config  CaptchaEvidenceIssuerConfig
	current EvidenceKey
}

// NewCaptchaEvidenceIssuer rejects incomplete/contradictory composition without
// callbacks, clock reads or IO. All errors are redacted ErrInvalidPolicy.
func NewCaptchaEvidenceIssuer(c CaptchaEvidenceIssuerConfig) (CaptchaEvidenceIssuer, error) {
	if c.Replay.state == nil || !captchaASCII(c.API, 64) || !captchaASCII(c.Version, 32) || !captchaASCII(c.Tier, 32) || c.Clock == nil || c.Verify == nil || c.Executor == nil || c.Lifetime < time.Second || c.Lifetime > 2*time.Minute || c.Timeout < time.Second || c.Timeout > 15*time.Second || len(c.Keys) < 1 || len(c.Keys) > 16 || len(c.Hostnames) > 32 || len(c.Origins) > 32 || (!c.Capabilities.Hostname && !c.Capabilities.Origin) {
		return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
	}
	v := reflect.ValueOf(c.Executor)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
		}
	}
	if c.Capabilities.Hostname != (len(c.Hostnames) > 0) || c.Capabilities.Origin != (len(c.Origins) > 0) || c.Capabilities.Action != (c.ExpectedAction != "") || c.ExpectedAction != "" && !captchaASCII(c.ExpectedAction, 128) || c.Capabilities.ChallengeTime && (c.ChallengeMaxAge < time.Second || c.ChallengeMaxAge > 5*time.Minute) || !c.Capabilities.ChallengeTime && c.ChallengeMaxAge != 0 {
		return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
	}
	for n, host := range c.Hostnames {
		if !captchaHostname(host) || slices.Contains(c.Hostnames[:n], host) {
			return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
		}
	}
	for n, origin := range c.Origins {
		if !captchaOrigin(origin) || slices.Contains(c.Origins[:n], origin) {
			return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
		}
	}
	if c.ScoreThreshold != nil {
		if !c.Capabilities.Score || !captchaScore(*c.ScoreThreshold) {
			return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
		}
		threshold := *c.ScoreThreshold
		c.ScoreThreshold = &threshold
	}
	c.Keys, c.Hostnames, c.Origins = slices.Clone(c.Keys), slices.Clone(c.Hostnames), slices.Clone(c.Origins)
	s := &captchaEvidenceIssuerState{config: c}
	for n, key := range c.Keys {
		if key.version == 0 || key.signing == ([32]byte{}) || key.digest == ([32]byte{}) || key.signing == key.digest {
			return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
		}
		for _, old := range c.Keys[:n] {
			if old.version == key.version || old.signing == key.signing || old.digest == key.digest || old.signing == key.digest || old.digest == key.signing {
				return CaptchaEvidenceIssuer{}, ErrInvalidPolicy
			}
		}
		if key.version > s.current.version {
			s.current = key
		}
	}
	return CaptchaEvidenceIssuer{state: s}, nil
}

// CaptchaEvidenceIntent is immutable core preparation retaining no raw token.
// Only Prepare constructs it; zero/foreign owner is invalid. Copies are safe
// concurrent reads. It binds every retained replay alias and exact command,
// flow, policy and verifier configuration. Preparation grants no permission.
type CaptchaEvidenceIntent struct{ state *captchaEvidenceIntentState }
type captchaEvidenceIntentState struct {
	owner        *captchaEvidenceIssuerState
	request      CaptchaEvidenceRequest
	replay       CaptchaReplayIdentity
	tokenDigests map[uint32][32]byte
}

// CaptchaIntentBinding is copied native command/lookup metadata, never HTTP
// output. Replay aliases name one provider token. Native storage must acquire
// one winner across all aliases and retain unresolved/terminal tombstones.
// IntentDigest binds exact command scope independently of Replay.Keys.
type CaptchaIntentBinding struct {
	CommandID     string
	Replay        CaptchaReplayBinding
	PolicyVersion uint64
	KeyVersion    uint32
	IntentDigest  [32]byte
}

// Prepare derives replay identity from bounded unchanged token bytes inside
// the core. It performs no clock/provider/store work and does not retain token.
// Invalid request/token returns zero and stable redacted rejection.
func (s CaptchaEvidenceIssuer) Prepare(request CaptchaEvidenceRequest, token []byte) (CaptchaEvidenceIntent, error) {
	if s.state == nil || !validEvidenceCommandID(request.CommandID) {
		return CaptchaEvidenceIntent{}, ErrInvalidEvidenceRequest
	}
	r, err := s.state.config.Replay.Prepare(request.Flow, token)
	if err != nil {
		return CaptchaEvidenceIntent{}, ErrInvalidEvidenceRequest
	}
	digests := make(map[uint32][32]byte, len(s.state.config.Keys))
	for _, key := range s.state.config.Keys {
		digests[key.version] = evidenceMAC(key.digest, "identity-captcha-command-token-v1", []string{string(token)})
	}
	return CaptchaEvidenceIntent{state: &captchaEvidenceIntentState{owner: s.state, request: request, replay: r, tokenDigests: digests}}, nil
}

// Bindings returns independently owned native projections for every retained
// integrity/linkage version. Zero returns nil. Aliases are not new authority.
func (i CaptchaEvidenceIntent) Bindings() []CaptchaIntentBinding {
	if i.state == nil {
		return nil
	}
	s := i.state.owner
	bindings := make([]CaptchaIntentBinding, 0, len(s.config.Keys))
	for _, key := range s.config.Keys {
		bindings = append(bindings, CaptchaIntentBinding{CommandID: i.state.request.CommandID, Replay: i.state.replay.Bindings(), PolicyVersion: s.config.Replay.state.config.Policy.state.version, KeyVersion: key.version, IntentDigest: captchaIntentDigest(i, key)})
	}
	return bindings
}

func captchaIntentDigest(i CaptchaEvidenceIntent, key EvidenceKey) [32]byte {
	s, c := i.state, i.state.owner.config
	b, flow := s.replay.state.binding, s.request.Flow.state.input
	fields := []string{s.request.CommandID, string(flow.Kind), flow.Tenant, string(flow.Operation), flow.Subject, flow.AnonymousFlow, flow.PreAuthTransaction, flow.Session, flow.Actor, flow.ChallengeID, flow.RequestFingerprint, b.Provider, b.Site, b.APIProfile, b.ConfigurationVersion, c.API, c.Version, c.Tier, strconv.FormatUint(c.Replay.state.config.Policy.state.version, 10), c.ExpectedAction, strconv.FormatInt(int64(c.Lifetime), 10), strconv.FormatInt(int64(c.ChallengeMaxAge), 10), strconv.FormatBool(c.Capabilities.Hostname), strconv.FormatBool(c.Capabilities.Origin), strconv.FormatBool(c.Capabilities.Action), strconv.FormatBool(c.Capabilities.Score), strconv.FormatBool(c.Capabilities.ChallengeTime)}
	if c.ScoreThreshold == nil {
		fields = append(fields, "no-score-policy")
	} else {
		fields = append(fields, strconv.FormatFloat(*c.ScoreThreshold, 'g', -1, 64))
	}
	// Explicit section counts prevent cross-list boundary ambiguity.
	fields = append(fields, strconv.Itoa(len(c.Hostnames)))
	fields = append(fields, c.Hostnames...)
	fields = append(fields, strconv.Itoa(len(c.Origins)))
	fields = append(fields, c.Origins...)
	// Token commitment uses this independently retained intent key, not the
	// rotating replay-alias list. A new replay alias therefore preserves original
	// command recovery while a different token cannot reuse its command identity.
	tokenDigest := s.tokenDigests[key.version]
	fields = append(fields, base64.RawURLEncoding.EncodeToString(tokenDigest[:]))
	return evidenceMAC(key.digest, "identity-captcha-intent-v1", fields)
}

// CaptchaEvidenceRef is opaque bearer custody. Reveal is an explicit transfer
// only to the authorized response encoder/encrypted journal. Possession or parse
// never grants use: native reserve/apply/finalize and authorization are required.
type CaptchaEvidenceRef struct{ value string }

func (r CaptchaEvidenceRef) Reveal() string { return r.value }

// ParseCaptchaEvidenceRef bounds canonical ce1 syntax only, not authenticity.
func ParseCaptchaEvidenceRef(value string) (CaptchaEvidenceRef, error) {
	if len(value) < 93 || len(value) > 103 {
		return CaptchaEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "ce1" || len(parts[2]) != 43 || len(parts[3]) != 43 {
		return CaptchaEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	v, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || v == 0 || parts[1] != strconv.FormatUint(v, 10) {
		return CaptchaEvidenceRef{}, ErrInvalidEvidenceExecution
	}
	for _, part := range parts[2:] {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(decoded) != 32 {
			return CaptchaEvidenceRef{}, ErrInvalidEvidenceExecution
		}
	}
	return CaptchaEvidenceRef{value: value}, nil
}

// CaptchaEvidence exposes only proven-committed safe metadata. MaxUses is one;
// the immutable bearer is not proof of its current durable state or authority.
type CaptchaEvidence struct {
	Reference           CaptchaEvidenceRef
	Provider            string
	IssuedAt, ExpiresAt time.Time
	MaxUses             uint8
}

// CaptchaEvidenceResult has zero Evidence for every noncommitted outcome.
type CaptchaEvidenceResult struct {
	Outcome  EvidenceOutcome
	Evidence CaptchaEvidence
}

// CaptchaEvidenceRecord is native-only persistence projection. Reference must
// be encrypted before storage. Times are original database UTC microseconds.
// No raw provider facts, score, reason text, token or remote address survives.
type CaptchaEvidenceRecord struct {
	Reference                                 CaptchaEvidenceRef
	Hostname                                  string
	IntentDigest, ProofDigest, EvidenceDigest [32]byte
	KeyVersion                                uint32
	IssuedAt, ExpiresAt                       time.Time
}

// CaptchaEvidenceIssue is provisional successful core verification custody,
// never issued evidence. Native execution must atomically journal the eventual
// row/result through shared Work; no method consumes or renews source validity.
type CaptchaEvidenceIssue struct{ state *captchaEvidenceIssueState }
type captchaEvidenceIssueState struct {
	intent                CaptchaEvidenceIntent
	key                   EvidenceKey
	proof, nonce          [32]byte
	preparedAt, expiresAt time.Time
	hostname              string
}

// Intent returns original immutable request custody; zero returns zero.
func (i CaptchaEvidenceIssue) Intent() CaptchaEvidenceIntent {
	if i.state == nil {
		return CaptchaEvidenceIntent{}
	}
	return i.state.intent
}

// Materialize creates only a provisional database-time-bound candidate. The
// executor must journal it and the command result atomically before disclosure.
// Exact original exclusive expiry wins; equal primary time gives equal candidate.
func (i CaptchaEvidenceIssue) Materialize(now time.Time) (CaptchaEvidenceRecord, error) {
	if i.state == nil || !databaseEvidenceTime(now) || now.Before(i.state.preparedAt) || !now.Before(i.state.expiresAt) {
		return CaptchaEvidenceRecord{}, ErrInvalidEvidenceExecution
	}
	s := i.state
	r := CaptchaEvidenceRecord{IntentDigest: captchaIntentDigest(s.intent, s.key), Hostname: s.hostname, ProofDigest: s.proof, KeyVersion: s.key.version, IssuedAt: now, ExpiresAt: s.expiresAt}
	nonce := base64.RawURLEncoding.EncodeToString(s.nonce[:])
	sig := captchaSignature(s.key, r, nonce)
	r.Reference = CaptchaEvidenceRef{value: "ce1." + strconv.FormatUint(uint64(s.key.version), 10) + "." + nonce + "." + base64.RawURLEncoding.EncodeToString(sig[:])}
	r.EvidenceDigest = evidenceMAC(s.key.digest, "identity-captcha-lookup-v1", []string{s.intent.state.request.Flow.state.input.Tenant, r.Reference.value})
	return r, nil
}
func captchaSignature(k EvidenceKey, r CaptchaEvidenceRecord, nonce string) [32]byte {
	return evidenceMAC(k.signing, "identity-captcha-bearer-v1", []string{strconv.FormatUint(uint64(r.KeyVersion), 10), base64.RawURLEncoding.EncodeToString(r.IntentDigest[:]), base64.RawURLEncoding.EncodeToString(r.ProofDigest[:]), r.Hostname, evidenceTime(r.IssuedAt), evidenceTime(r.ExpiresAt), nonce})
}
func validCaptchaRecord(i CaptchaEvidenceIntent, r CaptchaEvidenceRecord) bool {
	if i.state == nil || !databaseEvidenceTime(r.IssuedAt) || !databaseEvidenceTime(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > i.state.owner.config.Lifetime || r.ProofDigest == ([32]byte{}) {
		return false
	}
	c := i.state.owner.config
	if c.Capabilities.Hostname && (!captchaHostname(r.Hostname) || !slices.Contains(c.Hostnames, r.Hostname)) || !c.Capabilities.Hostname && r.Hostname != "" {
		return false
	}
	if _, err := ParseCaptchaEvidenceRef(r.Reference.value); err != nil {
		return false
	}
	for _, key := range i.state.owner.config.Keys {
		if key.version != r.KeyVersion || r.IntentDigest != captchaIntentDigest(i, key) {
			continue
		}
		parts := strings.Split(r.Reference.value, ".")
		if parts[1] != strconv.FormatUint(uint64(key.version), 10) {
			return false
		}
		sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
		if err != nil {
			return false
		}
		want := captchaSignature(key, r, parts[2])
		lookup := evidenceMAC(key.digest, "identity-captcha-lookup-v1", []string{i.state.request.Flow.state.input.Tenant, r.Reference.value})
		return hmac.Equal(sig, want[:]) && hmac.Equal(r.EvidenceDigest[:], lookup[:])
	}
	return false
}

// CaptchaEvidenceExecution is an attested native outcome, not inferred commit.
// Its constructor checks integrity, not database existence or one-use state.
type CaptchaEvidenceExecution struct {
	state *captchaEvidenceExecutionState
}
type captchaEvidenceExecutionState struct {
	intent  CaptchaEvidenceIntent
	outcome EvidenceOutcome
	record  CaptchaEvidenceRecord
}

// NewCaptchaEvidenceExecution authenticates original records, including expired
// historical ones. Noncommitted classifications require an exactly zero record.
func NewCaptchaEvidenceExecution(i CaptchaEvidenceIntent, o EvidenceOutcome, r CaptchaEvidenceRecord) (CaptchaEvidenceExecution, error) {
	if i.state == nil || o < EvidenceMissing || o > EvidenceCommitted || o != EvidenceCommitted && r != (CaptchaEvidenceRecord{}) || o == EvidenceCommitted && !validCaptchaRecord(i, r) {
		return CaptchaEvidenceExecution{}, ErrInvalidEvidenceExecution
	}
	return CaptchaEvidenceExecution{state: &captchaEvidenceExecutionState{intent: i, outcome: o, record: r}}, nil
}

// CaptchaEvidenceExecutor is the official durable adapter's shared-coordinator
// seam, not application glue. Resolve authorizes/reconciles exact primary command
// before Missing or terminal claims. Execute acquires one replay-alias winner,
// rechecks original validity, and atomically journals evidence plus command result.
// Unknown discloses nothing and never permits provider/replacement retry. Each
// method honors bounded context, supports concurrency and owns cleanup. Native
// reserve/apply/finalize for later protected use are separate required behavior.
type CaptchaEvidenceExecutor interface {
	Resolve(context.Context, CaptchaEvidenceIntent) (CaptchaEvidenceExecution, error)
	Execute(context.Context, CaptchaEvidenceIssue) (CaptchaEvidenceExecution, error)
}

// Issue first resolves the prepared original command before provider work. Only
// proven Missing can verify the exact original raw token once. All non-solved,
// malformed, unsupported, mismatched, expired or below-threshold facts deny
// issuance. This is CAPTCHA-evidence admission, not full risk assessment: later
// protected evaluation owns all other signals and low-risk independent step-up.
// Errors from providers never become positive facts. Executor ambiguity or late
// acknowledgement returns Unknown with no bearer; use Recover, not a new intent.
func (s CaptchaEvidenceIssuer) Issue(ctx context.Context, i CaptchaEvidenceIntent, token []byte) (CaptchaEvidenceResult, error) {
	if ctx == nil || s.state == nil || i.state == nil || i.state.owner != s.state {
		return CaptchaEvidenceResult{}, ErrInvalidEvidenceRequest
	}
	if err := ctx.Err(); err != nil {
		return CaptchaEvidenceResult{}, err
	}
	// Re-derive through the original policy, never accept adapter fingerprints.
	replay, err := s.state.config.Replay.Prepare(i.state.request.Flow, token)
	if err != nil || !slices.Equal(replay.Bindings().Keys, i.state.replay.Bindings().Keys) {
		return CaptchaEvidenceResult{}, ErrInvalidEvidenceRequest
	}
	start := s.state.config.Clock()
	if !validTime(start) {
		return CaptchaEvidenceResult{}, ErrInvalidContext
	}
	bounded, cancel := context.WithTimeout(ctx, s.state.config.Timeout)
	defer cancel()
	recovered, err := s.state.config.Executor.Resolve(bounded, i)
	now := s.state.config.Clock()
	if err != nil || bounded.Err() != nil || evaluationTime(now, start, start, s.state.config.Timeout) != nil {
		return captchaUnknown()
	}
	result, err := captchaExecutionResult(i, recovered)
	if err != nil || result.Outcome != EvidenceMissing {
		return result, err
	}
	verifiedAt := now
	facts, verifyErr := s.state.config.Verify(bounded, CaptchaVerificationRequest{CommandID: i.state.request.CommandID, Flow: i.state.request.Flow, Token: token})
	now = s.state.config.Clock()
	if err := bounded.Err(); err != nil {
		return CaptchaEvidenceResult{Outcome: EvidenceDenied}, err
	}
	if err := evaluationTime(now, verifiedAt, start, s.state.config.Timeout); err != nil {
		return CaptchaEvidenceResult{Outcome: EvidenceDenied}, err
	}
	if verifyErr != nil {
		return CaptchaEvidenceResult{Outcome: EvidenceDenied}, nil
	}
	expires, ok := s.admitFacts(i, facts, verifiedAt, now)
	if !ok {
		return CaptchaEvidenceResult{Outcome: EvidenceDenied}, nil
	}
	preparedAt := now.UTC().Truncate(time.Microsecond)
	if preparedAt.Before(now) {
		preparedAt = preparedAt.Add(time.Microsecond)
	}
	expires = expires.UTC().Truncate(time.Microsecond)
	if !preparedAt.Before(expires) {
		return CaptchaEvidenceResult{Outcome: EvidenceDenied}, nil
	}
	state := &captchaEvidenceIssueState{intent: i, key: s.state.current, preparedAt: preparedAt, expiresAt: expires, proof: captchaProof(s.state.current, facts), hostname: facts.Hostname.Value}
	_, _ = rand.Read(state.nonce[:])
	issue := CaptchaEvidenceIssue{state: state}
	executed, err := s.state.config.Executor.Execute(bounded, issue)
	finished := s.state.config.Clock()
	if err != nil || bounded.Err() != nil || evaluationTime(finished, now, start, s.state.config.Timeout) != nil {
		return captchaUnknown()
	}
	result, err = captchaExecutionResult(i, executed)
	if err != nil || result.Outcome == EvidenceMissing {
		return CaptchaEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
	}
	if result.Outcome == EvidenceCommitted {
		r := executed.state.record
		candidate, materializeErr := issue.Materialize(r.IssuedAt)
		if materializeErr != nil || candidate != r {
			// Concurrent exact submission may have won after our absence read.
			// Require primary reconciliation of that exact historical record.
			replayed, resolveErr := s.state.config.Executor.Resolve(bounded, i)
			if resolveErr != nil || bounded.Err() != nil || evaluationTime(s.state.config.Clock(), finished, start, s.state.config.Timeout) != nil {
				return captchaUnknown()
			}
			original, replayErr := captchaExecutionResult(i, replayed)
			if replayErr != nil || original.Outcome != EvidenceCommitted || replayed.state.record != r {
				return CaptchaEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
			}
			return original, nil
		}
	}
	return result, nil
}

// Recover reconciles only exact prepared command custody. No raw token, provider
// verification or issuance is needed or permitted, even for a Missing result.
// Recovered times are conserved; historical expiry is not current-use authority.
func (s CaptchaEvidenceIssuer) Recover(ctx context.Context, i CaptchaEvidenceIntent) (CaptchaEvidenceResult, error) {
	if ctx == nil || s.state == nil || i.state == nil || i.state.owner != s.state {
		return CaptchaEvidenceResult{}, ErrInvalidEvidenceRequest
	}
	if err := ctx.Err(); err != nil {
		return CaptchaEvidenceResult{}, err
	}
	start := s.state.config.Clock()
	if !validTime(start) {
		return CaptchaEvidenceResult{}, ErrInvalidContext
	}
	bounded, cancel := context.WithTimeout(ctx, s.state.config.Timeout)
	defer cancel()
	e, err := s.state.config.Executor.Resolve(bounded, i)
	if err != nil || bounded.Err() != nil || evaluationTime(s.state.config.Clock(), start, start, s.state.config.Timeout) != nil {
		return captchaUnknown()
	}
	return captchaExecutionResult(i, e)
}
func captchaUnknown() (CaptchaEvidenceResult, error) {
	return CaptchaEvidenceResult{Outcome: EvidenceUnknown}, ErrEvidenceUnavailable
}
func captchaExecutionResult(i CaptchaEvidenceIntent, e CaptchaEvidenceExecution) (CaptchaEvidenceResult, error) {
	if e.state == nil || e.state.intent.state != i.state {
		return CaptchaEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
	}
	r := CaptchaEvidenceResult{Outcome: e.state.outcome}
	if r.Outcome == EvidenceCommitted {
		v := e.state.record
		if !validCaptchaRecord(i, v) {
			return CaptchaEvidenceResult{Outcome: EvidenceUnknown}, ErrInvalidEvidenceExecution
		}
		r.Evidence = CaptchaEvidence{Reference: v.Reference, Provider: i.state.replay.state.binding.Provider, IssuedAt: v.IssuedAt, ExpiresAt: v.ExpiresAt, MaxUses: 1}
	}
	return r, nil
}

func (s CaptchaEvidenceIssuer) admitFacts(i CaptchaEvidenceIntent, f CaptchaObservation, verifiedAt, now time.Time) (time.Time, bool) {
	c, b := s.state.config, i.state.replay.state.binding
	if f.Flow.state == nil || f.Flow.state.input != b.Flow || f.CommandID != i.state.request.CommandID || f.Provider != b.Provider || f.Site != b.Site || f.APIProfile != b.APIProfile || f.ConfigurationVersion != b.ConfigurationVersion || f.API != c.API || f.Version != c.Version || f.Tier != c.Tier || f.Outcome != CaptchaSolved || len(f.ReasonCodes) > 32 {
		return time.Time{}, false
	}
	for _, reason := range f.ReasonCodes {
		if !captchaASCII(reason, 64) {
			return time.Time{}, false
		}
	}
	if !captchaField(f.Hostname, c.Capabilities.Hostname, 253) || !captchaField(f.Origin, c.Capabilities.Origin, 512) || !captchaField(f.Action, c.Capabilities.Action, 128) || c.Capabilities.Hostname && (!captchaHostname(f.Hostname.Value) || !slices.Contains(c.Hostnames, f.Hostname.Value)) || c.Capabilities.Origin && (!captchaOrigin(f.Origin.Value) || !slices.Contains(c.Origins, f.Origin.Value)) || c.Capabilities.Action && f.Action.Value != c.ExpectedAction || f.ScoreAvailable != c.Capabilities.Score || !captchaScore(f.Score) || !f.ScoreAvailable && f.Score != 0 || c.ScoreThreshold != nil && f.Score < *c.ScoreThreshold {
		return time.Time{}, false
	}
	if !validTime(f.ObservedAt) || !validTime(f.ExpiresAt) || f.ObservedAt.After(now) || !f.ExpiresAt.After(f.ObservedAt) || f.ExpiresAt.Sub(f.ObservedAt) > c.Lifetime || !now.Before(f.ExpiresAt) {
		return time.Time{}, false
	}
	// The callback cannot renew validity by reporting completion as its read
	// beginning. Preserve earlier provider expiry while independently capping
	// the interval at the core-owned invocation horizon.
	expires := earlierEvidenceExpiry(f.ExpiresAt, verifiedAt.Add(c.Lifetime))
	if c.Capabilities.ChallengeTime {
		if !validTime(f.ChallengeTime) || f.ChallengeTime.After(f.ObservedAt) || !now.Before(f.ChallengeTime.Add(c.ChallengeMaxAge)) {
			return time.Time{}, false
		}
		expires = earlierEvidenceExpiry(expires, f.ChallengeTime.Add(c.ChallengeMaxAge))
	} else if !f.ChallengeTime.IsZero() {
		return time.Time{}, false
	}
	return expires, true
}
func captchaProof(k EvidenceKey, f CaptchaObservation) [32]byte {
	fields := []string{f.Provider, f.Site, f.APIProfile, f.ConfigurationVersion, f.API, f.Version, f.Tier, strconv.Itoa(int(f.Outcome)), strconv.FormatBool(f.Hostname.Available), f.Hostname.Value, strconv.FormatBool(f.Origin.Available), f.Origin.Value, strconv.FormatBool(f.Action.Available), f.Action.Value, strconv.FormatBool(f.ScoreAvailable), strconv.FormatFloat(f.Score, 'g', -1, 64), evidenceTime(f.ChallengeTime), evidenceTime(f.ObservedAt), evidenceTime(f.ExpiresAt)}
	fields = append(fields, f.ReasonCodes...)
	return evidenceMAC(k.digest, "identity-captcha-proof-v1", fields)
}
func captchaASCII(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func captchaField(s CaptchaString, supported bool, max int) bool {
	if !supported {
		return !s.Available && s.Value == ""
	}
	return s.Available && captchaASCII(s.Value, max)
}
func captchaScore(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1 }
func captchaHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}
func captchaOrigin(s string) bool {
	if !captchaASCII(s, 512) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || !captchaHostname(u.Hostname()) || u.Host != u.Hostname() && u.Port() == "" {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || n == 443 || port != strconv.FormatUint(n, 10) {
			return false
		}
	}
	return u.String() == s
}

// All correlated runtime/native values refuse implicit custody export.
func (CaptchaString) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaString(redacted)")
}
func (CaptchaString) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaString) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceRequest(redacted)")
}
func (CaptchaEvidenceRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaVerificationRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaVerificationRequest(redacted)")
}
func (CaptchaVerificationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CaptchaVerificationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CaptchaObservation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaObservation(redacted)")
}
func (CaptchaObservation) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaObservation) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIssuerConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceIssuerConfig(redacted)")
}
func (CaptchaEvidenceIssuerConfig) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CaptchaEvidenceIssuerConfig) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (CaptchaEvidenceIssuer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceIssuer(redacted)")
}
func (CaptchaEvidenceIssuer) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIssuer) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceIntent(redacted)")
}
func (CaptchaEvidenceIntent) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIntent) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaIntentBinding) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaIntentBinding(redacted)")
}
func (CaptchaIntentBinding) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaIntentBinding) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRef) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceRef(redacted)")
}
func (CaptchaEvidenceRef) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRef) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidence(redacted)")
}
func (CaptchaEvidence) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidence) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceResult(redacted)")
}
func (CaptchaEvidenceResult) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceResult) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceRecord(redacted)")
}
func (CaptchaEvidenceRecord) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceRecord) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIssue) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceIssue(redacted)")
}
func (CaptchaEvidenceIssue) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceIssue) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceExecution) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.CaptchaEvidenceExecution(redacted)")
}
func (CaptchaEvidenceExecution) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CaptchaEvidenceExecution) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
