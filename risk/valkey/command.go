package valkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

// Layout is private until the native journal/epoch admission path can construct
// an executable store. A projected plan never grants mutation or health truth.
type commandLayout struct {
	namespace string
	secret    []byte
	policy    risk.Policy
	keys      []risk.CounterDigestKey
	replay    risk.VelocityReplayIdentity
}

type commandPlan struct {
	slot, fingerprint, epoch string
	keys                     []string
	targets                  []risk.CounterTarget
	window                   time.Duration
	limit                    uint64
	policyVersion            uint64
}

func (commandLayout) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.commandLayout(redacted)")
}
func (commandPlan) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "valkey.commandPlan(redacted)")
}
func (commandLayout) MarshalJSON() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (commandLayout) MarshalText() ([]byte, error) { return nil, risk.ErrSensitiveSerialization }
func (commandPlan) MarshalJSON() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }
func (commandPlan) MarshalText() ([]byte, error)   { return nil, risk.ErrSensitiveSerialization }

func newCommandLayout(namespace string, secret []byte, policy risk.Policy, keys []risk.CounterDigestKey) (commandLayout, error) {
	if len(keys) < 1 || len(keys) > 4 {
		return commandLayout{}, risk.ErrInvalidPolicy
	}
	replay, err := risk.NewVelocityReplayIdentity(namespace, secret)
	if err != nil {
		return commandLayout{}, err
	}
	if _, err := policy.Admit("identity.otp.send"); err != nil {
		return commandLayout{}, risk.ErrInvalidPolicy
	}
	for i, key := range keys {
		if key.Version() == 0 || i > 0 && keys[i-1].Version() <= key.Version() {
			return commandLayout{}, risk.ErrInvalidPolicy
		}
	}
	return commandLayout{namespace: namespace, secret: slices.Clone(secret), policy: policy, keys: slices.Clone(keys), replay: replay}, nil
}

func (l commandLayout) prepare(command risk.CounterCommand, epoch [16]byte) (commandPlan, error) {
	if !boundedScope(l.namespace) || len(l.secret) < 32 || epoch == [16]byte{} {
		return commandPlan{}, risk.ErrInvalidCounterCommand
	}
	if err := command.ValidateConfiguration(l.policy, l.keys); err != nil {
		return commandPlan{}, err
	}
	b := command.Bindings()
	if !boundedScope(b.Tenant) || !boundedScope(b.Attempt) || len(b.Operation) == 0 || len(b.Operation) > 128 || b.Window <= 0 || b.Window > time.Hour || b.Window%time.Microsecond != 0 || b.Limit == 0 || b.Limit > 120 || !lowerHex(b.Fingerprint, 64) || b.PolicyVersion == 0 {
		return commandPlan{}, risk.ErrInvalidCounterCommand
	}
	a, err := l.policy.Admit(b.Operation)
	if err != nil || a.PolicyVersion != b.PolicyVersion || b.Phase != a.Profile.Phase || b.Phase == risk.ReserveWithCommand || b.Window != a.Profile.Window || b.Limit != a.Profile.Limit || len(b.Targets) != len(a.Profile.Dimensions) || len(b.Targets) > 4 {
		return commandPlan{}, risk.ErrInvalidCounterCommand
	}
	for i, target := range b.Targets {
		if target.Dimension != a.Profile.Dimensions[i] || len(target.Keys) != len(l.keys) {
			return commandPlan{}, risk.ErrInvalidCounterCommand
		}
		for rank, key := range target.Keys {
			if key.Version != l.keys[rank].Version() {
				return commandPlan{}, risk.ErrInvalidCounterCommand
			}
		}
	}
	digest, err := l.replay.Attempt(command)
	if err != nil {
		return commandPlan{}, err
	}
	return l.plan(b, epoch, digest)
}

// plan only addresses bounded original facts. Callers establish either live
// command custody or authenticated history; it cannot mint either authority.
func (l commandLayout) plan(b risk.CounterBinding, epoch [16]byte, digest [32]byte) (commandPlan, error) {
	// All four dimensions share one tenant partition. Hashing by dimension
	// would make a clustered multi-dimension decision inherently non-atomic.
	// Namespace key custody is independent of rotating dimension digest keys.
	slot := l.digest("identity-risk-valkey-slot-v1", b.Tenant)
	// The former private layout's raw-attempt MAC cannot be reconstructed from
	// authenticated journal history. Its health markers must not enable this
	// shared-identity layout; activation still requires owned recovery.
	base := "irv2:{" + slot + "}:"
	epochText := hex.EncodeToString(epoch[:])
	replay := hex.EncodeToString(digest[:])
	p := commandPlan{slot: slot, epoch: epochText, fingerprint: b.Fingerprint, window: b.Window, limit: b.Limit, policyVersion: b.PolicyVersion, targets: b.Targets, keys: []string{base + "health", base + epochText + ":replay:" + replay}}
	// The freshly encoded HMAC guarantees hexadecimal syntax. Fixed bounded
	// probes avoid a growing index and give each reservation atomic expiry.
	seed, _ := strconv.ParseUint(replay[:4], 16, 16)
	for i := uint64(0); i < capacityProbeCount; i++ {
		p.keys = append(p.keys, base+epochText+":capacity:"+strconv.FormatUint((seed+i)%maximumReplayEntries, 10))
	}
	seen := make(map[string]bool, len(b.Targets)*len(l.keys))
	for _, target := range b.Targets {
		if len(target.Keys) < 1 || len(target.Keys) > 4 {
			return commandPlan{}, risk.ErrInvalidCounterCommand
		}
		for _, key := range target.Keys {
			if !validCounterKey(key) || seen[key.Encoded] {
				return commandPlan{}, risk.ErrInvalidCounterCommand
			}
			seen[key.Encoded] = true
			p.keys = append(p.keys, base+epochText+":counter:"+key.Encoded)
		}
	}
	return p, nil
}

func (l commandLayout) digest(domain string, fields ...string) string {
	m := hmac.New(sha256.New, l.secret)
	for _, field := range append([]string{domain, l.namespace}, fields...) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = m.Write(size[:])
		_, _ = io.WriteString(m, field)
	}
	return hex.EncodeToString(m.Sum(nil))
}

func validCounterKey(key risk.CounterKey) bool {
	if key.Version == 0 || len(key.Encoded) > 64 {
		return false
	}
	prefix := "rv1:" + strconv.FormatUint(uint64(key.Version), 10) + ":"
	tail, ok := strings.CutPrefix(key.Encoded, prefix)
	if !ok || len(tail) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(tail)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == tail
}

func boundedScope(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, b := range []byte(value) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

func lowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, b := range []byte(value) {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}
