package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

var (
	// ErrInvalidConfiguration rejects absent or unsafe native custody policy.
	ErrInvalidConfiguration = errors.New("otp postgres: invalid configuration")
	// ErrInvalidCommand rejects unsupported or changed private command custody.
	// It contains no code, destination, keys or private correlation fields.
	ErrInvalidCommand = errors.New("otp postgres: invalid command")
	// ErrUnavailable means local custody encryption could not finish. No provider
	// diagnostics or partial command output are retained.
	ErrUnavailable = errors.New("otp postgres: unavailable")
)

// AttemptCodecConfig is trusted secret-boundary configuration, not wire input.
// WrappingKeys contains 1..8 nonzero AES-256 keys under stable 1..128 ASCII
// alphanumeric/-/_ references. CurrentWrappingKey must be retained. AttemptKeys
// contains 1..8 positive versions/nonzero keys for the original core issuer;
// CodeKeys/CurrentCodeKeyVersion follow otp.NewVerifier's retained-key policy.
// MaximumDuration is 1ms..5s. Keys are copied; changing a referenced key's bytes
// is not rotation. Retain original keys while dependent command history needs
// them. No service, provider, entropy reader or callback can be injected.
type AttemptCodecConfig struct {
	WrappingKeys          map[string][]byte
	CurrentWrappingKey    string
	AttemptKeys           map[uint32][32]byte
	CodeKeys              map[uint32][32]byte
	CurrentCodeKeyVersion uint32
	MaximumDuration       time.Duration
}

// Format redacts configuration for every formatting verb.
func (AttemptCodecConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.postgres.AttemptCodecConfig(redacted)")
}

// MarshalJSON denies serialization of secret configuration.
func (AttemptCodecConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies serialization of secret configuration.
func (AttemptCodecConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// AttemptCodec owns the native original-command envelope profile. It maps
// existing core server-attempt custody; it neither prepares a new attempt nor
// verifies a stored challenge. Immutable copied local keyrings make concurrent
// use safe and exclude network/provider callbacks from coordinator validation.
// It owns no store, goroutine or resource. Zero/nil is invalid. Its private
// restoration is consumed by the forthcoming native participant implementation.
type AttemptCodec struct {
	crypto          *envelope.Service
	current         string
	issuers         map[uint32]otp.AttemptIssuer
	verifier        otp.Verifier
	maximumDuration time.Duration
	codeVersions    []uint32
	configuration   [32]byte
}

// Format redacts custody keys for every formatting verb, including nil receivers.
func (*AttemptCodec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.postgres.AttemptCodec(redacted)")
}

// MarshalJSON denies serialization of custody keys.
func (*AttemptCodec) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies serialization of custody keys.
func (*AttemptCodec) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// NewAttemptCodec validates and copies configuration without IO. Local owned
// envelope/keyring implementations are fixed, not consumer-written encryption.
// Invalid configuration returns ErrInvalidConfiguration with no retained cause.
func NewAttemptCodec(config AttemptCodecConfig) (*AttemptCodec, error) {
	if len(config.WrappingKeys) < 1 || len(config.WrappingKeys) > 8 || len(config.AttemptKeys) < 1 || len(config.AttemptKeys) > 8 ||
		config.MaximumDuration < time.Millisecond || config.MaximumDuration > 5*time.Second {
		return nil, ErrInvalidConfiguration
	}
	if _, ok := config.WrappingKeys[config.CurrentWrappingKey]; !ok {
		return nil, ErrInvalidConfiguration
	}
	for ref, key := range config.WrappingKeys {
		if len(ref) < 1 || len(ref) > 128 || len(key) != 32 {
			return nil, ErrInvalidConfiguration
		}
		var nonzero byte
		for _, b := range key {
			nonzero |= b
		}
		if nonzero == 0 {
			return nil, ErrInvalidConfiguration
		}
		for i := range len(ref) {
			b := ref[i]
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
				return nil, ErrInvalidConfiguration
			}
		}
	}
	issuers := make(map[uint32]otp.AttemptIssuer, len(config.AttemptKeys))
	for version, key := range config.AttemptKeys {
		i, err := otp.NewAttemptIssuer(version, key)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
		issuers[version] = i
	}
	verifier, err := otp.NewVerifier(config.CurrentCodeKeyVersion, config.CodeKeys)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	p, err := keyring.New(config.WrappingKeys)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	crypto, err := envelope.NewService(p)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	versions := make([]uint32, 0, len(config.CodeKeys))
	for version := range config.CodeKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	// Original owner selection must bind all retained custody, not only the
	// active version. Hash a bounded private frame and erase its copied keys.
	frame := []byte("identity-otp-codec-configuration-v1\x00")
	frame = appendAuthorityText(frame, config.CurrentWrappingKey)
	frame = binary.BigEndian.AppendUint32(frame, config.CurrentCodeKeyVersion)
	frame = binary.BigEndian.AppendUint64(frame, uint64(config.MaximumDuration))
	wrapping := make([]string, 0, len(config.WrappingKeys))
	for name := range config.WrappingKeys {
		wrapping = append(wrapping, name)
	}
	slices.Sort(wrapping)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(wrapping)))
	for _, name := range wrapping {
		frame = appendAuthorityText(frame, name)
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(config.WrappingKeys[name])))
		frame = append(frame, config.WrappingKeys[name]...)
	}
	for _, keys := range []map[uint32][32]byte{config.AttemptKeys, config.CodeKeys} {
		selected := make([]uint32, 0, len(keys))
		for version := range keys {
			selected = append(selected, version)
		}
		slices.Sort(selected)
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(selected)))
		for _, version := range selected {
			frame = binary.BigEndian.AppendUint32(frame, version)
			key := keys[version]
			frame = append(frame, key[:]...)
			clear(key[:])
		}
	}
	configuration := sha256.Sum256(frame)
	clear(frame)
	return &AttemptCodec{crypto: crypto, current: strings.Clone(config.CurrentWrappingKey), issuers: issuers, verifier: verifier, maximumDuration: config.MaximumDuration, codeVersions: versions, configuration: configuration}, nil
}

// Map appends the reserved native OTP custody fields to the owning feature's
// exact structural scope and other fields. Attempt must be an original sealed
// command-bound core submission. DigestKeyVersion selects the challenge's exact
// retained code-digest version; no fallback to the current version occurs.
// Private destination/flow/remember data is locally encrypted; raw code never
// enters the persisted metadata or ciphertext, remaining only opaque root
// custody. Mapping grants no challenge check, reservation, permission or proof.
//
// Map once per logical server submission and retain the returned immutable
// command/plan through retries: re-encrypting produces different ciphertext and
// therefore different command intent. After ambiguity recover the original
// command, never generate/remap a replacement attempt. Discard code custody on
// terminal outcomes. Inputs must not be mutated concurrently. No SQL, external
// provider, caller callback, goroutine or local retry runs. Earlier context
// deadlines win; local crypto/OS entropy cannot be interrupted mid-call, but
// deadline/cancellation is checked before and after and never returns late
// success. Invalid input returns zero outputs and ErrInvalidCommand.
func (c *AttemptCodec) Map(ctx context.Context, a otp.AttemptCommand, digestKeyVersion uint32, spec identity.FeatureCommandSpec) (identity.Command, identitypostgres.OTPAttemptPlan, error) {
	return c.mapAttempt(ctx, a, digestKeyVersion, spec, nil)
}

func (c *AttemptCodec) mapAttempt(ctx context.Context, a otp.AttemptCommand, digestKeyVersion uint32, spec identity.FeatureCommandSpec, authority *AttemptAuthority) (identity.Command, identitypostgres.OTPAttemptPlan, error) {
	fail := func(err error) (identity.Command, identitypostgres.OTPAttemptPlan, error) {
		return identity.Command{}, identitypostgres.OTPAttemptPlan{}, err
	}
	if c == nil || c.crypto == nil || ctx == nil || len(spec.Fields) > 126 {
		return fail(ErrInvalidCommand)
	}
	bounded, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return fail(err)
	}
	b, err := a.Bindings()
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	i, ok := c.issuers[b.FingerprintKeyVersion]
	if !ok {
		return fail(ErrInvalidCommand)
	}
	record, err := i.SealForCommand(a)
	if err != nil || record.Binding != spec.Binding || record.Operation != spec.Operation {
		return fail(ErrInvalidCommand)
	}
	plan, err := c.recordPlan(record, digestKeyVersion)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	fields := make([]identity.FeatureField, 0, len(spec.Fields)+2)
	for _, f := range spec.Fields {
		if otpField(f.Name) {
			return fail(ErrInvalidCommand)
		}
		fields = append(fields, f)
	}
	aad, err := attemptAAD(spec, digestKeyVersion)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	plaintext := encodeAttemptRecord(record)
	if authority != nil {
		if authority.validate(spec.Binding) != nil {
			clear(plaintext)
			return fail(ErrInvalidCommand)
		}
		original := plaintext
		plaintext = encodeAuthorityRecord(original, *authority)
		clear(original)
	}
	defer clear(plaintext)
	encrypted, err := c.crypto.Encrypt(bounded, envelope.EncryptRequest{Plaintext: plaintext, KeyReference: c.current, Context: aad})
	if err != nil {
		return fail(custodyFailure(bounded))
	}
	wire, err := encrypted.MarshalBinary()
	if err != nil || len(wire) > 8192 {
		return fail(ErrUnavailable)
	}
	fields = append(fields, identity.FeatureField{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}, identity.FeatureField{Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(digestKeyVersion)}})
	spec.Fields = fields
	code, err := a.Code()
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	command, err := identity.NewFeatureOneTimeCodeCommand(spec, code)
	if err != nil {
		return fail(ErrInvalidCommand)
	}
	if err := bounded.Err(); err != nil {
		return fail(err)
	}
	return command, plan, nil
}

func otpField(name string) bool { return name == "otp" || strings.HasPrefix(name, "otp.") }
func custodyFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

func (c *AttemptCodec) recordPlan(r otp.CommandAttemptRecord, keyVersion uint32) (identitypostgres.OTPAttemptPlan, error) {
	scope, err := r.Attempt.Continuation.DigestScope()
	if err != nil {
		return identitypostgres.OTPAttemptPlan{}, ErrInvalidCommand
	}
	digest, err := c.verifier.ScopeDigest(scope, keyVersion)
	if err != nil {
		return identitypostgres.OTPAttemptPlan{}, ErrInvalidCommand
	}
	b, err := r.Attempt.Continuation.Bindings()
	if err != nil {
		return identitypostgres.OTPAttemptPlan{}, ErrInvalidCommand
	}
	fp, err := base64.RawURLEncoding.Strict().DecodeString(string(r.Attempt.Fingerprint))
	if err != nil || len(fp) != 32 {
		return identitypostgres.OTPAttemptPlan{}, ErrInvalidCommand
	}
	return identitypostgres.OTPAttemptPlan{AttemptID: string(r.Attempt.AttemptID), AttemptFingerprint: [32]byte(fp), FingerprintKeyVersion: r.Attempt.FingerprintKeyVersion,
		ChallengeID: b.Scope.ChallengeID, ScopeDigest: digest.Value, DigestKeyVersion: keyVersion, ExpectedVersion: r.Attempt.ExpectedVersion, Mode: identitypostgres.OTPAttemptMode(r.Attempt.Mode)}, nil
}

// Private fixed-local restoration is bounded even where the coordinator's pure
// validation callback supplies no context. It never invokes a caller provider,
// regenerates custody, or compares a stored challenge. Domain phases use only
// restoreRecord; counted phases additionally borrow the original opaque code.
func (c *AttemptCodec) restoreRecord(spec identity.FeatureCommandSpec) (otp.CommandAttemptRecord, error) {
	value, err := c.restoreCustody(spec)
	return value.record, err
}

type nativeCustody struct {
	record    otp.CommandAttemptRecord
	authority *AttemptAuthority
}

func (c *AttemptCodec) restoreCustody(spec identity.FeatureCommandSpec) (nativeCustody, error) {
	if c == nil || c.crypto == nil || spec.Binding.ValidateFor(spec.Operation) != nil || len(spec.Fields) > 128 {
		return nativeCustody{}, ErrInvalidCommand
	}
	var wire []byte
	var version uint32
	var found int
	for _, f := range spec.Fields {
		if !otpField(f.Name) {
			continue
		}
		switch f.Name {
		case "otp.attempt-custody":
			if wire != nil || f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) == 0 || len(f.Value.Bytes) > 8192 {
				return nativeCustody{}, ErrInvalidCommand
			}
			wire = f.Value.Bytes
			found++
		case "otp.digest-key-version":
			if version != 0 || f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || f.Value.Uint64 > uint64(^uint32(0)) {
				return nativeCustody{}, ErrInvalidCommand
			}
			version = uint32(f.Value.Uint64)
			found++
		default:
			return nativeCustody{}, ErrInvalidCommand
		}
	}
	if found != 2 {
		return nativeCustody{}, ErrInvalidCommand
	}
	aad, err := attemptAAD(spec, version)
	if err != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	e, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(context.Background(), c.maximumDuration)
	defer stop()
	plain, err := c.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: e, Context: aad})
	if err != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	defer clear(plain)
	data, authority, err := decodeAuthorityRecord(plain, spec.Binding)
	if err != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	r, err := decodeAttemptRecord(data, spec.Binding, spec.Operation)
	if err != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	i, ok := c.issuers[r.Attempt.FingerprintKeyVersion]
	if !ok || i.VerifyCommandRecord(r) != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	if _, err := c.recordPlan(r, version); err != nil || ctx.Err() != nil {
		return nativeCustody{}, ErrInvalidCommand
	}
	return nativeCustody{record: r, authority: authority}, nil
}

func (c *AttemptCodec) restoreAttempt(command identity.Command, plan identitypostgres.OTPAttemptPlan) (otp.AttemptCommand, error) {
	s, ok := command.Feature()
	if !ok {
		return otp.AttemptCommand{}, ErrInvalidCommand
	}
	r, err := c.restoreRecord(s)
	if err != nil {
		return otp.AttemptCommand{}, ErrInvalidCommand
	}
	// restoreRecord authenticated the unique named version in this exact spec.
	// Derive the expected plan from that custody, never from caller plan fields:
	// substituting both version and digest must not reinterpret the command.
	var version uint32
	for _, f := range s.Fields {
		if f.Name == "otp.digest-key-version" {
			version = uint32(f.Value.Uint64)
		}
	}
	want, err := c.recordPlan(r, version)
	if err != nil || want != plan {
		return otp.AttemptCommand{}, ErrInvalidCommand
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return otp.AttemptCommand{}, ErrInvalidCommand
	}
	a, err := c.issuers[r.Attempt.FingerprintKeyVersion].RestoreForCommand(r, code)
	if err != nil {
		return otp.AttemptCommand{}, ErrInvalidCommand
	}
	return a, nil
}

func attemptAAD(s identity.FeatureCommandSpec, version uint32) (envelope.Context, error) {
	return commandCustodyAAD(s, version, "identity-otp-command-envelope-binding-v1\x00", "identity-otp-command-custody-v1")
}

func commandCustodyAAD(s identity.FeatureCommandSpec, version uint32, domain, profile string) (envelope.Context, error) {
	if s.Binding.ValidateFor(s.Operation) != nil || version == 0 {
		return envelope.Context{}, ErrInvalidCommand
	}
	b, d := s.Binding, s.Operation
	frame := []byte(domain)
	for _, v := range []string{string(b.CommandID), string(b.TenantID), string(b.UserID), b.AnonymousFlowID, string(b.ActorID), string(b.ActorKind), b.OperationID, b.PolicyID, b.SchemaID, b.CorrelationID, b.RecordID, d.Owner, d.OperationID, d.SchemaID} {
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(v)))
		frame = append(frame, v...)
	}
	frame = binary.BigEndian.AppendUint64(frame, b.PolicyVersion)
	frame = binary.BigEndian.AppendUint32(frame, b.SchemaVersion)
	frame = append(frame, byte(b.LinkMode))
	frame = binary.BigEndian.AppendUint32(frame, d.SchemaVersion)
	frame = append(frame, byte(d.RecordRequirement), byte(d.SubjectRequirement))
	frame = binary.BigEndian.AppendUint32(frame, version)
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": profile, "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
