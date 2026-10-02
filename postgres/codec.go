package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"slices"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
)

// prepareClaim is the coordinator-owned identity-command-v1 mapping. It never
// serializes Command through JSON/reflection and is not an authority issuer.
// Directory IDs preserve their validated representation (including ULIDs);
// only the core fixed-width random CommandID is decoded to bytes.
// Every current closed core variant is mapped; invalid commands fail closed.
func prepareClaim(c identity.Command, key [32]byte) (claimRequest, error) {
	if key == ([32]byte{}) {
		return claimRequest{}, codecError()
	}
	var binding identity.CommandBinding
	payload := map[string][]byte{}
	var attrs []identity.AttributeUpdate
	attributeCommand := false
	switch {
	case isCreation(c):
		s, _ := c.CreateUser()
		binding = s.Binding
		attrs = s.Attributes
		attributeCommand = true
		payload["status"] = cborText(string(s.Status))
	case isUpdate(c):
		s, _ := c.UpdateUser()
		binding = s.Binding
		attrs = s.Attributes
		attributeCommand = true
		payload["expected_version"] = cborUint(s.ExpectedVersion)
	case isProfile(c):
		s, _ := c.UpdateProfile()
		binding = s.Binding
		attrs = s.AdditionalFields
		attributeCommand = true
		payload["expected_version"] = cborUint(s.ExpectedVersion)
		for name, value := range map[string]string{"name": s.Name, "image": s.Image} {
			if value != "" {
				digest, e := commandSecret(key, "profile."+name, []byte(value), 4096)
				if e != nil {
					return claimRequest{}, e
				}
				payload[name] = cborBytes(digest)
			}
		}
	case isStatus(c):
		s, _ := c.UserStatus()
		binding = s.Binding
		payload["expected_version"] = cborUint(s.ExpectedVersion)
		payload["expected_authority_version"] = cborUint(s.ExpectedAuthorityVersion)
		payload["status_policy_version"] = cborUint(s.StatusPolicyVersion)
		payload["target_status"] = cborText(string(s.TargetStatus))
		if s.Reason != "" {
			payload["reason"] = cborText(s.Reason)
		}
		if !s.ExpiresAt.IsZero() {
			payload["expires_at"] = cborInt(s.ExpiresAt.UnixMicro())
		}
		consumers := s.RequiredConsumers()
		items := make([][]byte, len(consumers))
		for i, v := range consumers {
			items[i] = cborText(v)
		}
		payload["required_consumers"] = cborArray(items)
	case isLink(c):
		s, _ := c.LinkAccount()
		binding = s.Binding
		var err error
		payload, err = encodeLink(s, key)
		if err != nil {
			return claimRequest{}, err
		}
	case isUnlink(c):
		s, _ := c.UnlinkAccount()
		binding = s.Binding
		var err error
		payload, err = encodeUnlink(s, key)
		if err != nil {
			return claimRequest{}, err
		}
	case isIdentifier(c):
		s, _ := c.ChangeIdentifier()
		binding = s.Binding
		var err error
		payload, err = encodeIdentifier(s, key)
		if err != nil {
			return claimRequest{}, err
		}
	case isFeature(c):
		s, _ := c.Feature()
		binding = s.Binding
		var err error
		payload, err = encodeFeature(s, key)
		if err != nil {
			return claimRequest{}, err
		}
	default:
		return claimRequest{}, codecError()
	}
	fields := map[string][]byte{}
	for _, a := range attrs {
		value, e := encodeAttribute(a.Value)
		if e != nil {
			return claimRequest{}, e
		}
		// Commands do not carry schema sensitivity metadata. Conservatively digest
		// every attribute; safe collision fields never persist private values.
		digest, e := commandSecret(key, "attributes."+a.Name, value, 1<<19)
		if e != nil {
			return claimRequest{}, e
		}
		fields[a.Name] = cborBytes(digest)
	}
	if attributeCommand {
		payload["attributes"] = cborMap(fields)
	}
	scope := commandScope(binding)
	safe := cborMap(scope)
	scope["payload"] = cborMap(payload)
	canonical := cborMap(scope)
	if len(canonical) > 1<<20 || len(safe) > 65536 {
		return claimRequest{}, codecError()
	}
	return claimRequest{commandID: binding.CommandID, tenant: binding.TenantID, purpose: binding.OperationID, canonical: canonical, safeFields: safe, source: &c}, nil
}

func isCreation(c identity.Command) bool   { _, ok := c.CreateUser(); return ok }
func isUpdate(c identity.Command) bool     { _, ok := c.UpdateUser(); return ok }
func isProfile(c identity.Command) bool    { _, ok := c.UpdateProfile(); return ok }
func isStatus(c identity.Command) bool     { _, ok := c.UserStatus(); return ok }
func isLink(c identity.Command) bool       { _, ok := c.LinkAccount(); return ok }
func isUnlink(c identity.Command) bool     { _, ok := c.UnlinkAccount(); return ok }
func isIdentifier(c identity.Command) bool { _, ok := c.ChangeIdentifier(); return ok }
func isFeature(c identity.Command) bool    { _, ok := c.Feature(); return ok }

func commandScope(b identity.CommandBinding) map[string][]byte {
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	scope := map[string][]byte{
		"profile": cborText("identity-command-v1"), "command_id": cborBytes(id),
		"tenant_id": cborText(string(b.TenantID)), "user_id": cborText(string(b.UserID)),
		"actor_id": cborText(string(b.ActorID)), "actor_kind": cborText(string(b.ActorKind)),
		"purpose": cborText(b.OperationID), "policy_id": cborText(b.PolicyID),
		"policy_version": cborUint(b.PolicyVersion), "schema_id": cborText(b.SchemaID),
		"schema_version": cborUint(uint64(b.SchemaVersion)), "correlation_id": cborText(b.CorrelationID),
	}
	if b.RecordID != "" {
		scope["record_id"] = cborText(b.RecordID)
	}
	if b.LinkMode != 0 {
		scope["link_mode"] = cborUint(uint64(b.LinkMode))
	}
	return scope
}

func encodeAttribute(v identity.AttributeValue) ([]byte, error) {
	var value []byte
	if v.Kind == identity.AttributeStringList {
		items := make([][]byte, len(v.List))
		for i, s := range v.List {
			items[i] = cborText(s.String)
		}
		value = cborArray(items)
	} else {
		switch v.Kind {
		case identity.AttributeString:
			value = cborText(v.Scalar.String)
		case identity.AttributeBool:
			value = []byte{0xf4}
			if v.Scalar.Bool {
				value[0] = 0xf5
			}
		case identity.AttributeInt64:
			value = cborInt(v.Scalar.Int64)
		case identity.AttributeTime:
			if !postgresExactTime(v.Scalar.Time) {
				return nil, codecError()
			}
			value = cborInt(v.Scalar.Time.UnixMicro())
		default:
			return nil, codecError()
		}
	}
	return cborMap(map[string][]byte{"kind": cborText(string(v.Kind)), "value": value}), nil
}

func postgresExactTime(t time.Time) bool {
	// The persisted instant is UTC; checking the supplied display-zone year
	// would admit out-of-range instants and reject equivalent valid ones.
	year := t.UTC().Year()
	return !t.IsZero() && year >= 1 && year <= 9999 && t.Nanosecond()%1000 == 0
}

func commandSecret(key [32]byte, path string, secret []byte, bound int) ([]byte, error) {
	if key == ([32]byte{}) || len(path) == 0 || len(path) > 4096 || !utf8.ValidString(path) || bound < 0 || bound > 1<<20 || len(secret) > bound {
		return nil, codecError()
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-command-secret-v1"))
	var lengths [8]byte
	binary.BigEndian.PutUint32(lengths[:4], uint32(len(path)))
	_, _ = mac.Write(lengths[:4])
	_, _ = mac.Write([]byte(path))
	binary.BigEndian.PutUint64(lengths[:], uint64(len(secret)))
	_, _ = mac.Write(lengths[:])
	_, _ = mac.Write(secret)
	return mac.Sum(nil), nil
}

func codecError() error { return identity.InvalidInputError{Field: "command_encoding"} }

// These closed encoders only consume bounded constructor-validated core values.
// No generic untrusted CBOR parser, tags, floats or indefinite items are exposed.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 255:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 65535:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	case n <= 4294967295:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	default:
		return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
	}
}
func cborUint(n uint64) []byte { return cborHead(0, n) }
func cborInt(n int64) []byte {
	if n >= 0 {
		return cborUint(uint64(n))
	}
	return cborHead(1, uint64(-(n + 1)))
}
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }
func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborArray(values [][]byte) []byte {
	out := cborHead(4, uint64(len(values)))
	for _, v := range values {
		out = append(out, v...)
	}
	return out
}
func cborMap(values map[string][]byte) []byte {
	type entry struct{ key, value []byte }
	entries := make([]entry, 0, len(values))
	for k, v := range values {
		entries = append(entries, entry{cborText(k), v})
	}
	slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.key, b.key) })
	out := cborHead(5, uint64(len(entries)))
	for _, e := range entries {
		out = append(out, e.key...)
		out = append(out, e.value...)
	}
	return out
}
