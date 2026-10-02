package postgres

import (
	"bytes"
	"encoding/base64"
	"math"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// decodeCommandScope reconstructs historical metadata, never authority or
// caller-selected policy. The closed grammar shares the bounded scalar reader
// and requires the existing encoder's exact bytes; no alternate durable scope
// or newly normalized identifier is accepted.
func decodeCommandScope(encoded []byte) (identity.CommandBinding, error) {
	invalid := func() (identity.CommandBinding, error) {
		return identity.CommandBinding{}, identity.UnavailableError{}
	}
	if len(encoded) == 0 || len(encoded) > 65536 {
		return invalid()
	}
	r := attributeReader{data: encoded}
	count, ok := r.head(5)
	if !ok || count < 12 || count > 14 {
		return invalid()
	}
	var binding identity.CommandBinding
	seen := make(map[string]bool, int(count))
	for range count {
		key, ok := r.text(16)
		if !ok || seen[key] {
			return invalid()
		}
		seen[key] = true
		switch key {
		case "command_id":
			if !r.exact(2, 16) || len(r.data) < 16 {
				return invalid()
			}
			binding.CommandID = identity.CommandID(base64.RawURLEncoding.EncodeToString(r.data[:16]))
			r.data = r.data[16:]
		case "policy_version", "schema_version", "link_mode":
			value, ok := r.head(0)
			if !ok {
				return invalid()
			}
			switch key {
			case "policy_version":
				binding.PolicyVersion = value
			case "schema_version":
				if value > math.MaxUint32 {
					return invalid()
				}
				binding.SchemaVersion = uint32(value)
			case "link_mode":
				if value < uint64(identity.AccountLinkExplicit) || value > uint64(identity.AccountLinkAdministrative) {
					return invalid()
				}
				binding.LinkMode = identity.AccountLinkMode(value)
			}
		default:
			value, ok := r.text(128)
			if !ok {
				return invalid()
			}
			switch key {
			case "profile":
				if value != "identity-command-v1" {
					return invalid()
				}
			case "tenant_id":
				binding.TenantID = identity.TenantID(value)
			case "user_id":
				binding.UserID = identity.UserID(value)
			case "actor_id":
				binding.ActorID = identity.ActorID(value)
			case "actor_kind":
				binding.ActorKind = authorization.SubjectKind(value)
			case "purpose":
				binding.OperationID = value
			case "policy_id":
				binding.PolicyID = value
			case "schema_id":
				binding.SchemaID = value
			case "correlation_id":
				binding.CorrelationID = value
			case "record_id":
				binding.RecordID = value
			default:
				return invalid()
			}
		}
	}
	probe := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeNotCommitted}
	if len(r.data) != 0 || probe.Validate() != nil || !bytes.Equal(encoded, cborMap(commandScope(binding))) {
		return invalid()
	}
	return binding, nil
}
