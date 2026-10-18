package passwordpostgres

import (
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

const actionPrimaryRecordPrefix = "password.action-primary.record."

// Use the existing closed scalar vocabulary, not an arbitrary JSON/blob field.
// RFC3339Nano text preserves signed proof instants that predate the command's
// microsecond-only time scalar, without truncating their signature inputs.
func actionPrimaryRecordFields(record auth.SignedReauthenticationRecord) ([]identity.FeatureField, error) {
	wire, err := encodeReauthenticationRecord(record)
	clear(wire)
	if err != nil {
		return nil, err
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: actionPrimaryRecordPrefix + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: actionPrimaryRecordPrefix + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	p := record.Proof.Proof
	return []identity.FeatureField{
		text("issuer", record.Issuer), text("environment", record.Environment),
		number("proof-version", record.ProofVersion), text("credential-id", record.CredentialID), number("credential-version", record.CredentialVersion),
		text("key-id", record.KeyID), {Name: actionPrimaryRecordPrefix + "signature", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(record.Signature)}},
		text("proof-id", string(p.ID)), text("tenant", p.Tenant), text("subject", p.Subject), text("method", p.Method), number("assurance", uint64(p.Assurance)),
		text("purpose", string(p.Purpose)), text("audience", p.Audience), text("issued-at", p.IssuedAt.UTC().Format(time.RFC3339Nano)), text("expires-at", p.ExpiresAt.UTC().Format(time.RFC3339Nano)),
		text("session-id", record.Proof.SessionID), number("session-version", record.Proof.SessionVersion), text("action", record.Proof.Action),
	}, nil
}

func actionPrimaryRecord(fields []identity.FeatureField) (auth.SignedReauthenticationRecord, error) {
	bad := func() (auth.SignedReauthenticationRecord, error) {
		return auth.SignedReauthenticationRecord{}, password.ErrPasswordWork
	}
	if len(fields) == 0 || len(fields) > 128 {
		return bad()
	}
	seen := make(map[string]bool, len(fields))
	values := make(map[string]identity.FeatureValue, 19)
	for _, field := range fields {
		if len(field.Name) > 128 || seen[field.Name] {
			return bad()
		}
		seen[field.Name] = true
		if strings.HasPrefix(field.Name, actionPrimaryRecordPrefix) {
			if len(field.Value.Text) > 1024 || len(field.Value.Bytes) > 64 {
				return bad()
			}
			values[strings.TrimPrefix(field.Name, actionPrimaryRecordPrefix)] = field.Value
		}
	}
	if len(values) != 19 {
		return bad()
	}
	issued, err := time.Parse(time.RFC3339Nano, values["issued-at"].Text)
	if err != nil {
		return bad()
	}
	expires, err := time.Parse(time.RFC3339Nano, values["expires-at"].Text)
	if err != nil {
		return bad()
	}
	record := auth.SignedReauthenticationRecord{
		Issuer: values["issuer"].Text, Environment: values["environment"].Text, ProofVersion: values["proof-version"].Uint64,
		CredentialID: values["credential-id"].Text, CredentialVersion: values["credential-version"].Uint64, KeyID: values["key-id"].Text, Signature: slices.Clone(values["signature"].Bytes),
		Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: auth.ProofID(values["proof-id"].Text), Tenant: values["tenant"].Text, Subject: values["subject"].Text, Method: values["method"].Text, Assurance: auth.Assurance(values["assurance"].Uint64), Purpose: auth.Purpose(values["purpose"].Text), Audience: values["audience"].Text, IssuedAt: issued, ExpiresAt: expires}, SessionID: values["session-id"].Text, SessionVersion: values["session-version"].Uint64, Action: values["action"].Text},
	}
	expected, err := actionPrimaryRecordFields(record)
	if err != nil {
		return bad()
	}
	for _, field := range expected {
		actual, ok := values[strings.TrimPrefix(field.Name, actionPrimaryRecordPrefix)]
		if !ok || !reflect.DeepEqual(actual, field.Value) {
			return bad()
		}
	}
	return record, nil
}
