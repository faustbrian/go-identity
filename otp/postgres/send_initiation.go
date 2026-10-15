package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maximumSendInitiation = 16384
const sendInitiationPrefix = "identity-otp-initiation-v1\x00"

// Authentication-lane dimensions are frozen before any assessment. Attempt is
// the original server-issued command ID, not a newly allocated submission ID.
// IdentifierDigest is the owner's domain-bound HMAC of canonical destination;
// this structural record cannot establish trusted-proxy/device provenance.
type sendInitiationRisk struct{ network, device, identifierDigest string }

func (sendInitiationRisk) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendInitiationRisk(redacted)"))
}

type sendInitiationCustody struct {
	original        identity.Command
	request         sendRequestRecord
	binding         identity.CommandBinding
	risk            sendInitiationRisk
	attempt         string
	suppressed      bool
	retainedBinding kernel.RequestKeyPreparationBinding
	retainedWire    []byte
}

func (sendInitiationCustody) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.sendInitiation(redacted)"))
}

func validInitiationRisk(r sendInitiationRisk) bool {
	address, err := netip.ParseAddr(r.network)
	if err != nil || address.Zone() != "" || address.String() != r.network || !initiationText(r.device, 128) || len(r.identifierDigest) != 64 {
		return false
	}
	for _, c := range []byte(r.identifierDigest) {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func initiationText(s string, max int) bool {
	if len(s) < 1 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// Full kernel provenance and native immutable configuration are authenticated.
// No timestamp is synthesized here, and no bearer enters envelope AAD/data.
func (p *Contributor) sendInitiationAAD(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	f := b.Feature
	if p == nil || p.send == nil || p.codec == nil || f.Contributor != p.Descriptor() || f.Operation != issuanceOperation(f.Operation.SubjectRequirement) || b.Scope.RouteID != f.Operation.OperationID || b.Scope.Method != "POST" || b.Admission.FingerprintKeyVersion == 0 || b.PolicyVersion == 0 || b.IntentDigest == ([32]byte{}) || !initiationText(b.Namespace, 128) || !initiationText(string(b.Scope.TenantID), 128) || !initiationText(string(b.Scope.ActorID), 128) {
		return envelope.Context{}, ErrInvalidCommand
	}
	if _, err := identity.ParseCommandID(string(b.Admission.CommandID)); err != nil {
		return envelope.Context{}, ErrInvalidCommand
	}
	if b.Scope.ActorKind != "user" && b.Scope.ActorKind != "api-key" && b.Scope.ActorKind != "service-account" {
		return envelope.Context{}, ErrInvalidCommand
	}
	frame := []byte(sendInitiationPrefix)
	for _, s := range []string{b.Namespace, string(b.Scope.TenantID), string(b.Scope.ActorID), string(b.Scope.ActorKind), b.Scope.Method, b.Scope.RouteID, string(b.Admission.CommandID), f.Contributor.Owner, f.Contributor.ContractID, f.Operation.Owner, f.Operation.OperationID, f.Operation.SchemaID} {
		frame = appendAuthorityText(frame, s)
	}
	for _, v := range []uint32{b.Admission.FingerprintKeyVersion, f.Contributor.Version, f.Operation.SchemaVersion} {
		frame = binary.BigEndian.AppendUint32(frame, v)
	}
	frame = append(frame, byte(f.Operation.RecordRequirement), byte(f.Operation.SubjectRequirement))
	frame = binary.BigEndian.AppendUint64(frame, b.PolicyVersion)
	frame = append(frame, b.IntentDigest[:]...)
	frame = append(frame, p.send.configuration[:]...)
	if p.initiation != nil {
		frame = append(frame, p.initiation.configuration[:]...)
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-otp-initiation-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func initiationBindingMatches(b identity.CommandBinding, k kernel.RequestKeyPreparationBinding) bool {
	return b.ValidateFor(k.Feature.Operation) == nil && b.CommandID == k.Admission.CommandID && b.TenantID == k.Scope.TenantID && b.ActorID == k.Scope.ActorID && b.ActorKind == k.Scope.ActorKind && b.OperationID == k.Scope.RouteID
}

func appendInitiationBinding(out []byte, b identity.CommandBinding) []byte {
	for _, s := range []string{string(b.CommandID), string(b.TenantID), string(b.UserID), b.AnonymousFlowID, string(b.ActorID), string(b.ActorKind), b.OperationID, b.PolicyID, b.SchemaID, b.CorrelationID, b.RecordID} {
		out = appendAuthorityText(out, s)
	}
	out = binary.BigEndian.AppendUint64(out, b.PolicyVersion)
	out = binary.BigEndian.AppendUint32(out, b.SchemaVersion)
	return append(out, byte(b.LinkMode))
}

func readInitiationBinding(r *recordReader) identity.CommandBinding {
	b := identity.CommandBinding{CommandID: identity.CommandID(r.text(128)), TenantID: identity.TenantID(r.text(128)), UserID: identity.UserID(r.text(128)), AnonymousFlowID: r.text(128), ActorID: identity.ActorID(r.text(128)), ActorKind: ""}
	b.ActorKind = authorization.SubjectKind(r.text(128))
	b.OperationID, b.PolicyID, b.SchemaID, b.CorrelationID, b.RecordID = r.text(128), r.text(128), r.text(128), r.text(128), r.text(128)
	b.PolicyVersion, b.SchemaVersion, b.LinkMode = r.u64(), r.u32(), identity.AccountLinkMode(r.u8())
	return b
}

func encodeSendInitiation(request sendRequestRecord, b identity.CommandBinding, risk sendInitiationRisk, suppressed bool) ([]byte, error) {
	if !validInitiationRisk(risk) || suppressed && request.recipient != nil || !suppressed && request.recipient == nil {
		return nil, ErrInvalidCommand
	}
	record, err := encodeSendRequestRecord(request, b)
	if err != nil {
		return nil, err
	}
	defer clear(record)
	out := appendInitiationBinding([]byte(sendInitiationPrefix), b)
	if suppressed {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	for _, s := range []string{risk.network, risk.device, risk.identifierDigest, string(record)} {
		out = appendAuthorityText(out, s)
	}
	if len(out) > maximumSendInitiation {
		clear(out)
		return nil, ErrInvalidCommand
	}
	return out, nil
}

func decodeSendInitiation(wire []byte, k kernel.RequestKeyPreparationBinding) (sendInitiationCustody, error) {
	bad := func() (sendInitiationCustody, error) { return sendInitiationCustody{}, ErrInvalidCommand }
	if len(wire) > maximumSendInitiation || !bytes.HasPrefix(wire, []byte(sendInitiationPrefix)) {
		return bad()
	}
	r := recordReader{data: wire[len(sendInitiationPrefix):], ok: true}
	b := readInitiationBinding(&r)
	tag := r.u8()
	if tag > 1 || !initiationBindingMatches(b, k) {
		return bad()
	}
	risk := sendInitiationRisk{network: r.text(45), device: r.text(128), identifierDigest: r.text(64)}
	data := []byte(r.text(8192))
	defer clear(data)
	if !r.ok || len(r.data) != 0 || !validInitiationRisk(risk) {
		return bad()
	}
	request, err := decodeSendRequestRecord(data, b)
	if err != nil || tag == 1 && request.recipient != nil || tag == 0 && request.recipient == nil {
		return bad()
	}
	return sendInitiationCustody{request: request, binding: b, risk: risk, attempt: string(k.Admission.CommandID), suppressed: tag == 1}, nil
}

func (p *Contributor) sealSendInitiation(parent context.Context, b kernel.RequestKeyPreparationBinding, original identity.Command, risk sendInitiationRisk, suppressed bool) ([]byte, error) {
	if parent == nil || p == nil || p.codec == nil || p.codec.crypto == nil {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(parent, p.codec.maximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aad, err := p.sendInitiationAAD(b)
	if err != nil {
		return nil, err
	}
	request, _, err := p.originalPreparedSend(ctx, original)
	if err != nil {
		return nil, err
	}
	spec, _ := original.Feature()
	if !initiationBindingMatches(spec.Binding, b) {
		return nil, ErrInvalidCommand
	}
	return p.sealSendInitiationRecord(ctx, aad, request, spec.Binding, risk, suppressed)
}

// Request-key preparation has structural primary input, not a raw bearer.
// Keep its encryption path separate from authenticated command restoration.
func (p *Contributor) sealSendInitiationRecord(ctx context.Context, aad envelope.Context, request sendRequestRecord, binding identity.CommandBinding, risk sendInitiationRisk, suppressed bool) ([]byte, error) {
	plain, err := encodeSendInitiation(request, binding, risk, suppressed)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	encrypted, err := p.codec.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.codec.current, Context: aad})
	if err != nil {
		return nil, custodyFailure(ctx)
	}
	wire, err := encrypted.MarshalBinary()
	if err != nil || len(wire) > maximumSendInitiation || ctx.Err() != nil {
		return nil, custodyFailure(ctx)
	}
	return wire, nil
}

func (p *Contributor) restoreSendInitiation(parent context.Context, b kernel.RequestKeyPreparationBinding, wire []byte, bearer auth.BearerCredential) (sendInitiationCustody, error) {
	bad := func(err error) (sendInitiationCustody, error) { return sendInitiationCustody{}, err }
	if parent == nil || p == nil || p.codec == nil || p.codec.crypto == nil || len(wire) == 0 || len(wire) > maximumSendInitiation {
		return bad(ErrInvalidCommand)
	}
	ctx, stop := context.WithTimeout(parent, p.codec.maximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	aad, err := p.sendInitiationAAD(b)
	if err != nil {
		return bad(err)
	}
	encrypted, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	plain, err := p.codec.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: encrypted, Context: aad})
	if err != nil {
		return bad(custodyFailure(ctx))
	}
	defer clear(plain)
	input, err := decodeSendInitiation(plain, b)
	if err != nil {
		return bad(err)
	}
	command, err := p.mapPreparedSendRequest(ctx, input.request, input.binding, bearer)
	if err != nil {
		return bad(err)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	// A suppressed original never becomes an executable issuance command, even
	// if that destination subsequently appears in the directory. The separately
	// authenticated flow and risk input remain available to its no-op owner.
	if !input.suppressed {
		input.original = command
	}
	input.retainedBinding = b
	input.retainedWire = bytes.Clone(wire)
	return input, nil
}
