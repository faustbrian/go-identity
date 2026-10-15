package magiclinkpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Exact original binding/generation/configuration can be recovered from the
// sole journal. The full command is retained inside authenticated ciphertext;
// no email, primary bearer, browser cookie or input digest is needed for AAD.
func requestOriginOutputAAD(b identity.CommandBinding, generation uint64, profile [32]byte) (envelope.Context, error) {
	if b.ValidateFor(requestOperation()) != nil || generation == 0 || profile == ([32]byte{}) {
		return envelope.Context{}, invalid()
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{b, generation, profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, invalid()
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-magic-link-request-origin-output-v2", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// MFAMagicLinkPrimary is authenticated historical request metadata, not current
// account authority, a factor proof or a session. Recipient is the exact
// original selected address/versions; protected completion must fence it against
// primary authority. Authentication preserves the original primary time and
// exclusive parent expiry, never the time this projection was read. Copies own
// scalar metadata and immutable session bindings; do not mutate borrowed input.
type MFAMagicLinkPrimary struct {
	Recipient      kernel.RecipientRecord
	Authentication session.MagicLinkAuthentication
}

// ReadMFAMagicLinkPrimary reconstructs original magic-link metadata after the
// capability owner has authenticated its consumed parent through the original
// MFA child. flow must be restored original browser custody; authenticatedAt
// must be the authenticated stored continuation's original primary admission
// time, never request data or this read's clock. Caller is trusted native
// transport/result-access context. This seam is not a public lookup endpoint.
//
// Current history-access policy precedes reads/decryption of the existing
// committed request preparation. The owner reconstructs every original signed
// payload field and compares its full canonical digest against opaque parent
// custody. It does not restore old risk admission as new permission, decrypt a
// bearer, generate or transfer credentials, mutate state, consume, renew or run
// a sender. Final completion must authenticate original cookie possession and
// repeat current account/recipient/factor/policy/child checks in its protected
// transaction; a projection is not an execution ticket.
//
// Concurrent calls borrow the pool and immutable service configuration. One
// MaximumDuration and the earlier caller deadline bound policy, indexed journal
// reads and local decryption. Zero/foreign scope denies; missing/legacy origin
// ciphertext or unavailable storage fails closed without reconstructing intent
// from a digest. Cancellation retains its classification. Every failure returns
// zero metadata; errors and diagnostics expose no correlated or credential data.
func (s *RequestService) ReadMFAMagicLinkPrimary(ctx context.Context, parent issuerpg.MFAMagicLinkParent, flow session.PreAuthTransaction, authenticatedAt time.Time, caller authorization.DecisionContext) (out MFAMagicLinkPrimary, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.pool.Raw() == nil || s.crypto == nil || authenticatedAt.IsZero() {
		return out, invalid()
	}
	c := s.config()
	if c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return out, invalid()
	}
	ctx, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = MFAMagicLinkPrimary{}
		}
	}()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	b, err := parent.Bindings()
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	f, err := flow.Bindings()
	if err != nil || f.Binding.Intent.TenantID != b.TenantID || f.Binding.Intent.Action != "identity.magic-link.consume" || f.Binding.Intent.PolicyID != c.PolicyID || authenticatedAt.Before(b.IssuedAt) || !authenticatedAt.Before(b.ExpiresAt) || !slices.Contains(c.Origins, f.Binding.Intent.Origin) || !slices.Contains(c.Callbacks, f.Binding.Intent.CallbackURL) {
		return out, identity.ForbiddenError{}
	}
	q := identity.RecoveryQuery{CommandID: b.RequestCommandID, TenantID: b.TenantID, AnonymousFlowID: string(f.Binding.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: requestOperation().OperationID}
	p := &requestPhase{service: s, flow: flow, request: magiclink.RequestRequest{Intent: magiclink.SignInOnly, Callback: f.Binding.Intent.CallbackURL}}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	caller = caller.Clone()
	caller.Request.Action = authorization.Action(q.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(f.Binding.ID)}
	caller.PolicyRevision = authorization.Revision(c.Coordinator.AdmissionPolicy.PolicyVersion)
	observed, err := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if err != nil {
		return out, err
	}
	if observed.Validate() != nil || observed.Absent || observed.Record.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.ForbiddenError{}
	}
	caller.PolicyRevision = authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion)
	wire, generation, err := coordinator.QueryFeaturePreparation(ctx, q, caller, p.registration(), p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	stored, err := s.readOriginOutput(ctx, observed.Record.Binding, generation, wire)
	defer clear(stored.IssuanceWire)
	defer clear(stored.DeliveryWire)
	if err != nil {
		return out, err
	}
	p.original, err = identity.NewFeatureCommand(*stored.RequestSpec)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	r := stored.Recipient
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}
	recipient.ObservedAt, err = time.Parse(time.RFC3339Nano, r.Observed)
	if err != nil || recipient.Validate() != nil || recipient.Suppressed || recipient.User.ID != b.UserID || recipient.Query.TenantID != b.TenantID || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.Query.UserID != "" || stored.Factor == 0 || stored.Prospective != nil || !stored.Issued.Equal(b.IssuedAt) || !stored.Expires.Equal(b.ExpiresAt) {
		return out, identity.ForbiddenError{}
	}
	selection := requestSelection{recipient: recipient, global: stored.Global, tenant: stored.Tenant, factor: stored.Factor, issued: stored.Issued, expires: stored.Expires}
	p.canonical = recipient.Query.CanonicalValue
	expected, err := p.payload(selection)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	expected.ID = b.CapabilityID
	if parent.MatchPayload(expected) != nil {
		return out, identity.ForbiddenError{}
	}
	originalFlow, err := p.flowDigest()
	if err != nil || originalFlow != stored.Flow || len(stored.Issuance.Grants) != 1 || stored.Issuance.User != b.UserID {
		return out, identity.ForbiddenError{}
	}
	grant := kernel.CapabilityPlan(stored.Issuance.Grants[0])
	plan := kernel.CapabilityIssuancePlan{Contributor: stored.Issuance.Contributor, MagicLinkRecipientUserID: stored.Issuance.User, Grants: []kernel.CapabilityPlan{grant}}
	if grant.CapabilityID != b.CapabilityID || grant.ReplayKeyVersion != b.ReplayKeyVersion || !grant.ExpiresAt.Equal(b.ExpiresAt) || s.issuer.ValidateCapabilityIssuance(observed.Record.Binding, plan) != nil {
		return out, identity.ForbiddenError{}
	}
	meta, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: b.PrimaryCommandID, RequestCommandID: b.RequestCommandID, CapabilityID: b.CapabilityID, IdentifierID: recipient.Identifier.ID, IdentifierVersion: recipient.Identifier.Version, VerificationVersion: recipient.Verification.Version, AuthenticatedAt: authenticatedAt, ValidUntil: b.ExpiresAt})
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	return MFAMagicLinkPrimary{Recipient: recipient, Authentication: meta}, nil
}

// readOriginOutput deliberately opens only the new historical projection. Old
// retry ciphertext remains supported by restoreOutput, with original input;
// there is no fallback that invents its missing command or refreshes old risk.
func (s *RequestService) readOriginOutput(ctx context.Context, binding identity.CommandBinding, generation uint64, wire []byte) (out storedOutput, err error) {
	if len(wire) <= len(requestOriginPrefix) || len(wire) > maximumRequestOutput || !bytes.HasPrefix(wire, []byte(requestOriginPrefix)) {
		return out, identity.UnavailableError{}
	}
	aad, err := requestOriginOutputAAD(binding, generation, s.configuration)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	sealed, err := envelope.ParseEnvelope(wire[len(requestOriginPrefix):])
	if err != nil {
		return out, identity.UnavailableError{}
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumRequestOutput-4096 {
		return out, identity.UnavailableError{}
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		clear(out.IssuanceWire)
		clear(out.DeliveryWire)
		return storedOutput{}, identity.UnavailableError{}
	}
	canonical, err := json.Marshal(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || out.Schema != 2 || out.Global == 0 || out.Tenant == 0 || out.RequestSpec == nil || out.RequestSpec.Binding != binding || out.RequestSpec.Operation != requestOperation() {
		clear(out.IssuanceWire)
		clear(out.DeliveryWire)
		return storedOutput{}, identity.UnavailableError{}
	}
	return out, nil
}

// Format redacts historical primary identity and recipient metadata.
func (MFAMagicLinkPrimary) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkpostgres.MFAMagicLinkPrimary(redacted)"))
}

// MarshalJSON refuses implicit historical metadata export.
func (MFAMagicLinkPrimary) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText refuses implicit text/map-key export.
func (MFAMagicLinkPrimary) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts correlated recipient and primary metadata.
func (MFAMagicLinkPrimary) LogValue() slog.Value {
	return slog.StringValue("magiclinkpostgres.MFAMagicLinkPrimary(redacted)")
}
