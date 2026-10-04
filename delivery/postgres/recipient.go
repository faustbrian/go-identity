package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// recipientFence contains only safe primary record versions. It grants no
// authority itself; the native phase checks it under the original transaction.
type recipientFence struct {
	id                 identity.IdentifierID
	version, authority uint64
}

func verificationPurpose(purpose string) bool {
	return purpose == "verification" || purpose == "email-change" || purpose == "phone-verification" || purpose == "phone-change"
}

// AdmitIdentifier is owned workflow composition, not an application endpoint.
// Authentication supplies the original binding and exact caller scope. The
// owned primary repository supplies the recipient; an address or digest supplied
// in input cannot substitute for the selected canonical identifier. Pending
// identifiers are eligible only for the closed address-verification purposes.
// Public Queue composition remains responsible for obtaining that trusted scope.
func (e *enqueueExecutor) AdmitIdentifier(ctx context.Context, b identity.CommandBinding, caller authorization.DecisionContext, input IntentInput, repo *identitypostgres.Repository, id identity.IdentifierID, policies *retainedPolicies, keyed *keyedAdmission, requestKey string) (identity.CommandResult, error) {
	if ctx == nil || e == nil || repo == nil || keyed == nil || e.custody == nil || e.custody.store == nil || keyed.deployment != e.custody.store.deployment || b.RecordID != "" || len(requestKey) < 16 || !safeID(requestKey, false) {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	if _, err := identity.ParseIdentifierID(string(id)); err != nil {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	checked := b
	checked.RecordID = "enqueue-validation"
	if checked.ValidateFor(EnqueueOperation()) != nil {
		return identity.CommandResult{}, delivery.ErrInvalidInput
	}
	for _, attrs := range []authorization.Attributes{caller.Request.Subject.Attributes, caller.Request.Resource.Attributes, caller.Request.Environment.Attributes, caller.Request.Attributes} {
		if len(attrs) > 128 {
			return identity.CommandResult{}, delivery.ErrInvalidInput
		}
		for name := range attrs {
			if len(name) > 128 || strings.HasPrefix(string(name), "delivery.") {
				return identity.CommandResult{}, delivery.ErrInvalidInput
			}
		}
	}
	w, stop := context.WithTimeout(ctx, e.timeout)
	defer stop()
	if err := e.allow(w, checked, caller); err != nil {
		return identity.CommandResult{}, err
	}
	state, err := repo.GetIdentifierState(w, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil {
		if errors.Is(err, identity.ErrUserAbsent) {
			return identity.CommandResult{}, delivery.ErrForbidden
		}
		if w.Err() != nil {
			return identity.CommandResult{}, w.Err()
		}
		return identity.CommandResult{}, delivery.ErrUnavailable
	}
	if state.User.Status != identity.StatusActive {
		return identity.CommandResult{}, delivery.ErrForbidden
	}
	for n, identifier := range state.Identifiers {
		if identifier.ID != id {
			continue
		}
		channel := delivery.ChannelEmail
		if identifier.Kind == identity.IdentifierPhone {
			channel = delivery.ChannelSMS
		} else if identifier.Kind != identity.IdentifierEmail {
			return identity.CommandResult{}, delivery.ErrForbidden
		}
		verification := state.Verifications[n]
		pending := verification.State == identity.VerificationPending
		if verification.State != identity.VerificationVerified && !(pending && verificationPurpose(input.Purpose)) {
			return identity.CommandResult{}, delivery.ErrForbidden
		}
		// This path receives already rendered trusted workflow output. Do not
		// silently redirect that output to a changed or caller-chosen address;
		// full Queue composition resolves the recipient before rendering.
		if input.Recipient.Channel != channel || input.Recipient.Address != identifier.CanonicalValue {
			return identity.CommandResult{}, delivery.ErrForbidden
		}
		// Canonical recipient custody is owned here. The scope digest binds this
		// exact tenant/user/identifier/version/channel, never a caller's claim.
		digest := custodyMAC(keyed.key, "identity-delivery-recipient-v1", keyedFields(keyed.deployment, string(b.TenantID), string(b.UserID), string(id), strconv.FormatUint(identifier.Version, 10), strconv.FormatUint(state.AuthorityVersion, 10), strconv.Itoa(int(channel))), []byte(identifier.CanonicalValue))
		input.Recipient = delivery.Recipient{Channel: channel, Address: identifier.CanonicalValue, ScopeDigest: hex.EncodeToString(digest[:])}
		input.SubjectID = string(b.UserID)
		if input.Rendered.Channel != channel {
			return identity.CommandResult{}, delivery.ErrInvalidInput
		}
		return e.admit(w, b, caller, []IntentInput{input}, policies, keyed, requestKey, []recipientFence{{id: id, version: identifier.Version, authority: state.AuthorityVersion}})
	}
	return identity.CommandResult{}, delivery.ErrForbidden
}

func recipientFields(s identity.FeatureCommandSpec) ([]recipientFence, error) {
	if len(s.Fields) < 11 || !strings.HasSuffix(s.Fields[8].Name, ".x-id") {
		return nil, nil
	}
	if len(s.Fields)%11 != 0 {
		return nil, delivery.ErrInvalidInput
	}
	fences := make([]recipientFence, len(s.Fields)/11)
	for n := range fences {
		fields := s.Fields[n*11+8 : n*11+11]
		prefix := strings.TrimSuffix(s.Fields[n*11].Name, ".digest")
		if fields[0].Name != prefix+".x-id" || fields[1].Name != prefix+".x-id-version" || fields[2].Name != prefix+".x-version" || fields[0].Value.Kind != identity.FeatureText || fields[1].Value.Kind != identity.FeatureUint64 || fields[2].Value.Kind != identity.FeatureUint64 || fields[1].Value.Uint64 == 0 || fields[2].Value.Uint64 == 0 {
			return nil, delivery.ErrInvalidInput
		}
		id, err := identity.ParseIdentifierID(fields[0].Value.Text)
		if err != nil {
			return nil, delivery.ErrInvalidInput
		}
		fences[n] = recipientFence{id: id, version: fields[1].Value.Uint64, authority: fields[2].Value.Uint64}
	}
	return fences, nil
}

// checkRecipients never opens a transaction or holds locks across a callback.
// Share locks persist until the original coordinator commits or aborts, fencing
// normal identifier and user lifecycle mutations after the pre-crypto read.
func checkRecipients(ctx context.Context, w identitypostgres.Work, s identity.FeatureCommandSpec, intents []identitypostgres.DeliveryIntentPlan) error {
	fences, err := recipientFields(s)
	if err != nil {
		return err
	}
	for n, fence := range fences {
		rows, err := w.Query(ctx, `SELECT u.status,u.identifier_version::text,i.version::text,i.verification_state FROM identity.users u JOIN identity.identifiers i ON i.tenant_id=u.tenant_id AND i.user_id=u.user_id WHERE u.tenant_id=$1 AND u.user_id=$2 AND i.identifier_id=$3 FOR SHARE OF u,i`, string(s.Binding.TenantID), string(s.Binding.UserID), string(fence.id))
		if err != nil {
			return delivery.ErrUnavailable
		}
		var status, authority, version string
		var verification int16
		if !rows.Next() {
			rows.Close()
			return identity.ConflictError{}
		}
		err = rows.Scan(&status, &authority, &version, &verification)
		extra := rows.Next()
		rowErr := rows.Err()
		rows.Close()
		if err != nil || extra || rowErr != nil {
			return delivery.ErrUnavailable
		}
		if status != string(identity.StatusActive) || authority != strconv.FormatUint(fence.authority, 10) || version != strconv.FormatUint(fence.version, 10) || verification != int16(identity.VerificationVerified) && !(verification == int16(identity.VerificationPending) && verificationPurpose(intents[n].Purpose)) {
			return identity.ConflictError{}
		}
	}
	return nil
}
