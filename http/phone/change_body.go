package phonehttp

import (
	"context"
	"encoding/json"
	"strconv"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/phone"
)

// Decoded intent is not authorization. The handler supplies tenant, subject,
// original session, synchronizer and signed proof from the actual native owners.
type changeBody struct {
	flowID   string
	proofID  auth.ProofID
	change   phone.ChangeRequestSpec
	update   phone.UpdateRequestSpec
	recovery phone.VerificationRecovery
}

func decodeChangeBody(ctx context.Context, policy *phone.NumberPolicy, mode int, fields map[string]json.RawMessage) (changeBody, error) {
	var out changeBody
	invalid := func() (changeBody, error) { return changeBody{}, identityhttp.ErrInvalidInput }
	if ctx == nil || policy == nil || mode < 0 || mode > 2 {
		return invalid()
	}
	var proof string
	switch mode {
	case 0:
		var next, previous, identifierVersion, verificationVersion string
		if !closedFields(fields, map[string]any{"flowID": &out.flowID, "number": &next, "previousNumber": &previous, "identifierID": &out.change.IdentifierID, "expectedIdentifierVersion": &identifierVersion, "expectedVerificationVersion": &verificationVersion, "proofID": &proof}) {
			return invalid()
		}
		if _, err := identity.ParseIdentifierID(string(out.change.IdentifierID)); err != nil {
			return invalid()
		}
		parseVersion := func(value string) (uint64, bool) {
			n, err := strconv.ParseUint(value, 10, 64)
			return n, err == nil && n > 0 && n < ^uint64(0) && strconv.FormatUint(n, 10) == value
		}
		var valid bool
		out.change.ExpectedIdentifierVersion, valid = parseVersion(identifierVersion)
		if !valid {
			return invalid()
		}
		out.change.ExpectedVerificationVersion, valid = parseVersion(verificationVersion)
		if !valid {
			return invalid()
		}
		var err error
		out.change.Enrollment.Number, err = policy.Canonicalize(ctx, next)
		if err != nil {
			return invalid()
		}
		out.change.PreviousNumber, err = policy.Canonicalize(ctx, previous)
		if err != nil || out.change.PreviousNumber.Equal(out.change.Enrollment.Number) {
			return invalid()
		}
	case 1:
		var code string
		if !closedFields(fields, map[string]any{"flowID": &out.flowID, "sendCommandID": &out.update.SendCommandID, "code": &code, "proofID": &proof, "reason": &out.update.Reason}) {
			return invalid()
		}
		if _, err := identity.ParseCommandID(string(out.update.SendCommandID)); err != nil {
			return invalid()
		}
		var err error
		out.update.Code, err = auth.NewOneTimeCode(code)
		if err != nil || len(code) > 128 || len(out.update.Reason) < 1 || len(out.update.Reason) > 64 {
			return invalid()
		}
	case 2:
		var recovery map[string]json.RawMessage
		if !closedFields(fields, map[string]any{"flowID": &out.flowID, "recovery": &recovery}) {
			return invalid()
		}
		var err error
		out.recovery, err = decodeRecovery(recovery)
		if err != nil {
			return invalid()
		}
	}
	if len(out.flowID) == 0 || len(out.flowID) > 128 {
		return invalid()
	}
	for _, ch := range []byte(out.flowID) {
		if ch < '!' || ch > '~' {
			return invalid()
		}
	}
	if mode != 2 {
		if _, err := identity.ParseCommandID(proof); err != nil {
			return invalid()
		}
		out.proofID = auth.ProofID(proof)
	}
	return out, nil
}
