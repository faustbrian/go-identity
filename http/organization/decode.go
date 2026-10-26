package organizationhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

type requestInput struct {
	op                        organization.Operation
	facts                     identityhttp.NetworkFacts
	auth                      organization.Authentication
	key                       identity.IdempotencyKey
	actor                     identity.UserID
	observed                  session.GetResult
	correlation               string
	name, slug                string
	org                       organization.ID
	user                      identity.UserID
	recipientIdentifier       identity.IdentifierID
	role                      organization.Role
	orgVersion, memberVersion uint64
	cursor                    identity.UserID
	limit                     uint32
	commandID                 identity.CommandID
	invitationID              organization.ID
	invitationVersion         uint64
	proof                     capability.Proof
	acceptance                organization.PreparedInvitationAcceptance
}

func operationPath(op organization.Operation) (string, string) {
	switch op {
	case organization.Create:
		return "/v1/organization/create", http.MethodPost
	case organization.Update:
		return "/v1/organization/update", http.MethodPost
	case organization.Get:
		return "/v1/organization/get", http.MethodGet
	case organization.ListMembers:
		return "/v1/organization/member/list", http.MethodGet
	case organization.AddMember:
		return "/v1/organization/member/add", http.MethodPost
	case organization.UpdateMember:
		return "/v1/organization/member/update", http.MethodPost
	case organization.RemoveMember:
		return "/v1/organization/member/remove", http.MethodPost
	case organization.InvitationSend:
		return "/v1/organization/invitation-send", http.MethodPost
	case organization.InvitationAccept:
		return "/v1/organization/invitation/accept", http.MethodPost
	case organization.InvitationResend:
		return "/v1/organization/invitation/resend", http.MethodPost
	case organization.InvitationCancel:
		return "/v1/organization/invitation/cancel", http.MethodPost
	}
	return "", ""
}
func newDecoder(c Config, op organization.Operation) (func(*http.Request) (State, error), error) {
	path, method := operationPath(op)
	missingOwner := nilService(c.Service)
	if op == organization.Update {
		missingOwner = nilService(c.MetadataUpdater)
	}
	if op == organization.UpdateMember {
		missingOwner = nilService(c.MemberUpdater)
	}
	if op == organization.InvitationSend {
		missingOwner = nilService(c.InvitationSender) || nilService(c.Invitations)
	}
	if op == organization.InvitationResend {
		missingOwner = nilService(c.InvitationResender)
	}
	if op == organization.InvitationCancel {
		missingOwner = nilService(c.InvitationCanceller)
	}
	missingRate := selectedMutation(op) && !c.AdminRate.Configured() || !selectedMutation(op) && !c.SafeRate.Configured()
	if op == organization.InvitationAccept {
		missingOwner, missingRate = nilService(c.InvitationAccepter), !c.SecretRate.Configured()
		if c.InvitationProofLimits == (capability.Limits{}) {
			c.InvitationProofLimits = capability.DefaultLimits()
		}
		if _, err := capability.ParseProof("", c.InvitationProofLimits); errors.Is(err, capability.ErrInvalidConfiguration) {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	if path == "" || missingOwner || missingRate || !c.Sessions.Configured() || c.Now == nil {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	return func(r *http.Request) (State, error) {
		var zero State
		if r == nil || r.URL == nil {
			return zero, identityhttp.ErrInvalidInput
		}
		if r.URL.Path != path || r.URL.RawPath != "" || r.URL.EscapedPath() != path {
			return zero, requestFailure{status: 404, code: "not_found"}
		}
		if r.Method != method {
			return zero, requestFailure{status: 405, code: "method_not_allowed", allow: method}
		}
		requirement := identityhttp.HeaderForbidden
		if op == organization.Create || op == organization.Update || op == organization.AddMember || op == organization.UpdateMember || op == organization.InvitationSend || op == organization.InvitationResend {
			requirement = identityhttp.HeaderRequired
		}
		key, _, err := decoder.IdempotencyKey(r, requirement)
		if err != nil {
			return zero, identityhttp.ErrInvalidInput
		}
		bearer, _, err := decoder.Bearer(r, identityhttp.HeaderRequired)
		if err != nil {
			return zero, identityhttp.ErrInvalidInput
		}
		if _, err := session.ParseToken(bearer.Token()); err != nil {
			return zero, identityhttp.ErrInvalidInput
		}
		facts, err := network.Resolve(r)
		if err != nil {
			return zero, networkFailure(err)
		}
		if facts.Realm() != identityhttp.RealmTenant {
			return zero, requestFailure{status: 421, code: "misdirected_request"}
		}
		if facts.Scheme() != "https" {
			return zero, identityhttp.ErrInvalidInput
		}
		input := &requestInput{op: op, facts: facts, auth: organization.Authentication{TenantID: facts.TenantID(), Bearer: bearer}, key: key}
		if selectedMutation(op) {
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				return zero, identityhttp.ErrInvalidInput
			}
			body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](decoder, r)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if op == organization.InvitationAccept {
				if err := decodeAcceptance(input, body, c.InvitationProofLimits); err != nil {
					return zero, err
				}
			} else if err := decodeMutation(input, body); err != nil {
				return zero, err
			}
		} else {
			if r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody {
				return zero, identityhttp.ErrInvalidInput
			}
			query, err := decoder.Query(r)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			for k := range query {
				if k != "organizationID" && (op != organization.ListMembers || k != "cursor" && k != "limit") {
					return zero, identityhttp.ErrInvalidInput
				}
			}
			input.org = organization.ID(query.Get("organizationID"))
			if !boundedID(string(input.org)) {
				return zero, identityhttp.ErrInvalidInput
			}
			if op == organization.ListMembers {
				input.limit = 100
				if values, present := query["limit"]; present {
					n, err := strconv.ParseUint(values[0], 10, 32)
					if err != nil || n == 0 || n > 100 || strconv.FormatUint(n, 10) != values[0] {
						return zero, identityhttp.ErrInvalidInput
					}
					input.limit = uint32(n)
				}
				input.cursor = identity.UserID(query.Get("cursor"))
				if _, present := query["cursor"]; present && !boundedID(string(input.cursor)) {
					return zero, identityhttp.ErrInvalidInput
				}
			}
		}
		if op == organization.InvitationAccept {
			input.correlation = string(input.commandID)
		} else {
			id, err := identity.NewCommandID()
			if err != nil {
				return zero, identityhttp.ErrUnavailable
			}
			input.correlation = string(id)
		}
		if err := input.validate(); err != nil {
			return zero, err
		}
		return State{input: func() *requestInput { return input }}, nil
	}, nil
}
func decodeMutation(in *requestInput, body map[string]json.RawMessage) error {
	var names []string
	if in.op == organization.Create {
		names = []string{"name", "slug"}
	} else if in.op == organization.Update {
		names = []string{"organizationID", "organizationVersion", "name", "slug"}
	} else if in.op == organization.InvitationSend {
		names = []string{"organizationID", "organizationVersion", "recipientUserID", "recipientIdentifierID"}
	} else if in.op == organization.InvitationResend || in.op == organization.InvitationCancel {
		names = []string{"organizationID", "organizationVersion", "invitationID", "invitationVersion"}
	} else {
		names = []string{"organizationID", "userID", "organizationVersion", "memberVersion"}
		if in.op == organization.AddMember || in.op == organization.UpdateMember {
			names = append(names, "role")
		}
	}
	if len(body) != len(names) {
		return identityhttp.ErrInvalidInput
	}
	for _, name := range names {
		value, ok := body[name]
		if !ok || string(value) == "null" {
			return identityhttp.ErrInvalidInput
		}
	}
	decode := func(name string, target any) bool { return json.Unmarshal(body[name], target) == nil }
	if in.op == organization.Create {
		if !decode("name", &in.name) || !decode("slug", &in.slug) {
			return identityhttp.ErrInvalidInput
		}
	} else if in.op == organization.Update {
		if !decode("organizationID", &in.org) || !decode("organizationVersion", &in.orgVersion) || !decode("name", &in.name) || !decode("slug", &in.slug) {
			return identityhttp.ErrInvalidInput
		}
	} else if in.op == organization.InvitationSend {
		if !decode("organizationID", &in.org) || !decode("organizationVersion", &in.orgVersion) || !decode("recipientUserID", &in.user) || !decode("recipientIdentifierID", &in.recipientIdentifier) {
			return identityhttp.ErrInvalidInput
		}
	} else if in.op == organization.InvitationResend || in.op == organization.InvitationCancel {
		if !decode("organizationID", &in.org) || !decode("organizationVersion", &in.orgVersion) || !decode("invitationID", &in.invitationID) || !decode("invitationVersion", &in.invitationVersion) {
			return identityhttp.ErrInvalidInput
		}
	} else {
		if !decode("organizationID", &in.org) || !decode("userID", &in.user) || !decode("organizationVersion", &in.orgVersion) || !decode("memberVersion", &in.memberVersion) {
			return identityhttp.ErrInvalidInput
		}
		if (in.op == organization.AddMember || in.op == organization.UpdateMember) && !decode("role", &in.role) {
			return identityhttp.ErrInvalidInput
		}
	}
	return nil
}
func (in *requestInput) validate() error {
	switch in.op {
	case organization.Create:
		return in.create().Validate()
	case organization.Update:
		return in.update().Validate()
	case organization.AddMember:
		return in.add().Validate()
	case organization.UpdateMember:
		return in.updateMember().Validate()
	case organization.RemoveMember:
		return in.remove().Validate()
	case organization.InvitationSend:
		return in.send().Validate()
	case organization.InvitationAccept:
		return in.accept().Validate()
	case organization.InvitationResend:
		return in.resend().Validate()
	case organization.InvitationCancel:
		return in.cancel().Validate()
	}
	return nil
}
func (in *requestInput) create() organization.CreateOperationRequest {
	return organization.CreateOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, Name: in.name, Slug: in.slug, CorrelationID: in.correlation}
}
func (in *requestInput) update() organization.UpdateOperationRequest {
	return organization.UpdateOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, OrganizationVersion: in.orgVersion, Name: in.name, Slug: in.slug, CorrelationID: in.correlation}
}
func (in *requestInput) updateMember() organization.UpdateMemberOperationRequest {
	return organization.UpdateMemberOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, UserID: in.user, Role: in.role, OrganizationVersion: in.orgVersion, MemberVersion: in.memberVersion, CorrelationID: in.correlation}
}
func (in *requestInput) add() organization.AddMemberOperationRequest {
	return organization.AddMemberOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, UserID: in.user, Role: in.role, OrganizationVersion: in.orgVersion, MemberVersion: in.memberVersion, CorrelationID: in.correlation}
}
func (in *requestInput) remove() organization.RemoveMemberOperationRequest {
	return organization.RemoveMemberOperationRequest{Authentication: in.auth, OrganizationID: in.org, UserID: in.user, OrganizationVersion: in.orgVersion, MemberVersion: in.memberVersion, CorrelationID: in.correlation}
}
func (in *requestInput) read() organization.ReadRequest {
	return organization.ReadRequest{Authentication: in.auth, OrganizationID: in.org, Cursor: in.cursor, Limit: in.limit, CorrelationID: in.correlation}
}

func (in *requestInput) send() organization.InvitationSendOperationRequest {
	return organization.InvitationSendOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, OrganizationVersion: in.orgVersion, RecipientUserID: in.user, RecipientIdentifierID: in.recipientIdentifier, CorrelationID: in.correlation}
}

func (in *requestInput) resend() organization.InvitationResendOperationRequest {
	return organization.InvitationResendOperationRequest{Authentication: in.auth, IdempotencyKey: in.key, OrganizationID: in.org, OrganizationVersion: in.orgVersion, InvitationID: in.invitationID, InvitationVersion: in.invitationVersion, CorrelationID: in.correlation}
}

func (in *requestInput) cancel() organization.InvitationCancelOperationRequest {
	return organization.InvitationCancelOperationRequest{Authentication: in.auth, OrganizationID: in.org, OrganizationVersion: in.orgVersion, InvitationID: in.invitationID, InvitationVersion: in.invitationVersion, CorrelationID: in.correlation}
}

// The root organization's safeID contract is 1..128 UTF-8 bytes excluding
// ASCII whitespace/controls and DEL. Preserve its non-ASCII ID semantics.
func boundedID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}
func networkFailure(err error) error {
	if _, ok := err.(identityhttp.DecodeError); ok {
		return requestFailure{status: 421, code: "misdirected_request"}
	}
	return identityhttp.ErrUnavailable
}
