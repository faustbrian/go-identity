package apikeyhttp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

// Native pages contain at most200 records, each bounded by the existing64KiB
// native record contract. This ceiling includes the explicit wire projection
// and JSON escaping without truncating an otherwise valid native page.
const maximumMetadataResponseBytes = 16 << 20

type metadataInput struct {
	facts    identityhttp.NetworkFacts
	get      apikey.GetRequest
	list     apikey.ListRequest
	actor    identity.UserID
	observed session.GetResult
}
type metadataState struct{ input func() *metadataInput }

func (s metadataState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.input == nil {
		return "", "", false
	}
	in := s.input()
	return in.get.Authentication.TenantID, in.actor, in.actor != ""
}
func (metadataState) MarshalJSON() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (metadataState) MarshalText() ([]byte, error) { return nil, apikey.ErrDisclosure }
func (metadataState) LogValue() slog.Value {
	return slog.StringValue("apikeyhttp.MetadataState(redacted)")
}

func newMetadataHandler(c Config, action string, network *identityhttp.NetworkResolver, decoder *identityhttp.RequestDecoder, organizations bool) (http.Handler, error) {
	path := "/v1/apikey/" + action
	operation := "identity.apikey." + action
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[metadataState]{MaximumDuration: c.MaximumDuration,
		Decode: func(r *http.Request) (metadataState, error) {
			var zero metadataState
			if r == nil || r.URL == nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if r.URL.Path != path || r.URL.RawPath != "" || r.URL.EscapedPath() != path {
				return zero, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return zero, failure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Body != nil && r.Body != http.NoBody {
				return zero, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
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
			if err != nil || facts.Scheme() != "https" {
				return zero, identityhttp.ErrInvalidInput
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return zero, failure{status: 421, code: "misdirected_request"}
			}
			query, err := decoder.Query(r)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			for name := range query {
				if name != "organizationID" && (action == "get" && name != "keyID" || action == "list" && name != "configurationIDs" && name != "cursor" && name != "limit") {
					return zero, identityhttp.ErrInvalidInput
				}
			}
			in := &metadataInput{facts: facts, get: apikey.GetRequest{Authentication: apikey.Authentication{TenantID: facts.TenantID(), Bearer: bearer}, KeyID: apikey.KeyID(query.Get("keyID"))}}
			if values, present := query["organizationID"]; present {
				if !organizations || values[0] == "" {
					return zero, identityhttp.ErrInvalidInput
				}
				in.get.OrganizationID = apikey.OrganizationID(values[0])
			}
			if action == "get" {
				if in.get.Validate() != nil {
					return zero, identityhttp.ErrInvalidInput
				}
			} else {
				limit, err := strconv.ParseUint(query.Get("limit"), 10, 16)
				if err != nil || strconv.FormatUint(limit, 10) != query.Get("limit") {
					return zero, identityhttp.ErrInvalidInput
				}
				in.list = apikey.ListRequest{Authentication: in.get.Authentication, OrganizationID: in.get.OrganizationID, Cursor: query.Get("cursor"), Limit: uint16(limit)}
				if raw, present := query["configurationIDs"]; present {
					// Query has already bounded decoded bytes. A JSON array avoids
					// treating punctuation in a configuration ID as a delimiter.
					if json.Unmarshal([]byte(raw[0]), &in.list.ConfigurationIDs) != nil || in.list.ConfigurationIDs == nil {
						return zero, identityhttp.ErrInvalidInput
					}
				}
				if _, present := query["cursor"]; present && !metadataCursor(in.list.Cursor) || in.list.Validate() != nil {
					return zero, identityhttp.ErrInvalidInput
				}
			}
			return metadataState{input: func() *metadataInput { return in }}, nil
		},
		Authenticate: func(r *http.Request, state metadataState) (metadataState, error) {
			in := state.input()
			token, _ := session.ParseToken(in.get.Authentication.Bearer.Token())
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return metadataState{}, identityhttp.ErrInvalidInput
			}
			observed, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.get.Authentication.TenantID, Credential: credential})
			if err != nil {
				return metadataState{}, identityhttp.ErrUnavailable
			}
			b, bindErr := observed.Session.Bindings()
			if !observed.Authenticated || observed.ValidateAt(c.Now()) != nil || bindErr != nil || b.TenantID != in.get.Authentication.TenantID || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || observed.Session.CSRFState() != (session.CSRFState{}) {
				return metadataState{}, failure{status: 403, code: "forbidden"}
			}
			in.observed, in.actor = observed, b.UserID
			return state, nil
		},
		Admit: func(r *http.Request, state metadataState) error {
			in := state.input()
			out, err := c.SafeRate.Admit(r.Context(), in.facts, operation, in.actor)
			if err != nil {
				if out.RetryAfter > 0 {
					return failure{status: 429, code: "rate_limited", retry: out.RetryAfter}
				}
				return identityhttp.ErrUnavailable
			}
			if !out.Allowed || in.observed.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state metadataState) {
			in := state.input()
			var response any
			var err error
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				rejectMetadata(w, r, identityhttp.ErrUnavailable)
				return
			}
			if action == "get" {
				var out apikey.GetResult
				out, err = c.Getter.Get(r.Context(), in.get)
				if err == nil {
					var view metadataKeyView
					view, err = metadataView(in, out.Record)
					if out.Record.ID != in.get.KeyID {
						err = identityhttp.ErrUnavailable
					}
					response = struct {
						Key metadataKeyView `json:"key"`
					}{view}
				}
			} else {
				var out apikey.ListResult
				out, err = c.Lister.List(r.Context(), in.list)
				if err == nil {
					response, err = metadataPage(in, out)
				}
			}
			if err != nil {
				rejectMetadata(w, r, err)
				return
			}
			body, err := json.Marshal(response)
			if err != nil || len(body) >= maximumMetadataResponseBytes || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				rejectMetadata(w, r, identityhttp.ErrUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(append(body, '\n'))
		}, Reject: rejectMetadata,
	})
	if err != nil {
		return nil, err
	}
	return &protectedHandler{pipeline: pipeline}, nil
}

func rejectMetadata(w http.ResponseWriter, r *http.Request, err error) {
	if failureOf(err).status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", http.MethodGet)
	}
	// The common mutation rejector only changes Allow for405, so keep the
	// selected GET method rather than passing through that POST-only branch.
	f := failureOf(err)
	if f.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((f.retry+time.Second-1)/time.Second), 10))
	}
	writeJSON(w, f.status, struct {
		Error string `json:"error"`
	}{f.code})
}

type metadataOwnerView struct {
	Kind           string                `json:"kind"`
	Version        uint64                `json:"version"`
	UserID         identity.UserID       `json:"userID,omitempty"`
	OrganizationID apikey.OrganizationID `json:"organizationID,omitempty"`
}
type metadataKeyView struct {
	ID                    apikey.KeyID      `json:"id"`
	Version               uint64            `json:"version"`
	AuthorityVersion      uint64            `json:"authorityVersion"`
	Owner                 metadataOwnerView `json:"owner"`
	ConfigurationID       string            `json:"configurationID"`
	ConfigurationRevision uint64            `json:"configurationRevision"`
	Name                  string            `json:"name"`
	Status                string            `json:"status"`
	Permissions           []string          `json:"permissions"`
	CreatedAt             time.Time         `json:"createdAt"`
	ExpiresAt             *time.Time        `json:"expiresAt"`
	RootID                apikey.KeyID      `json:"rootID"`
	RootVersion           uint64            `json:"rootVersion"`
	PreviousID            apikey.KeyID      `json:"previousID,omitempty"`
	Issuer                string            `json:"issuer"`
	Environment           string            `json:"environment"`
	Audience              string            `json:"audience"`
}
type metadataListResponse struct {
	Keys       []metadataKeyView `json:"keys"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

func metadataView(in *metadataInput, r apikey.Record) (metadataKeyView, error) {
	var zero metadataKeyView
	owner := r.Owner.Spec()
	if r.Owner.Validate() != nil || owner.TenantID != in.get.Authentication.TenantID || in.get.OrganizationID == "" && (owner.Kind != apikey.OwnerUser || owner.UserID != in.actor) || in.get.OrganizationID != "" && (owner.Kind != apikey.OwnerOrganization || owner.OrganizationID != in.get.OrganizationID) {
		return zero, identityhttp.ErrUnavailable
	}
	if _, err := apikey.ParseKeyID(string(r.ID)); err != nil {
		return zero, identityhttp.ErrUnavailable
	}
	if r.RootID != r.ID || r.RootVersion != r.AuthorityVersion || r.Version == 0 || r.AuthorityVersion == 0 || r.ConfigurationRevision == 0 || r.Status != apikey.KeyActive && r.Status != apikey.KeyRevoked || !metadataText(r.ConfigurationID, 128, false) || !metadataText(r.Name, 128, true) || !metadataText(r.Issuer, 512, false) || !metadataText(r.Environment, 128, false) || !metadataText(r.Audience, 128, false) || len(r.Grant) > 64 || r.CreatedAt.IsZero() {
		return zero, identityhttp.ErrUnavailable
	}
	if r.PreviousID != "" {
		if _, err := apikey.ParseKeyID(string(r.PreviousID)); err != nil || r.PreviousID == r.ID {
			return zero, identityhttp.ErrUnavailable
		}
	}
	for i, permission := range r.Grant {
		if !metadataText(permission, 128, false) || strings.IndexFunc(permission, func(r rune) bool { return r <= ' ' || r == 127 }) >= 0 || i > 0 && r.Grant[i-1] >= permission {
			return zero, identityhttp.ErrUnavailable
		}
	}
	permissions := make([]string, len(r.Grant))
	copy(permissions, r.Grant)
	view := metadataKeyView{ID: r.ID, Version: r.Version, AuthorityVersion: r.AuthorityVersion, ConfigurationID: r.ConfigurationID, ConfigurationRevision: r.ConfigurationRevision, Name: r.Name, Status: "active", Permissions: permissions, CreatedAt: r.CreatedAt, RootID: r.RootID, RootVersion: r.RootVersion, PreviousID: r.PreviousID, Issuer: r.Issuer, Environment: r.Environment, Audience: r.Audience, Owner: metadataOwnerView{Kind: "user", Version: owner.Version, UserID: owner.UserID}}
	if owner.Kind == apikey.OwnerOrganization {
		view.Owner = metadataOwnerView{Kind: "organization", Version: owner.Version, OrganizationID: owner.OrganizationID}
	}
	if r.Status == apikey.KeyRevoked {
		view.Status = "revoked"
	}
	if !r.ExpiresAt.IsZero() {
		expiry := r.ExpiresAt
		view.ExpiresAt = &expiry
	}
	return view, nil
}

func metadataPage(in *metadataInput, page apikey.ListResult) (metadataListResponse, error) {
	var zero metadataListResponse
	if len(page.Records) > int(in.list.Limit) || page.NextCursor != "" && (!metadataCursor(page.NextCursor) || page.NextCursor == in.list.Cursor || len(page.Records) != int(in.list.Limit)) {
		return zero, identityhttp.ErrUnavailable
	}
	views := make([]metadataKeyView, 0, len(page.Records))
	var previous apikey.KeyID
	for _, record := range page.Records {
		if record.ID <= previous || len(in.list.ConfigurationIDs) != 0 && !slices.Contains(in.list.ConfigurationIDs, record.ConfigurationID) {
			return zero, identityhttp.ErrUnavailable
		}
		view, err := metadataView(in, record)
		if err != nil {
			return zero, err
		}
		views, previous = append(views, view), record.ID
	}
	return metadataListResponse{Keys: views, NextCursor: page.NextCursor}, nil
}

func metadataText(value string, maximum int, empty bool) bool {
	return (empty || value != "") && len(value) <= maximum && utf8.ValidString(value)
}

func metadataCursor(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}
