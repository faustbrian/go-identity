package organizationhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	"github.com/felixge/httpsnoop"
)

const maximumResponseBytes = 1 << 20

type requestFailure struct {
	status      int
	code, allow string
	retry       time.Duration
}

func (e requestFailure) Error() string { return "organizationhttp: " + e.code }
func reject(w http.ResponseWriter, _ *http.Request, err error) {
	f := requestFailure{status: 503, code: "unavailable"}
	if errors.Is(err, identityhttp.ErrInvalidInput) || errors.Is(err, organization.ErrInvalidInput) {
		f = requestFailure{status: 400, code: "invalid_request"}
	}
	var specific requestFailure
	if errors.As(err, &specific) {
		f = specific
	}
	if f.allow != "" {
		w.Header().Set("Allow", f.allow)
	}
	if f.retry > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(int64((f.retry+time.Second-1)/time.Second), 10))
	}
	writeJSON(w, f.status, struct {
		Error string `json:"error"`
	}{f.code})
}
func newHandler(c Config, op organization.Operation, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	decode, err := newDecoder(c, op)
	if err != nil {
		return nil, err
	}
	pipeline, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[State]{MaximumDuration: c.MaximumDuration, Middleware: m, Decode: decode, Reject: reject,
		Authenticate: func(r *http.Request, state State) (State, error) {
			in := state.input()
			token, err := session.ParseToken(in.auth.Bearer.Token())
			if err != nil {
				return State{}, identityhttp.ErrInvalidInput
			}
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return State{}, identityhttp.ErrInvalidInput
			}
			observed, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.auth.TenantID, Credential: credential})
			if err != nil {
				return State{}, identityhttp.ErrUnavailable
			}
			if !observed.Authenticated || observed.ValidateAt(c.Now()) != nil {
				return State{}, requestFailure{status: 403, code: "forbidden"}
			}
			binding, err := observed.Session.Bindings()
			if err != nil || binding.TenantID != in.auth.TenantID || binding.Authentication.Kind != session.AuthenticationVerified {
				return State{}, requestFailure{status: 403, code: "forbidden"}
			}
			in.observed, in.actor = observed, binding.UserID
			if op == organization.InvitationAccept {
				in.user = binding.UserID
			}
			return state, nil
		},
		Admit: func(r *http.Request, state State) error {
			in := state.input()
			if op == organization.InvitationAccept {
				prepared, err := c.InvitationAccepter.PrepareAcceptance(r.Context(), in.accept(), in.facts.ClientIP().String())
				if err != nil {
					status, code := domainFailure(err)
					return requestFailure{status: status, code: code}
				}
				if nilService(prepared) {
					return identityhttp.ErrUnavailable
				}
				source, err := prepared.Admission()
				if err != nil {
					return identityhttp.ErrUnavailable
				}
				if err := admitInvitationAccept(r.Context(), c, in, source); err != nil {
					return err
				}
				in.acceptance = prepared
				return nil
			}
			var retry time.Duration
			var admitted bool
			var err error
			if selectedMutation(op) && op != organization.InvitationReject && op != organization.LeaveMember {
				var result AdminRateResult
				result, err = c.AdminRate.Admit(r.Context(), in.facts, op, in.actor)
				admitted, retry = result.Allowed, result.RetryAfter
			} else {
				var result identityhttp.SafeRateResult
				result, err = c.SafeRate.Admit(r.Context(), in.facts, string(op), in.actor)
				admitted, retry = result.Allowed, result.RetryAfter
			}
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return requestFailure{status: 429, code: "rate_limited", retry: retry}
			}
			if err != nil || !admitted || in.observed.ValidateAt(c.Now()) != nil || r.Context().Err() != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, state State) {
			in := state.input()
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if selectedMutation(op) {
				var out organization.StoreResult
				var resend organization.InvitationResendOperationResult
				var err error
				switch op {
				case organization.CreateDynamicRole:
					out, err = c.RoleCreator.CreateDynamicRole(r.Context(), in.createRole(), in.facts.ClientIP().String())
				case organization.UpdateDynamicRole:
					out, err = c.RoleUpdater.UpdateDynamicRole(r.Context(), in.updateRole(), in.facts.ClientIP().String())
				case organization.DeleteDynamicRole:
					out, err = c.RoleDeleter.DeleteDynamicRole(r.Context(), in.deleteRole(), in.facts.ClientIP().String())
				case organization.Create:
					out, err = c.Service.Create(r.Context(), in.create(), in.facts.ClientIP().String())
				case organization.Update:
					out, err = c.MetadataUpdater.Update(r.Context(), in.update(), in.facts.ClientIP().String())
				case organization.AddMember:
					out, err = c.Service.AddMember(r.Context(), in.add(), in.facts.ClientIP().String())
				case organization.AddTeamMember:
					out, err = c.TeamMemberAdder.AddTeamMember(r.Context(), in.teamAdd(), in.facts.ClientIP().String())
				case organization.CreateTeam:
					out, err = c.TeamCreator.CreateTeam(r.Context(), in.createTeam(), in.facts.ClientIP().String())
				case organization.UpdateTeam:
					out, err = c.TeamUpdater.UpdateTeam(r.Context(), in.updateTeam(), in.facts.ClientIP().String())
				case organization.DeleteTeam:
					out, err = c.TeamDeleter.DeleteTeam(r.Context(), in.deleteTeam(), in.facts.ClientIP().String())
				case organization.RemoveTeamMember:
					out, err = c.TeamMemberRemover.RemoveTeamMember(r.Context(), in.teamRemove(), in.facts.ClientIP().String())
				case organization.UpdateMember:
					out, err = c.MemberUpdater.UpdateMember(r.Context(), in.updateMember(), in.facts.ClientIP().String())
				case organization.RemoveMember:
					out, err = c.Service.RemoveMember(r.Context(), in.remove(), in.facts.ClientIP().String())
				case organization.LeaveMember:
					out, err = c.MemberLeaver.LeaveMember(r.Context(), in.leave(), in.facts.ClientIP().String())
				case organization.OwnerTransfer:
					out, err = dispatchOwnerTransfer(r.Context(), c, in)
				case organization.Archive, organization.Restore:
					out, err = dispatchLifecycle(r.Context(), c, in)
				case organization.InvitationSend:
					out, err = c.InvitationSender.Send(r.Context(), in.send(), in.facts.ClientIP().String())
				case organization.InvitationResend:
					resend, err = c.InvitationResender.Resend(r.Context(), in.resend(), in.facts.ClientIP().String())
					out = resend.StoreResult
				case organization.InvitationCancel:
					out, err = c.InvitationCanceller.Cancel(r.Context(), in.cancel(), in.facts.ClientIP().String())
				case organization.InvitationExpire:
					out, err = c.InvitationExpirer.Expire(r.Context(), in.expire(), in.facts.ClientIP().String())
				case organization.InvitationReject:
					out, err = c.InvitationRejecter.Reject(r.Context(), in.reject(), in.facts.ClientIP().String())
				case organization.InvitationAccept:
					if nilService(in.acceptance) {
						reject(w, r, identityhttp.ErrUnavailable)
						return
					}
					out, err = in.acceptance.Execute(r.Context())
				}
				if op == organization.InvitationReject {
					status, response := invitationRejectResponse(in, out, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error = 503, "unavailable"
						response.State = ""
					}
					writeJSON(w, status, response)
					return
				}
				if op == organization.InvitationExpire {
					status, response := invitationExpireResponse(in, out, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error, response.State = 503, "unavailable", ""
					}
					writeJSON(w, status, response)
					return
				}
				if op == organization.InvitationCancel {
					status, response := invitationCancelResponse(in, out, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error = 503, "unavailable"
						response.State = ""
					}
					writeJSON(w, status, response)
					return
				}
				if op == organization.InvitationResend {
					status, response := invitationResendResponse(in, resend, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error = 503, "unavailable"
						response.DeliveryState = ""
					}
					writeJSON(w, status, response)
					return
				}
				if op == organization.InvitationAccept {
					status, response := invitationAcceptResponse(in, out, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error = 503, "unavailable"
					}
					writeJSON(w, status, response)
					return
				}
				if op == organization.InvitationSend {
					status, response := invitationSendResponse(r.Context(), c, in, out, err)
					if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
						status, response.Error = 503, "unavailable"
						response.Invitation, response.DeliveryState = nil, ""
					}
					writeJSON(w, status, response)
					return
				}
				status, response := mutationResponse(in, out, err)
				// A post-dispatch deadline is not rollback. Preserve known safe
				// original outcome, but do not claim timely successful delivery.
				if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					status, response.Error = 503, "unavailable"
				}
				writeJSON(w, status, response)
				return
			}
			if op == organization.ListOrganizations {
				out, err := c.OrganizationLister.ListOrganizations(r.Context(), in.listOrganizations())
				if err != nil {
					status, code := domainFailure(err)
					reject(w, r, requestFailure{status: status, code: code})
					return
				}
				response, err := organizationListResponse(in, out)
				if err != nil || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				writeJSON(w, 200, response)
				return
			}
			if op == organization.SlugAvailable {
				out, err := c.SlugAvailability.SlugAvailable(r.Context(), in.slugAvailable())
				if err != nil {
					status, code := domainFailure(err)
					reject(w, r, requestFailure{status: status, code: code})
					return
				}
				if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				writeJSON(w, 200, SlugAvailableResponse{Available: out.Available})
				return
			}
			if op == organization.CheckPermission {
				decision, err := c.PermissionChecker.CheckPermission(r.Context(), in.permissionCheck())
				if err != nil {
					status, code := domainFailure(err)
					reject(w, r, requestFailure{status: status, code: code})
					return
				}
				response, err := permissionResponse(in, decision)
				if err != nil || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				writeJSON(w, 200, response)
				return
			}
			if roleReadOperation(op) {
				var view organization.View
				var err error
				if op == organization.GetDynamicRole {
					view, err = c.RoleGetter.GetDynamicRole(r.Context(), in.readRole())
				} else {
					view, err = c.RoleLister.ListDynamicRoles(r.Context(), in.readRole())
				}
				if err != nil {
					status, code := domainFailure(err)
					reject(w, r, requestFailure{status: status, code: code})
					return
				}
				response, err := roleReadResponse(in, view)
				if err != nil || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				writeJSON(w, 200, response)
				return
			}
			if teamPageRead(op) {
				var view organization.View
				var err error
				if op == organization.ListMyTeams {
					view, err = c.MyTeamLister.ListMyTeams(r.Context(), in.teamRead())
				} else if op == organization.ListTeams {
					view, err = c.TeamLister.ListTeams(r.Context(), in.teamRead())
				} else {
					view, err = c.TeamMemberLister.ListTeamMembers(r.Context(), in.teamRead())
				}
				if err != nil {
					status, code := domainFailure(err)
					reject(w, r, requestFailure{status: status, code: code})
					return
				}
				if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				if op == organization.ListMyTeams || op == organization.ListTeams {
					page, err := teamListResponse(in, view)
					if err != nil {
						reject(w, r, err)
						return
					}
					writeJSON(w, 200, page)
				} else {
					page, err := teamMembersResponse(in, view)
					if err != nil {
						reject(w, r, err)
						return
					}
					writeJSON(w, 200, page)
				}
				return
			}
			var out organization.View
			var err error
			if op == organization.Get {
				out, err = c.Service.Get(r.Context(), in.read())
			} else {
				out, err = c.Service.ListMembers(r.Context(), in.read())
			}
			if err != nil {
				status, code := domainFailure(err)
				reject(w, r, requestFailure{status: status, code: code})
				return
			}
			if r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			response, err := readResponse(in, out)
			if err != nil {
				reject(w, r, err)
				return
			}
			writeJSON(w, 200, response)
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: pipeline}, nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	wire, err := json.Marshal(value)
	if err != nil || len(wire) > maximumResponseBytes {
		wire = []byte(`{"error":"unavailable"}`)
		status = 503
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(append(wire, '\n'))
}
func (p *protectedPipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	protect := func() {
		for name := range w.Header() {
			if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "X-CSRF-Token") || strings.EqualFold(name, "X-MFA-Token") || strings.EqualFold(name, "Location") || strings.EqualFold(name, "Trailer") || strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Content-Type") || strings.EqualFold(name, "Cache-Control") || strings.EqualFold(name, "X-Content-Type-Options") {
				delete(w.Header(), name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	protect()
	defer protect()
	writer := httpsnoop.Wrap(w, httpsnoop.Hooks{WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
		return func(status int) { protect(); next(status) }
	}, Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
		return func(body []byte) (int, error) { protect(); return next(body) }
	}, Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc { return func() { protect(); next() } }, ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
		return func(reader io.Reader) (int64, error) { protect(); return next(reader) }
	}})
	p.pipeline.ServeHTTP(writer, r)
}
