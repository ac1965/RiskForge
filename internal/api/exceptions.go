package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/exception"
	"github.com/ac1965/riskforge/internal/domain/finding"
)

// This file is the first write-endpoint slice (ADR 0014): the Exception
// workflow only, since it involves no command execution. Remediation's
// write endpoints are a separate, later ADR.

// requestExceptionBody is POST /api/v1/exceptions's request shape.
// Field names are PascalCase to match this API's existing convention of
// marshaling Go structs as-is (ADR 0011), not typical REST
// snake_case/camelCase.
type requestExceptionBody struct {
	FindingID           string
	Reason              string
	ExpiresAt           string // RFC3339
	CompensatingControl string
}

type reasonBody struct {
	Reason string
}

// decodeJSONBody decodes r's body into v. A missing or empty body is not
// an error — several of these endpoints (reject, revoke, and expire's
// optional Reason) have nothing required to send — but malformed JSON
// is.
func decodeJSONBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// writeMutationError classifies a write Named API's error into a status
// code (ADR 0014): a missing addressed resource is 404, an invalid
// state transition is 409, and everything else — predominantly
// validation failures, given how these Named APIs are structured — is
// 400. This is a deliberately simple approximation, the same tradeoff
// ADR 0011 already made for the read endpoints' single 500 bucket,
// rather than threading typed errors through every failure mode.
func writeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, exception.ErrInvalidTransition):
		writeError(w, http.StatusConflict, err)
	default:
		writeError(w, http.StatusBadRequest, err)
	}
}

func handleRequestException(svc *application.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusInternalServerError, errors.New("no authenticated principal in request context"))
			return
		}

		var body requestExceptionBody
		if err := decodeJSONBody(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
			return
		}
		if body.FindingID == "" {
			writeError(w, http.StatusBadRequest, errors.New("FindingID is required"))
			return
		}
		if body.Reason == "" {
			writeError(w, http.StatusBadRequest, errors.New("Reason is required"))
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("ExpiresAt: %w", err))
			return
		}

		// No organizational duration cap over HTTP yet (exception.Policy{}
		// zero value), matching the CLI's own default when
		// --max-duration-days is omitted.
		e, err := svc.RequestException(r.Context(), exception.Params{
			FindingID:           finding.ID(body.FindingID),
			Reason:              body.Reason,
			RequestedBy:         principal.Name,
			CreatedAt:           time.Now(),
			ExpiresAt:           expiresAt,
			CompensatingControl: body.CompensatingControl,
		}, exception.Policy{})
		if err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, e)
	}
}

func handleApproveException(svc *application.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusInternalServerError, errors.New("no authenticated principal in request context"))
			return
		}

		var body reasonBody
		if err := decodeJSONBody(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
			return
		}

		e, err := svc.ApproveException(r.Context(), exception.ID(r.PathValue("id")), principal.Name, body.Reason)
		if err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func handleRejectException(svc *application.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, err := svc.RejectException(r.Context(), exception.ID(r.PathValue("id")))
		if err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func handleExpireException(svc *application.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body reasonBody
		if err := decodeJSONBody(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
			return
		}
		reason := body.Reason
		if reason == "" {
			reason = "reached expiry date" // same default the CLI uses
		}

		e, err := svc.ExpireException(r.Context(), exception.ID(r.PathValue("id")), reason)
		if err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func handleRevokeException(svc *application.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e, err := svc.RevokeException(r.Context(), exception.ID(r.PathValue("id")))
		if err != nil {
			writeMutationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}
