package identityhttp

import (
	"encoding/json"
	"slices"
	"strings"
)

// CoverageStatus describes selection, never completion or security evidence.
type CoverageStatus string

const (
	// CoverageSelectedRouted has one selected descriptor and wire operation.
	CoverageSelectedRouted CoverageStatus = "selected-routed"
	// CoverageUnselectedRouted is a canonical obligation not selected here.
	CoverageUnselectedRouted CoverageStatus = "unselected-routed"
	// CoverageDirectOnly has no HTTP route by contract; implementation is unproven.
	CoverageDirectOnly CoverageStatus = "direct-only"
	// CoverageMiddleware is not a standalone HTTP operation; enforcement is unproven.
	CoverageMiddleware CoverageStatus = "middleware"
	// CoverageSharedVariantUnavailable retains a shared-route variant whose
	// runtime implementation this selected builder cannot currently establish.
	CoverageSharedVariantUnavailable CoverageStatus = "shared-variant-unavailable"
)

// OperationCoverage is one canonical obligation or selected namespaced
// extension. Only selected routed rows have RegisteredOperationID. Baseline
// rows do not advertise enabled capabilities, direct implementation, middleware
// enforcement or full parity. These records belong to the separate diagnostic
// coverage export, never the served OpenAPI document. Values own no resources.
type OperationCoverage struct {
	OperationID           string         `json:"operationID"`
	Exposure              Exposure       `json:"exposure"`
	Status                CoverageStatus `json:"status"`
	RegisteredOperationID string         `json:"registeredOperationID,omitempty"`
	Extension             bool           `json:"extension,omitempty"`
}

// Coverage returns a detached operation-ID-sorted selection report retaining
// every canonical row, including non-HTTP obligations. Zero returns no rows.
// Concurrent exports are safe. This is not a unit-completion certificate.
func (d OpenAPIDocument) Coverage() []OperationCoverage { return slices.Clone(d.coverage) }

// CoverageJSON returns deterministic detached JSON for Coverage, or nil for
// zero. It includes unselected baseline names; do not mistake this diagnostic
// inventory for enabled feature metadata or automatically publish it.
func (d OpenAPIDocument) CoverageJSON() []byte {
	if len(d.data) == 0 {
		return nil
	}
	data, _ := json.Marshal(d.coverage)
	return data
}

func documentCoverage(ops []OperationDescriptor) []OperationCoverage {
	catalog := readCatalog()
	rows := make(map[string]OperationCoverage, len(catalog)+len(ops))
	for id, row := range catalog {
		status := CoverageUnselectedRouted
		switch row.Exposure {
		case "direct":
			status = CoverageDirectOnly
		case "middleware":
			status = CoverageMiddleware
		default:
			if row.OpenAPIID != id {
				status = CoverageSharedVariantUnavailable
			}
		}
		rows[id] = OperationCoverage{OperationID: id, Exposure: row.record().Exposure, Status: status}
	}
	for _, op := range ops {
		_, canonical := catalog[op.Record.OperationID]
		rows[op.Record.OperationID] = OperationCoverage{OperationID: op.Record.OperationID, Exposure: op.Record.Exposure, Status: CoverageSelectedRouted, RegisteredOperationID: op.Record.OpenAPIOperationID, Extension: !canonical}
	}
	result := make([]OperationCoverage, 0, len(rows))
	for _, row := range rows {
		result = append(result, row)
	}
	slices.SortFunc(result, func(a, b OperationCoverage) int { return strings.Compare(a.OperationID, b.OperationID) })
	return result
}
