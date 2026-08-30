// Package match resolves components to known vulnerabilities.
package match

import (
	"context"

	"github.com/mhmtkas/fwscan/internal/model"
)

// Matcher turns components into findings.
//
// A matcher that finds nothing returns an empty slice and a nil error. Errors
// mean the lookup could not be performed — no network, a refused request, a
// cancelled context — which output-spec section 5 maps to exit 2.
type Matcher interface {
	Match(ctx context.Context, comps []model.Component) ([]model.Finding, error)
}
