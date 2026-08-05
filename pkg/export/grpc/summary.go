package evidencepb

import (
	"fmt"

	"github.com/Unspekable1654/flight-recorder/pkg/format"
)

// caseSummary is the handful of fields the API surfaces from a CASE bundle.
type caseSummary struct {
	rule         string
	severity     string
	podName      string
	podNamespace string
	containerID  string
}

// parseCASESummary extracts summary fields from a stored CASE/UCO document.
//
// The facets are read through the public accessor rather than by re-walking the
// JSON here, so that a change to the ontology mapping only has to be made in
// one place.
func parseCASESummary(raw []byte) (caseSummary, error) {
	var out caseSummary

	bundle, err := format.ParseBundle(raw)
	if err != nil {
		return out, fmt.Errorf("grpc: parse CASE bundle: %w", err)
	}

	if v, ok := bundle.FindFacetValue("fr:TriggerFacet", "fr:ruleName"); ok {
		out.rule, _ = v.(string)
	}
	if v, ok := bundle.FindFacetValue("fr:TriggerFacet", "fr:severity"); ok {
		out.severity, _ = v.(string)
	}
	if v, ok := bundle.FindFacetValue("fr:ContainerFacet", "fr:podName"); ok {
		out.podName, _ = v.(string)
	}
	if v, ok := bundle.FindFacetValue("fr:ContainerFacet", "fr:podNamespace"); ok {
		out.podNamespace, _ = v.(string)
	}
	if v, ok := bundle.FindFacetValue("fr:ContainerFacet", "fr:containerID"); ok {
		out.containerID, _ = v.(string)
	}

	return out, nil
}
