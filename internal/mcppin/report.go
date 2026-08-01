package mcppin

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ReportSchemaVersion versions the JSON report. Adding a field is free;
// removing one or changing what it means bumps this number.
const ReportSchemaVersion = 1

type jsonReport struct {
	SchemaVersion int            `json:"schema_version"`
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	Findings      []Finding      `json:"findings"`
	Unstable      []UnstableTool `json:"unstable_digests"`
}

// WriteJSON emits the machine-readable report.
func WriteJSON(w io.Writer, result Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonReport{
		SchemaVersion: ReportSchemaVersion,
		Tool:          "mcppin",
		Version:       Version,
		Findings:      result.Findings,
		Unstable:      result.Unstable,
	})
}

// WriteText emits the human-readable report. Output stays ASCII: these tools
// run in CI logs and on Windows consoles whose code page renders anything
// else as a question mark.
//
// Findings are observations. Only the gate summary says PASS or FAIL, and no
// line may read as reassurance while the exit code says otherwise.
func WriteText(w io.Writer, result Result, requested []string) {
	if len(result.Findings) == 0 && len(result.Unstable) == 0 {
		fmt.Fprintln(w, "the tool surface matches what was approved")
		fmt.Fprintln(w)
	}

	currentPolicy := ""
	for _, finding := range result.Findings {
		if finding.Policy != currentPolicy {
			currentPolicy = finding.Policy
			fmt.Fprintf(w, "VIOLATION %s\n", currentPolicy)
		}
		if finding.Server != "" {
			fmt.Fprintf(w, "  %s: %s\n", finding.Server, finding.Detail)
		} else {
			fmt.Fprintf(w, "  %s\n", finding.Detail)
		}
	}
	if len(result.Findings) > 0 {
		fmt.Fprintln(w)
	}

	if len(result.Unstable) > 0 {
		fmt.Fprintf(w, "UNDECIDABLE: %d tool(s) carry a number this canonicalisation cannot hold exactly\n",
			len(result.Unstable))
		for _, unstable := range result.Unstable {
			fmt.Fprintf(w, "  %s %s: %s\n", unstable.Server, unstable.Tool, strings.Join(unstable.Literals, ", "))
		}
		fmt.Fprintf(w, "  their digests are not reproducible and must not be presented as evidence\n\n")
	}

	for _, policy := range requested {
		if found := result.FindingsFor(policy); len(found) > 0 {
			fmt.Fprintf(w, "FAIL %s: %d finding(s)\n", policy, len(found))
		} else {
			fmt.Fprintf(w, "PASS %s\n", policy)
		}
	}
}
