package mcppin

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ReportSchemaVersion versions the JSON report. Adding a field is free;
// removing one or changing what it means bumps this number. Version 2 keys
// findings by server identity rather than by reported name, and carries the
// diff and the completeness of the capture.
const ReportSchemaVersion = 2

// maxRenderedValue bounds one side of one change in the text report. The JSON
// report carries the whole value; a console does not need a schema pasted into
// it.
const maxRenderedValue = 200

type jsonReport struct {
	SchemaVersion int      `json:"schema_version"`
	Tool          string   `json:"tool"`
	Version       string   `json:"version"`
	Gate          []string `json:"gate"`
	// Status and ExitCode are the run's own verdict. A reader that had to
	// re-derive them from the findings would be writing a second copy of the
	// rule, and the two copies would disagree eventually.
	Status          string         `json:"status"`
	ExitCode        int            `json:"exit_code"`
	CaptureComplete bool           `json:"capture_complete"`
	SignedBy        string         `json:"signed_by,omitempty"`
	Findings        []Finding      `json:"findings"`
	Unstable        []UnstableTool `json:"unstable_digests"`
	Unseen          []UnseenTool   `json:"unseen_tools"`
}

// Outcome is the verdict a run reaches, and the exit code that carries it.
// The text, the JSON and the process agree because they all come from here.
func Outcome(result Result, gate []string) (string, int) {
	for _, policy := range gate {
		if len(result.FindingsFor(policy)) > 0 {
			return "violation", ExitPolicyFailed
		}
	}
	if len(result.Unstable) > 0 || !result.CaptureComplete {
		return "undecidable", ExitUndecidable
	}
	return "clean", ExitOK
}

// WriteJSON emits the machine-readable report. The gate is part of it: a
// reader has to be able to tell a finding the exit code answered for from one
// it only reported.
//
// Values are carried as they were served. This is the one output that is not
// meant for a terminal, so it is the one output that does not rewrite them.
func WriteJSON(w io.Writer, result Result, gate []string) error {
	if gate == nil {
		gate = []string{}
	}
	status, code := Outcome(result, gate)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(jsonReport{
		SchemaVersion:   ReportSchemaVersion,
		Tool:            "mcppin",
		Version:         Version,
		Gate:            gate,
		Status:          status,
		ExitCode:        code,
		CaptureComplete: result.CaptureComplete,
		SignedBy:        result.SignedBy,
		Findings:        result.Findings,
		Unstable:        result.Unstable,
		Unseen:          result.Unseen,
	})
}

// WriteText emits the human-readable report. Output stays ASCII: these tools
// run in CI logs and on Windows consoles whose code page renders anything
// else as a question mark.
//
// Findings are observations. Only the gate summary says PASS or FAIL, and no
// line may read as reassurance while the exit code says otherwise.
func WriteText(w io.Writer, result Result, gate []string) {
	if result.SignedBy != "" {
		fmt.Fprintf(w, "the lockfile is signed by %s\n\n", result.SignedBy)
	}
	if result.clean() {
		fmt.Fprintln(w, "the tool surface matches what was approved")
		fmt.Fprintln(w)
	}

	// Every value below reaches a terminal through Printable. The names and
	// the details are the server's text as much as a description is.
	currentPolicy := ""
	for _, finding := range result.Findings {
		if finding.Policy != currentPolicy {
			currentPolicy = finding.Policy
			fmt.Fprintf(w, "VIOLATION %s\n", currentPolicy)
		}
		if finding.Server != "" {
			fmt.Fprintf(w, "  %s: %s\n", Printable(finding.Server), Printable(finding.Detail))
		} else {
			fmt.Fprintf(w, "  %s\n", Printable(finding.Detail))
		}
		writeChanges(w, finding.Changes)
	}
	if len(result.Findings) > 0 {
		fmt.Fprintln(w)
	}

	if len(result.Unstable) > 0 {
		fmt.Fprintf(w, "UNDECIDABLE: %d tool(s) carry a number this canonicalisation does not identify\n",
			len(result.Unstable))
		for _, unstable := range result.Unstable {
			fmt.Fprintf(w, "  %s %s (%s): %s\n", Printable(unstable.Server), Printable(unstable.Tool),
				unstable.Where, Printable(strings.Join(unstable.Literals, ", ")))
		}
		fmt.Fprintf(w, "  they have no digest worth comparing and prove nothing either way\n\n")
	}

	if !result.CaptureComplete {
		fmt.Fprintln(w, "INCOMPLETE: the capture says it does not hold every tool the servers offered")
		for _, unseen := range result.Unseen {
			fmt.Fprintf(w, "  %s %s was approved and was not in the capture\n",
				Printable(unseen.Server), Printable(unseen.Tool))
		}
		fmt.Fprintln(w, "  nothing here can prove a tool was withdrawn, and a tool added after the")
		fmt.Fprintln(w, "  capture stopped was never seen. Fix the exporter before trusting this run.")
		fmt.Fprintln(w)
	}

	if len(gate) == 0 {
		fmt.Fprintln(w, "NO GATE: -fail-on none was requested, so nothing above changes the exit code")
		return
	}
	for _, policy := range gate {
		found := result.FindingsFor(policy)
		switch {
		case len(found) > 0:
			fmt.Fprintf(w, "FAIL %s: %d finding(s)\n", policy, len(found))
		case policy == PolicyToolChanged && len(result.Unstable) > 0,
			policy == PolicyToolRemoved && !result.CaptureComplete,
			policy == PolicyToolAdded && !result.CaptureComplete:
			// Nothing was proven among what could be compared, and what could
			// not be compared is exactly where a departure would hide. That is
			// not a pass, and it must not be printed as one.
			fmt.Fprintf(w, "PARTIAL %s: the comparison was not complete\n", policy)
		default:
			fmt.Fprintf(w, "PASS %s\n", policy)
		}
	}
}

func (r Result) clean() bool {
	return len(r.Findings) == 0 && len(r.Unstable) == 0 && len(r.Unseen) == 0 && r.CaptureComplete
}

func writeChanges(w io.Writer, changes []Change) {
	for _, change := range changes {
		where := Printable(change.Pointer)
		if where == "" {
			where = "the tool object"
		}
		fmt.Fprintf(w, "    %s\n", where)
		if change.Before != "" || change.Kind != changeAdded {
			fmt.Fprintf(w, "    - %s\n", printableValue(change.Before))
		}
		if change.After != "" || change.Kind != changeRemoved {
			fmt.Fprintf(w, "    + %s\n", printableValue(change.After))
		}
	}
}

// Printable renders text that came from a server on a console that must not
// be asked to interpret it. Everything outside printable ASCII is named by
// code point.
//
// Every string in a report is attacker-controlled somewhere: a description, a
// tool name, a server's own error message, the line it wrote to its standard
// error. Printing one verbatim would hand a terminal escape, a right-to-left
// override or a zero-width character straight to the reviewer the report is
// meant to inform - and an ANSI sequence can erase the line above it, which is
// where the finding was.
func Printable(text string) string {
	// Every character that is not plain ASCII is named the same way, U+FFFD
	// included. Calling that one "invalid UTF-8" would be wrong twice over:
	// invalid UTF-8 never gets this far, so a replacement character here is
	// one a server sent on purpose, and saying otherwise would describe the
	// reader's failure instead of the server's text.
	var out strings.Builder
	for _, r := range text {
		if r >= 0x20 && r < 0x7F {
			out.WriteRune(r)
			continue
		}
		fmt.Fprintf(&out, "<U+%04X>", r)
	}
	return out.String()
}

// printableValue is Printable for one side of a diff, where a whole schema
// pasted into a console helps nobody. The JSON report carries the value whole.
func printableValue(text string) string {
	rendered := Printable(text)
	if len(rendered) <= maxRenderedValue {
		return rendered
	}
	// Cut on the rendered form, which is ASCII, so the cut cannot land inside
	// a character or inside a <U+XXXX> name.
	cut := maxRenderedValue
	if marker := strings.LastIndex(rendered[:cut], "<U+"); marker > cut-8 {
		cut = marker
	}
	return rendered[:cut] + "..."
}
