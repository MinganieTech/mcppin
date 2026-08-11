// SARIF 2.1.0 output, so a run can be read by the code scanning a repository
// already has rather than by a parser somebody has to write first.
package mcppin

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// Two statements are not policy findings and still belong in the report: a
// digest that could not be compared and a capture that admits it is partial.
// Silence about either would read as coverage.
const (
	ruleUndecidableDigest = "undecidable-digest"
	ruleIncompleteCapture = "incomplete-capture"
	ruleUnexaminedServer  = "unexamined-server"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     sarifText          `json:"shortDescription"`
	FullDescription      sarifText          `json:"fullDescription"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

var ruleDescriptions = map[string]string{
	PolicyToolChanged:      "An approved tool no longer canonicalises to what was approved.",
	PolicyToolAdded:        "A server offers a tool nobody approved.",
	PolicyToolRemoved:      "An approved tool is no longer offered.",
	PolicyNameCollision:    "Two servers offer the same tool name, and nothing says which one an agent meant.",
	PolicyHiddenCharacters: "A string in the tool object carries characters that occupy no visible space.",
	PolicyMixedScriptName:  "A tool name draws on several writing systems, which is how one name is made to look like another.",
	PolicyInvalidToolName:  "A tool name carries characters outside A-Za-z0-9._- .",
	PolicyServerRenamed:    "A server no longer calls itself what it called itself when it was approved.",
	PolicyProtocolChanged:  "A server negotiated a different protocol revision than the one the surface was approved over.",
	ruleUndecidableDigest:  "A tool carries a number the canonical form does not identify, so it has no digest worth comparing.",
	ruleIncompleteCapture:  "The capture says it does not hold every tool, so absence proves nothing.",
	ruleUnexaminedServer:   "An approved server was outside what this capture claims to cover, and was not compared.",
}

// undecidable names the rules that are not policies. They are never gated and
// they always fail the run, with exit 3, so they are errors: a dashboard that
// showed them as warnings would disagree with the pipeline about the same run.
var undecidable = map[string]bool{
	ruleUndecidableDigest: true,
	ruleIncompleteCapture: true,
	ruleUnexaminedServer:  true,
}

// severityOf keeps SARIF and the exit code telling the same story.
func severityOf(rule string, gated map[string]bool) string {
	if gated[rule] || undecidable[rule] {
		return "error"
	}
	return "warning"
}

// WriteSARIF emits the run as SARIF 2.1.0. What fails the run is an error and
// what is only reported is a warning: the severity has to agree with the exit
// code, or a dashboard and a pipeline will disagree about the same run.
func WriteSARIF(w io.Writer, result Result, gate []string, manifestPath string) error {
	gated := make(map[string]bool, len(gate))
	for _, policy := range gate {
		gated[policy] = true
	}

	rules := make([]sarifRule, 0, len(ruleDescriptions))
	for _, id := range append(Policies(), ruleUndecidableDigest, ruleIncompleteCapture, ruleUnexaminedServer) {
		description, described := ruleDescriptions[id]
		if !described {
			// A rule with no description is a rule somebody added in one place
			// and not the other, and it reaches a dashboard as a blank line.
			description = "This build declares " + id + " and has no description for it, which is a bug in mcppin."
		}
		rules = append(rules, sarifRule{
			ID:                   id,
			Name:                 id,
			ShortDescription:     sarifText{Text: description},
			FullDescription:      sarifText{Text: description},
			DefaultConfiguration: sarifConfiguration{Level: severityOf(id, gated)},
		})
	}

	location := []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(manifestPath)},
	}}}
	results := make([]sarifResult, 0, len(result.Findings)+len(result.Unstable)+1)
	for _, finding := range result.Findings {
		results = append(results, sarifResult{
			RuleID:    finding.Policy,
			Level:     severityOf(finding.Policy, gated),
			Message:   sarifText{Text: sarifMessage(finding)},
			Locations: location,
			PartialFingerprints: map[string]string{
				"mcppin/v1": fingerprint(finding.Policy, finding.Server, finding.Tool),
			},
		})
	}
	for _, unstable := range result.Unstable {
		results = append(results, sarifResult{
			RuleID: ruleUndecidableDigest,
			Level:  severityOf(ruleUndecidableDigest, gated),
			Message: sarifText{Text: fmt.Sprintf("%s %s carries %s (%s), which the canonical form does not identify",
				Printable(unstable.Server), Printable(unstable.Tool),
				Printable(strings.Join(unstable.Literals, ", ")), unstable.Where)},
			Locations: location,
			PartialFingerprints: map[string]string{
				"mcppin/v1": fingerprint(ruleUndecidableDigest, unstable.Server, unstable.Tool),
			},
		})
	}
	for _, server := range result.Unexamined {
		results = append(results, sarifResult{
			RuleID: ruleUnexaminedServer,
			Level:  severityOf(ruleUnexaminedServer, gated),
			Message: sarifText{Text: fmt.Sprintf(
				"%s was approved and this capture did not claim to cover it", Printable(server))},
			Locations: location,
			PartialFingerprints: map[string]string{
				"mcppin/v1": fingerprint(ruleUnexaminedServer, server, ""),
			},
		})
	}
	if !result.CaptureComplete {
		message := "the capture says it does not hold every tool the servers offered"
		for _, unseen := range result.Unseen {
			message += fmt.Sprintf("; %s %s was approved and was not in it",
				Printable(unseen.Server), Printable(unseen.Tool))
		}
		results = append(results, sarifResult{
			RuleID:              ruleIncompleteCapture,
			Level:               severityOf(ruleIncompleteCapture, gated),
			Message:             sarifText{Text: message},
			Locations:           location,
			PartialFingerprints: map[string]string{"mcppin/v1": fingerprint(ruleIncompleteCapture, "", "")},
		})
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "mcppin",
				Version:        Version,
				InformationURI: "https://github.com/MinganieTech/mcppin",
				Rules:          rules,
			}},
			Results: results,
		}},
	})
}

// sarifMessage renders a finding for a viewer. Served text is named by code
// point here as it is on a console: a SARIF message is displayed to a person,
// and the text in it is the attacker's.
func sarifMessage(finding Finding) string {
	message := Printable(finding.Detail)
	if finding.Server != "" {
		message = Printable(finding.Server) + ": " + message
	}
	for _, change := range finding.Changes {
		message += fmt.Sprintf("\n%s\n- %s\n+ %s",
			Printable(change.Pointer), printableValue(change.Before), printableValue(change.After))
	}
	return message
}

func fingerprint(parts ...string) string {
	return strings.Join(parts, "/")
}
