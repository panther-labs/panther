package analysis

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// PolicyEngineInput is the request format for invoking the panther-policy-engine Lambda function.
type PolicyEngineInput struct {
	Policies  []Policy   `json:"policies"`
	Resources []Resource `json:"resources"`
}

// Policy is a subset of the policy fields needed for analysis, returns True if compliant.
type Policy struct {
	Body          string   `json:"body"`
	ID            string   `json:"id"`
	ResourceTypes []string `json:"resourceTypes"`
}

// Resource is a subset of the resource fields needed for analysis.
type Resource struct {
	Attributes interface{} `json:"attributes"`
	ID         string      `json:"id"`
	Type       string      `json:"type"`
}

// PolicyEngineOutput is the response format returned by the panther-policy-engine Lambda function.
type PolicyEngineOutput struct {
	Resources []Result `json:"resources"`
}

// Result is the analysis result for a single resource.
type Result struct {
	ID      string        `json:"id"` // resourceID
	Errored []PolicyError `json:"errored"`
	Failed  []string      `json:"failed"` // set of non-compliant policy IDs
	Passed  []string      `json:"passed"` // set of compliant policy IDs
}

// PolicyError indicates an error when evaluating a policy.
type PolicyError struct {
	ID      string `json:"id"`      // policy ID which caused runtime error
	Message string `json:"message"` // error message
}

// ##### Log Analysis #####

// RulesEngineInput is the request format when doing event-driven log analysis.
type RulesEngineInput struct {
	Rules  []Rule  `json:"rules"`
	Events []Event `json:"events"`
}

// Rule evaluates streaming logs, returning True if an alert should be triggered.
type Rule struct {
	Body     string   `json:"body"`
	ID       string   `json:"id"`
	LogTypes []string `json:"logTypes"`
}

// Event is a security log to be analyzed, e.g. a  CloudTrail event.
type Event struct {
	Data  interface{}       `json:"data"`
	ID    string            `json:"id"`
	Mocks map[string]string `json:"mocks"`
}

// RulesEngineOutput is the response returned when invoking in log analysis mode.
type RulesEngineOutput struct {
	Results []RuleResult `json:"results"`
}

// The result of a evaluating a rule with an event.
//nolint:maligned
type RuleResult struct {
	ID         string `json:"id"`
	RuleID     string `json:"ruleId"`
	RuleOutput bool   `json:"ruleOutput"`
	// Rule function outputs
	RuleError          string   `json:"ruleError"`
	TitleOutput        string   `json:"titleOutput"`
	TitleError         string   `json:"titleError"`
	DescriptionOutput  string   `json:"descriptionOutput"`
	DescriptionError   string   `json:"descriptionError"`
	ReferenceOutput    string   `json:"referenceOutput"`
	ReferenceError     string   `json:"referenceError"`
	SeverityOutput     string   `json:"severityOutput"`
	SeverityError      string   `json:"severityError"`
	RunbookOutput      string   `json:"runbookOutput"`
	RunbookError       string   `json:"runbookError"`
	DestinationsOutput []string `json:"destinationsOutput"`
	DestinationsError  string   `json:"destinationsError"`
	DedupOutput        string   `json:"dedupOutput"`
	DedupError         string   `json:"dedupError"`
	AlertContextOutput string   `json:"alertContextOutput"`
	AlertContextError  string   `json:"alertContextError"`
	// Indicates general error in the Python script (import error, syntax error, etc).
	GenericError string `json:"genericError"`
	// True if any error (generic or from rule functions) is included in the result.
	Errored bool `json:"errored"`
}
