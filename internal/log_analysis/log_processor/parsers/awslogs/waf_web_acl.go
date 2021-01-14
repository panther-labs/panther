package awslogs

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

import (
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// AWS WAF Web ACL Log event structure: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
// File naming convention follows the Firehose delivery stream pattern:
// - https://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html#s3-object-name
// - The prefix `aws-waf-logs-` is mandatory for Web ACL logging delivery stream names.
// nolint:lll,maligned
type WAFWebACL struct {
	Action pantherlog.String `json:"action" validate:"required" description:"The action applied by WAF. Possible values for a terminating rule: ALLOW and BLOCK. COUNT is not a valid value for a terminating rule."`
	FormatVersion pantherlog.Uint8 `json:"formatVersion" description:"The format version for the log."`
	HTTPRequest HTTPRequest `json:"httpRequest" description:"The metadata about the request."`
	HTTPSourceID pantherlog.String `json:"httpSourceId" description:"The source ID. This field shows the ID of the associated resource."`
	HTTPSourceName pantherlog.String `json:"httpSourceName" description:"The source of the request. Possible values: CF for Amazon CloudFront, APIGW for Amazon API Gateway, ALB for Application Load Balancer, and APPSYNC for AWS AppSync."`
	NonTerminatingMatchingRules []RuleDetail `json:"nonTerminatingMatchingRules" description:"The list of non-terminating rules in the rule group that match the request. These are always COUNT rules (non-terminating rules that match)."`
	RateBasedRuleList []RateBasedRuleListDetail `json:"rateBasedRuleList" description:"The list of rate-based rules that acted on the request."`
	RuleGroupList []RuleGroupListDetail `json:"ruleGroupList" description:"The list of rule groups that acted on this request. In the preceding code example, there is only one."`
	TerminatingRuleID pantherlog.String `json:"terminatingRuleId"`
	TerminatingRuleMatchDetails []RuleMatchDetail `json:"terminatingRuleMatchDetails" description:"Detailed information about the terminating rule that matched the request. A terminating rule has an action that ends the inspection process against a web request. Possible actions for a terminating rule are ALLOW and BLOCK. This is only populated for SQL injection and cross-site scripting (XSS) match rule statements. As with all rule statements that inspect for more than one thing, AWS WAF applies the action on the first match and stops inspecting the web request. A web request with a terminating action could contain other threats, in addition to the one reported in the log."`
	TerminatingRuleType pantherlog.String `json:"terminatingRuleType" description:"The type of rule that terminated the request. Possible values: RATE_BASED, REGULAR, GROUP, and MANAGED_RULE_GROUP."`
	Timestamp pantherlog.Time `json:"timestamp" tcodec:"unix_ms" event_time:"true" description:"The timestamp in milliseconds."`
	WebACLID pantherlog.String `json:"webaclId" description:"The GUID of the web ACL."`
}

// nolint:lll,maligned
type RuleGroupListDetail struct {
	ExcludedRules []ExcludedRule `json:"excludedRules" description:"The list of rules in the rule group that you have excluded. The action for these rules is set to COUNT."`
	NonTerminatingMatchingRules []RuleDetail `json:"nonTerminatingMatchingRules"`
	RuleGroupID pantherlog.String `json:"ruleGroupId"`
	TerminatingRule *RuleDetail `json:"terminatingRule"`
}

// nolint:lll,maligned
type ExcludedRule struct {
	ExclusionType pantherlog.String `json:"exclusionType" description:"A type that indicates that the excluded rule has the action COUNT (most likely value is EXCLUDED_AS_COUNT)."`
	RuleID pantherlog.String `json:"ruleId" description:"The ID of the rule within the rule group that is excluded."`
}

// nolint:lll,maligned
type RuleDetail struct {
	RuleID pantherlog.String `json:"ruleId" description:"The Rule ID."`
	Action pantherlog.String `json:"action" description:"The configured rule action. For non-terminating rules the value is always COUNT."`
	RuleMatchDetails *[]RuleMatchDetail `json:"ruleMatchDetails" description:"Detailed information about the rule that matched the request. This field is only populated for SQL injection and cross-site scripting (XSS) match rule statements."`
}

// nolint:lll,maligned
type RuleMatchDetail struct {
	ConditionType pantherlog.String `json:"conditionType" description:"The vulnerability type, either SQL_INJECTION or XSS"`
	Location pantherlog.String `json:"location" description:"The request parameter type that provided the match. Can be ALL_QUERY_ARGS, HEADER etc."`
	MatchedData []string `json:"matchedData" description:"The list of strings that provides the match, e.g. [\"10\", \"AND\", \"1\"]"`
}

// nolint:lll,maligned
type RateBasedRuleListDetail struct {
	LimitKey pantherlog.String `json:"limitKey"`
	LimitValue pantherlog.String `json:"limitValue"`
	MaxRateAllowed pantherlog.Uint32 `json:"maxRateAllowed"`
	RateBasedRuleID pantherlog.String `json:"rateBasedRuleId"`
	RateBasedRuleName pantherlog.String `json:"rateBasedRuleName"`
}

// nolint:lll,maligned
type HTTPRequest struct {
	Args pantherlog.String `json:"args" description:"The HTTP Request query string."`
	ClientIP pantherlog.String `json:"clientIp" panther:"ip" description:"The IP address of the client sending the request."`
	Country pantherlog.String `json:"country" description:"The source country of the request. If AWS WAF is unable to determine the country of origin, it sets this field to -."`
	Headers []HTTPHeader `json:"headers" description:"The list of headers."`
	HTTPMethod pantherlog.String `json:"httpMethod" description:"The HTTP method in the request."`
	HTTPVersion pantherlog.String `json:"httpVersion" description:"The HTTP version, e.g. HTTP/2.0."`
	RequestID pantherlog.String `json:"requestId" panther:"trace_id" description:"The ID of the request, which is generated by the underlying host service. For Application Load Balancer, this is the trace ID. For all others, this is the request ID."`
	URI pantherlog.String `json:"uri" description:"The URI of the request."`
}

// nolint:lll,maligned
type HTTPHeader struct {
	// Maybe we should apply some normalization here, e.g. always convert to lowercase?
	Name pantherlog.String `json:"name" description:"The header name."`
	Value pantherlog.String `json:"value" description:"The header value."`
}
