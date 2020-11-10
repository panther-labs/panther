package models

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

import "time"

const (
	DefaultPage            = 1
	DefaultPageSize        = 25
	DefaultLimitTopFailing = 10 // GetOrgOverview
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type ComplianceStatus string

const (
	StatusPass  ComplianceStatus = "PASS"
	StatusFail  ComplianceStatus = "FAIL"
	StatusError ComplianceStatus = "ERROR"
)

// LambdaInput is the request structure for the compliance-api Lambda function.
type LambdaInput struct {
	DescribeOrg      *DescribeOrgInput      `json:"describeOrg"`
	DescribePolicy   *DescribePolicyInput   `json:"describePolicy"`
	DescribeResource *DescribeResourceInput `json:"describeResource"`
	GetOrgOverview   *GetOrgOverviewInput   `json:"getOrgOverview"`
	GetStatus        *GetStatusInput        `json:"getStatus"`

	DeleteStatus   *DeleteStatusInput   `json:"deleteStatus"`
	SetStatus      *SetStatusInput      `json:"setStatus"`
	UpdateMetadata *UpdateMetadataInput `json:"updateMetadata"`
}

// List pass/fail status for every policy or resource in the org
// TODO - handle responses > 6MB
//
// The resources-api and policy-api load and cache all pass/fail information
// so they can filter and sort their respective lists.
//
// For example,
// {
//    "describeOrg": {"type": "policy"}
// }
//
// might return
// {
//     "policies": [  (or "resources")
//         {
//             "id":       "AWS.S3.EncryptionEnabled",
//             "status":   "ERROR|FAIL|PASS",
//         }
//     ]
// }
type DescribeOrgInput struct {
	// Which type of information is returned
	Type string `json:"type" validate:"oneof=policy resource"`
}

type DescribeOrgOutput struct {
	Policies  []ItemSummary `json:"policies"`
	Resources []ItemSummary `json:"resources"`
}

// Summary of a single policy or resource compliance status
type ItemSummary struct {
	// Policy/resource ID
	ID string `json:"id"`

	// Compliance status for a policy/resource pair
	Status ComplianceStatus `json:"status"`
}

// The UI policy detail page shows pass/fail counts and pages through affected resources.
// TODO - add sorting options
// TODO - use cursor-based pagination
//
// For example,
// {
//     "describePolicy": {
//         "policyId": "AWS.S3.BucketEncryptionEnabled", // can be url-encoded
//         "page": 1,
//         "pageSize": 25,
//         "suppressed": false
//     }
// }
//
// might return:
// {
//     "items": [
//         {
//             "errorMessage":   "ZeroDivisionError",
//             "lastUpdated":    "2019-08-22T00:00:00Z",
//             "policyId":       "AWS.S3.BucketEncryptionEnabled",
//             "policySeverity": "MEDIUM",
//             "resourceId":     "arn:aws:s3:::my-bucket",
//             "resourceType":   "AWS.S3.Bucket",
//             "status":         "ERROR",
//             "suppressed":     false,
//             "integrationId":  "ff76ea2a-5afc-4005-9e77-61a32c4c365f"
//         },
//         {
//             "lastUpdated":    "2019-08-22T00:00:00Z",
//             "policyId":       "AWS.S3.BucketEncryptionEnabled",
//             "policySeverity": "MEDIUM",
//             "resourceId":     "arn:aws:s3:::my-other-bucket",
//             "resourceType":   "AWS.S3.Bucket",
//             "status":         "PASS",
//             "suppressed":     false,
//             "integrationId":  "ff76ea2a-5afc-4005-9e77-61a32c4c365f"
//         }
//    ],
//    "paging": {
//        "thisPage": 1,
//        "totalPages": 15,
//        "totalItems": 123
//    },
//    "status": "ERROR",
//    "totals": {  // global totals - will be the same regardless of paging/filtering
//        "active":     {"error": 0, "fail": 4, "pass": 10},
//        "suppressed": {"error": 0, "fail": 4, "pass": 5}
//    }
// }
type DescribePolicyInput struct {
	PolicyID string `json:"policyId" validate:"required"` // URL-encoded

	// Which page of results to retrieve
	Page int `json:"page" validate:"omitempty,min=1"`

	// Number of items in each page of results (DefaultPageSize if not specified)
	PageSize int `json:"pageSize" validate:"omitempty,min=1,max=1000"`

	// Include only policies which match the given compliance status
	Status ComplianceStatus `json:"status" validate:"omitempty,oneof=ERROR FAIL PASS"`

	// Include only policies which are or are not suppressed
	Suppressed *bool `json:"suppressed"`
}

// The UI resource detail page shows pass/fail counts and pages through applied policies.
type DescribeResourceInput struct {
	ResourceID string `json:"resourceId" validate:"required"` // URL-encoded

	// Which page of results to retrieve
	Page int `json:"page" validate:"omitempty,min=1"`

	// Number of items in each page of results (DefaultPageSize if not specified)
	PageSize int `json:"pageSize" validate:"omitempty,min=1,max=1000"`

	// Include only policies with this severity
	Severity Severity `json:"severity" validate:"omitempty,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Include only policies which match the given compliance status
	Status ComplianceStatus `json:"status" validate:"omitempty,oneof=ERROR FAIL PASS"`

	// Include only policies which are or are not suppressed
	Suppressed *bool `json:"suppressed"`
}

// Returned from DescribePolicy and DescribeResource
type PolicyResourceDetail struct {
	Items  []ComplianceEntry   `json:"items"`
	Paging Paging              `json:"paging"`
	Status ComplianceStatus    `json:"status"` // overall compliance status
	Totals ActiveSuppressCount `json:"totals"`
}

type ComplianceEntry struct {
	// Python error message when policy was applied to this resource
	ErrorMessage string `json:"errorMessage"`

	// Dynamo TTL - unix time when the status will be automatically cleared
	ExpiresAt int64 `json:"expiresAt"`

	// IntegrationID where the resource was discovered
	IntegrationID string `json:"integrationId"`

	// When the compliance state was last updated in the Panther database
	LastUpdated time.Time `json:"lastUpdated"`

	PolicyID       string   `json:"policyId"`
	PolicySeverity Severity `json:"policySeverity"` // INFO, LOW, MEDIUM, HIGH, or CRITICAL
	ResourceID     string   `json:"resourceId"`
	ResourceType   string   `json:"resourceType"`

	Status ComplianceStatus `json:"status"`

	// True if this resource is ignored/suppressed by this specific policy.
	// Suppressed resources are still analyzed and reported, but not trigger alerts nor remediations.
	Suppressed bool `json:"suppressed"`
}

type Paging struct {
	ThisPage   int `json:"thisPage"`
	TotalPages int `json:"totalPages"`
	TotalItems int `json:"totalItems"`
}

type ActiveSuppressCount struct {
	Active     StatusCount `json:"active"`
	Suppressed StatusCount `json:"suppressed"`
}

type StatusCount struct {
	Error int `json:"error"`
	Fail  int `json:"fail"`
	Pass  int `json:"pass"`
}

// The UI dashboard shows:
//   - failing policy counts by severity
//   - total number of failing resources
//   - top failing policies/resources
//
// Example: {
//     "getOrgOverview": {"limitTopFailing": 10}
// }
//
// Note that errors can generally be considered failures - it means the Python policy failed
// to analyze a specific resource. Suppressions are not included in any counts.
//
// Response (OrgSummary): {
//     "appliedPolicies": {
//         // This ONLY includes enabled policies which scanned at least one resource.
//         "info":     {"error": 0, "fail": 10, "pass": 0},
//         "low":      {"error": 0, "fail": 10, "pass": 0},
//         "medium":   {"error": 0, "fail": 10, "pass": 0},
//         "high":     {"error": 0, "fail": 10, "pass": 0},
//         "critical": {"error": 0, "fail": 10, "pass": 0}
//     },
//     "scannedResources": {
//         // This ONLY includes resources with at least one applicable policy.
//         // There could be more resources in the account (e.g. with no policies for them).
//         "byType": [
//             {
//                 "count": {"error": 0, "fail": 5, "pass": 1},
//                 "type": "AWS.S3.Bucket"
//             }
//         ],
//     },
//     "topFailingPolicies": [
//         {
//             "count":     {"error": 1, "fail": 10, "pass": 0},
//             "id":        "AWS.S3.BlockPublicAccess",
//             "severity":  "CRITICAL",
//         },
//         {
//             "count":    {"error": 0, "fail": 20, "pass": 9},
//             "id":       "AWS.S3.VersioningEnabled",
//             "severity": "MEDIUM",
//         }
//     ],
//     "topFailingResources": [
//         {
//             "count": {
//                 "info":     {"error": 0, "fail": 10, "pass": 0},
//                 "low":      {"error": 0, "fail": 10, "pass": 0},
//                 "medium":   {"error": 0, "fail": 10, "pass": 0},
//                 "high":     {"error": 0, "fail": 10, "pass": 0},
//                 "critical": {"error": 0, "fail": 10, "pass": 0}
//             }
//             "id":     "arn:aws:s3:::my-bucket",
//             "type":   "AWS.S3.Bucket"
//         }
//     ]
// }
type GetOrgOverviewInput struct {
	LimitTopFailing int `json:"limitTopFailing" validate:"min=0,max=500"`
}

type OrgSummary struct {
	AppliedPolicies     StatusCountBySeverity `json:"appliedPolicies"`
	ScannedResources    ScannedResources      `json:"scannedResources"`
	TopFailingPolicies  []PolicySummary       `json:"topFailingPolicies"`
	TopFailingResources []ResourceSummary     `json:"topFailingResources"`
}

type StatusCountBySeverity struct {
	Info     StatusCount `json:"info"`
	Low      StatusCount `json:"low"`
	Medium   StatusCount `json:"medium"`
	High     StatusCount `json:"high"`
	Critical StatusCount `json:"critical"`
}

type ScannedResources struct {
	ByType []ResourceOfType `json:"byType"`
}

type ResourceOfType struct {
	Count StatusCount `json:"count"`
	Type  string      `json:"type"`
}

// Summary of a single policy compliance status
type PolicySummary struct {
	Count    StatusCount `json:"count"`
	ID       string      `json:"id"`
	Severity Severity    `json:"severity"`
}

// Summary of a single resource compliance status
type ResourceSummary struct {
	Count StatusCountBySeverity `json:"count"`
	ID    string                `json:"id"`
	Type  string                `json:"type"`
}

// Get compliance status for a single policy/resource pair
//
// The alert-processor verifies a resource is still failing a specific policy
// before proceeding to deliver the remediation and/or alert.
type GetStatusInput struct {
	PolicyID   string `json:"policyId" validate:"required"`
	ResourceID string `json:"resourceId" validate:"required"`
}

// Delete the compliance status associated with one or more policies or resources
//
// The policy-api deletes statuses when a policy is disabled or deleted or no longer applies to a resource type, and
// the resources-api deletes statuses when a resource is deleted.
type DeleteStatusInput struct {
	Entries []DeleteStatusEntry `json:"entries" validate:"min=1,dive"`
}

type DeleteStatusEntry struct {
	// Exactly one of the following must be specified:
	Policy   *DeletePolicy   `json:"policy" validate:"required_without=Resource"`
	Resource *DeleteResource `json:"resource" validate:"required_without=Policy"`
}

type DeletePolicy struct {
	ID string `json:"id" validate:"required"`

	// Only delete entries with these specific resource types
	ResourceTypes []string `validate:"dive,required"`
}

type DeleteResource struct {
	ID string `json:"id" validate:"required"`
}

// Set the compliance status for a batch of resource/policy pairs.
//
// The resource-processor analyzes each modified resource and posts the results here.
type SetStatusInput struct {
	Entries []SetStatusEntry `json:"entries" validate:"min=1,dive"`
}

type SetStatusEntry struct {
	ErrorMessage   string           `json:"errorMessage"`
	IntegrationID  string           `json:"integrationId" validate:"required"`
	PolicyID       string           `json:"policyId" validate:"required"`
	PolicySeverity Severity         `json:"policySeverity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	ResourceID     string           `json:"resourceId" validate:"required"`
	ResourceType   string           `json:"resourceType" validate:"required"`
	Status         ComplianceStatus `json:"status" validate:"oneof=ERROR PASS FAIL"`
	Suppressed     bool             `json:"suppressed"`
}

// The policy-api updates the relevant policy attributes here when they change (severity/suppressions).
// For these updates, we don't need to re-scan the resources and can instead directly modify the compliance state.
type UpdateMetadataInput struct {
	PolicyID     string   `json:"policyId" validate:"required"`
	Severity     Severity `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Suppressions []string `json:"suppressions"`
}
