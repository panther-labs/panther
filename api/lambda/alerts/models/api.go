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

// LambdaInput is the request structure for the alerts-api Lambda function.
type LambdaInput struct {
	GetAlert            *GetAlertInput            `json:"getAlert"`
	ListAlerts          *ListAlertsInput          `json:"listAlerts"`
	UpdateAlertStatus   *UpdateAlertStatusInput   `json:"updateAlertStatus"`
	UpdateAlertDelivery *UpdateAlertDeliveryInput `json:"updateAlertDelivery"`
}

// GetAlertInput retrieves details for a single alert.
//
// The response will contain by definition all of the events associated with the alert.
// If `eventPageSize` and `eventPage` are specified, it will returns only the specified events in the response.
// Example:
// {
//     "getAlert": {
//         "alertId": "ruleId-2",
//         "eventsPageSize": 20
//     }
// }
type GetAlertInput struct {
	AlertID                 string  `json:"alertId" validate:"required,hexadecimal,len=32"` // AlertID is an MD5 hash
	EventsPageSize          *int    `json:"eventsPageSize"  validate:"required,min=1,max=50"`
	EventsExclusiveStartKey *string `json:"eventsExclusiveStartKey,omitempty"`
}

// GetAlertOutput retrieves details for a single alert.
type GetAlertOutput = Alert

// ListAlertsInput lists the alerts in reverse-chronological order (newest to oldest)
// If "ruleId" is not set, we return all the alerts for the organization
// If the "exclusiveStartKey" is not set, we return alerts starting from the most recent one. If it is set,
// the output will return alerts starting from the "exclusiveStartKey" exclusive.
//
//
// {
//     "listAlerts": {
//         "ruleId": "My.Rule",
//	    "type" : "RULE_ERROR",
//         "pageSize": 25,
//         "exclusiveStartKey": "abcdef",
//         "severity": ["INFO"],
//         "status": ["TRIAGED"],
//         "nameContains": "string in alert title",
//         "createdAtAfter": "2020-06-17T15:49:40Z",
//         "createdAtBefore": "2020-06-17T15:49:40Z",
//         "eventCountMin": "0",
//         "eventCountMax": "500",
//         "sortDir": "ascending",
//     }
// }
type ListAlertsInput struct {
	// Used for searching as secondary index
	RuleID *string `json:"ruleId"`

	// Number of results to return per query
	PageSize *int `json:"pageSize" validate:"omitempty,min=1,max=50"`

	// Infinite scroll/pagination query key
	ExclusiveStartKey *string `json:"exclusiveStartKey"`

	// Filtering
	Types           []string   `json:"types" validate:"omitempty,dive,oneof=RULE RULE_ERROR POLICY"`
	Severity        []string   `json:"severity" validate:"omitempty,dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	NameContains    *string    `json:"nameContains"`
	Status          []string   `json:"status" validate:"omitempty,dive,oneof=OPEN TRIAGED CLOSED RESOLVED"`
	CreatedAtBefore *time.Time `json:"createdAtBefore"`
	CreatedAtAfter  *time.Time `json:"createdAtAfter"`
	EventCountMin   *int       `json:"eventCountMin" validate:"omitempty,min=0"`
	EventCountMax   *int       `json:"eventCountMax" validate:"omitempty,min=1"`
	LogTypes        []string   `json:"logTypes" validate:"omitempty,dive,required"`
	ResourceTypes   []string   `json:"resourceTypes" validate:"omitempty,dive,required"`
	// Sorting
	SortDir *string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`
}

// UpdateAlertStatusInput updates alert statuses by their IDs
// {
//     "updateAlertStatus": {
//         "alertIds": ["84c3e4b27c702a1c31e6eb412fc377f6"],
//         "status": "CLOSED"
//         // userId is added by AppSync resolver (UpdateAlertStatusResolver)
//         "userId": "5f54cf4a-ec56-44c2-83bc-8b742600f307"
//     }
// }
type UpdateAlertStatusInput struct {
	// ID of the alert to update
	AlertIDs []string `json:"alertIds" validate:"gt=0,dive,hexadecimal,len=32"` // AlertID is an MD5 hash

	// Variables that we allow updating:
	Status string `json:"status" validate:"oneof=OPEN TRIAGED CLOSED RESOLVED"`

	// User who made the change
	UserID string `json:"userId" validate:"uuid4"`
}

// UpdateAlertDeliveryInput updates an alert by its ID
// {
//     "updateAlertDelivery": {
//         "alertId": "84c3e4b27c702a1c31e6eb412fc377f6",
//         "deliveryResponses": [
//           {
//             "outputId": "1f54cf4a-ec56-44c2-83bc-8b742600f307"
//             "message": "gateway timeout",
//             "statusCode": 504,
//             "success": false,
//             "dispatchedAt": "2020-06-17T15:49:40Z",
//           }
//         ]
//     }
// }
type UpdateAlertDeliveryInput struct {
	// ID of the alert to update
	AlertID string `json:"alertId" validate:"hexadecimal,len=32"` // AlertID is an MD5 hash

	// Variables that we allow updating (will be appended)
	DeliveryResponses []*DeliveryResponse `json:"deliveryResponses"`
}

// DeliveryResponse holds the delivery response for data stored in DDB
type DeliveryResponse struct {
	OutputID     string    `json:"outputId" validate:"required,uuid4"`
	Message      string    `json:"message"`
	StatusCode   int       `json:"statusCode"`
	Success      bool      `json:"success"`
	DispatchedAt time.Time `json:"dispatchedAt"`
}

// UpdateAlertStatusOutput is an alias for an alert summary
type UpdateAlertStatusOutput = []*AlertSummary

// UpdateAlertDeliveryOutput is an alias for an alert summary
type UpdateAlertDeliveryOutput = AlertSummary

// Constants defined for alert statuses
const (
	// Open is strictly used for updating/filtering and is not explicitly set on an alert
	OpenStatus = "OPEN"

	// Triaged sets the alert to actively investigating
	TriagedStatus = "TRIAGED"

	// Closed is set for false positive or anything other reason than resolved
	ClosedStatus = "CLOSED"

	// Resolved is set when the issue was found and remediated
	ResolvedStatus = "RESOLVED"
)

// ListAlertsOutput is the returned alert list.
type ListAlertsOutput struct {
	// Alerts is a list of alerts sorted by timestamp descending.
	// Alerts with the same timestamp are returned in ascending order of alert ID.
	Alerts []*AlertSummary `json:"alertSummaries"`
	// LastEvaluatedKey contains the last evaluated alert Id.
	// If it is populated it means there are more alerts available
	// If it is nil, it means there are no more alerts to be returned.
	LastEvaluatedKey *string `json:"lastEvaluatedKey,omitempty"`
}

// AlertSummary contains summary information for an alert
type AlertSummary struct {
	AlertID           string              `json:"alertId"`
	Type              string              `json:"type"`
	RuleID            *string             `json:"ruleId"`
	RuleDisplayName   *string             `json:"ruleDisplayName"`
	RuleVersion       *string             `json:"ruleVersion"`
	DedupString       *string             `json:"dedupString"`
	DeliveryResponses []*DeliveryResponse `json:"deliveryResponses"`
	LogTypes          []string            `json:"logTypes"`
	CreationTime      *time.Time          `json:"creationTime"`
	UpdateTime        *time.Time          `json:"updateTime"`
	EventsMatched     *int                `json:"eventsMatched"`
	Severity          *string             `json:"severity"`
	Status            string              `json:"status,omitempty"`
	Title             *string             `json:"title"`
	LastUpdatedBy     string              `json:"lastUpdatedBy"`
	LastUpdatedByTime time.Time           `json:"lastUpdatedByTime"`
	PolicyID          string              `json:"policyId"`
	PolicyDisplayName string              `json:"policyDisplayName"`
	PolicySourceID    string              `json:"policySourceId"`
	PolicyVersion     string              `json:"policyVersion"`
	ResourceTypes     []string            `json:"resourceTypes"`
	ResourceID        string              `json:"resourceId"`
	// Generated Fields Support
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Runbook     string `json:"runbook"`
}

// Alert contains the details of an alert
type Alert struct {
	AlertSummary
	Events                 []string `json:"events" validate:"required"`
	EventsLastEvaluatedKey *string  `json:"eventsLastEvaluatedKey,omitempty"`
}
