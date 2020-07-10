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
	GetAlert    *GetAlertInput    `json:"getAlert"`
	ListAlerts  *ListAlertsInput  `json:"listAlerts"`
	UpdateAlert *UpdateAlertInput `json:"updateAlert"`
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
	AlertID                 *string `json:"alertId" validate:"required,hexadecimal,len=32"` // AlertID is an MD5 hash
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
//         "pageSize": 25,
//         "exclusiveStartKey": "abcdef",
//         "severity": ["INFO"],
//         "status": ["TRIAGED"],
//         "nameContains": "string in alert title",
//         "createdAtAfter": "2020-06-17T15:49:40Z",
//         "createdAtBefore": "2020-06-17T15:49:40Z",
//         "ruleIdContains": "string in rule id",
//         "alertIdContains": "string in alert id",
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
	Severity        []*string  `json:"severity" validate:"omitempty,dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	NameContains    *string    `json:"nameContains"`
	Status          []*string  `json:"status" validate:"omitempty,dive,oneof=OPEN TRIAGED CLOSED RESOLVED"`
	CreatedAtBefore *time.Time `json:"createdAtBefore"`
	CreatedAtAfter  *time.Time `json:"createdAtAfter"`
	RuleIDContains  *string    `json:"ruleIdContains"`
	AlertIDContains *string    `json:"alertIdContains"`
	EventCountMin   *int       `json:"eventCountMin" validate:"omitempty,min=0"`
	EventCountMax   *int       `json:"eventCountMax" validate:"omitempty,min=1"`

	// Sorting
	SortDir *string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`
}

// UpdateAlertInput updates an alert by its ID
// {
//     "updateAlert": {
//         "alertId": "84c3e4b27c702a1c31e6eb412fc377f6",
//         "status": "CLOSED"
//         "userId": ""5f54cf4a-ec56-44c2-83bc-8b742600f307""
//     }
// }
type UpdateAlertInput struct {
	// ID of the alert to update
	AlertID *string `json:"alertId" validate:"required,hexadecimal,len=32"` // AlertID is an MD5 hash

	// Variables that we allow updating:
	Status *string `json:"status" validate:"required,oneof=OPEN TRIAGED CLOSED RESOLVED"`

	// User who made the change
	RequesterID *string `json:"requesterId" validate:"required,uuid4"`
}

// UpdateAlertOutput the returne alert summary after an update
type UpdateAlertOutput = AlertSummary

// Constants defined for alert statuses
const (
	// Empty is the default value for an alert status and is used to create an alert
	EmptyStatus = ""

	// Open is the default value for an alert status and is used to filter alerts
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
	AlertID         *string    `json:"alertId" validate:"required"`
	RuleID          *string    `json:"ruleId" validate:"required"`
	RuleDisplayName *string    `json:"ruleDisplayName,omitempty"`
	RuleVersion     *string    `json:"ruleVersion" validate:"required"`
	DedupString     *string    `json:"dedupString,omitempty"`
	CreationTime    *time.Time `json:"creationTime" validate:"required"`
	UpdateTime      *time.Time `json:"updateTime" validate:"required"`
	EventsMatched   *int       `json:"eventsMatched" validate:"required"`
	Severity        *string    `json:"severity" validate:"required"`
	Status          *string    `json:"status,omitempty"`
	Title           *string    `json:"title" validate:"required"`
	UpdatedBy       *string    `json:"updatedBy"`
}

// Alert contains the details of an alert
type Alert struct {
	AlertSummary
	Events                 []*string `json:"events" validate:"required"`
	EventsLastEvaluatedKey *string   `json:"eventsLastEvaluatedKey,omitempty"`
}
