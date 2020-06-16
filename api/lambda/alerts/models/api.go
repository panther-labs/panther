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
	GetAlert   *GetAlertInput   `json:"getAlert"`
	ListAlerts *ListAlertsInput `json:"listAlerts"`
}

// GetAlertInput retrieves details for a single alert.
//
// The response will contain by definition all of the events associated with the alert.
// If `eventPageSize` and `eventPage` are specified, it will returns only the specified events in the response.
// Example:
// {
//     "getAlert": {
// 	    "alertId": "ruleId-2",
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
//         "severity": "INFO",
//         "eventCountMin": "0",
//         "eventCountMax": "500",
//         "createdAtAfter": "2020-06-17T15:49:40Z",
//         "createdAtBefore": "2020-06-17T15:49:40Z",
//         "sortDir": "ascending",
//     }
// }
type ListAlertsInput struct {
	RuleID   *string `json:"ruleId,omitempty"`
	PageSize *int    `json:"pageSize,omitempty" validate:"omitempty,min=1,max=50"`

	// Infinite scroll/pagination query key
	ExclusiveStartKey *string `json:"exclusiveStartKey,omitempty"`

	// Filtering
	Severity        *string    `json:"severity,omitempty" validate:"omitempty,oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Contains        *string    `json:"contains,omitempty"`
	EventCountMin   *int       `json:"eventCountMin,omitempty" validate:"omitempty,min=0"`
	EventCountMax   *int       `json:"eventCountMax,omitempty" validate:"omitempty,min=0"`
	CreatedAtBefore *time.Time `json:"createdAtBefore,omitempty" validate:"omitempty"`
	CreatedAtAfter  *time.Time `json:"createdAtAfter,omitempty" validate:"omitempty"`

	// Sorting
	SortDir *string `json:"sortDir,omitempty" validate:"omitempty,oneof=ascending descending"`
}

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
	Title           *string    `json:"title" validate:"required"`
}

// Alert contains the details of an alert
type Alert struct {
	AlertSummary
	Events                 []*string `json:"events" validate:"required"`
	EventsLastEvaluatedKey *string   `json:"eventsLastEvaluatedKey,omitempty"`
}
