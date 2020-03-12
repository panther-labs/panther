package models

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
// 	    "alertId": "ruleId-2"
//     }
// }
type GetAlertInput struct {
	AlertID                 *string `json:"alertId" validate:"required,hexadecimal,len=32"` // AlertID is an MD5 hash
	EventsPageSize          *int    `json:"eventsPageSize,omitempty"  validate:"omitempty,min=1,max=50"`
	EventsExclusiveStartKey *string `json:"eventsExclusiveStartKey,omitempty"`
}

// GetAlertOutput retrieves details for a single alert.
//
// Example:
// {
//     "getAlert": {
// 	    "alertId": "ruleId-2"
//     }
// }
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
//         "pageSize": 25
//     }
// }
type ListAlertsInput struct {
	RuleID            *string `json:"ruleId,omitempty"`
	PageSize          *int    `json:"pageSize,omitempty"  validate:"omitempty,min=1,max=50"`
	ExclusiveStartKey *string `json:"exclusiveStartKey,omitempty"`
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
	AlertID       *string    `json:"alertId"`
	RuleID        *string    `json:"ruleId"`
	DedupString   *string    `json:"dedupString"`
	CreationTime  *time.Time `json:"creationTime"`
	UpdateTime    *time.Time `json:"updateTime"`
	EventsMatched *int       `json:"eventsMatched"`
	Severity      *string    `json:"severity"`
}

// Alert contains the details of an alert
type Alert struct {
	AlertID                *string    `json:"alertId"`
	RuleID                 *string    `json:"ruleId"`
	DedupString            *string    `json:"dedupString"`
	CreationTime           *time.Time `json:"creationTime"`
	UpdateTime             *time.Time `json:"updateTime"`
	EventsMatched          *int       `json:"eventsMatched"`
	Events                 []*string  `json:"events"`
	EventsLastEvaluatedKey *string    `json:"eventsLastEvaluatedKey,omitempty"`
}
