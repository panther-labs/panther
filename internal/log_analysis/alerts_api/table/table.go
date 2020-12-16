// Package table manages all of the Dynamo calls (query, scan, get, write, etc).
package table

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
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
)

const (
	RuleIDKey            = "ruleId"
	AlertIDKey           = "id"
	CreatedAtKey         = "creationTime"
	TimePartitionKey     = "timePartition"
	TimePartitionValue   = "defaultPartition"
	TitleKey             = "title"
	SeverityKey          = "severity"
	EventCountKey        = "eventCount"
	StatusKey            = "status"
	LogTypesKey          = "logTypes"
	ResourceTypesKey     = "resourceTypes"
	DeliveryResponsesKey = "deliveryResponses"
	LastUpdatedByKey     = "lastUpdatedBy"
	LastUpdatedByTimeKey = "lastUpdatedByTime"
	TypeKey              = "type"
)

// API defines the interface for the alerts table which can be used for mocking.
type API interface {
	GetAlert(string) (*AlertItem, error)
	ListAll(*models.ListAlertsInput) ([]*AlertItem, *string, error)
	UpdateAlertStatus(*models.UpdateAlertStatusInput) ([]*AlertItem, error)
	UpdateAlertDelivery(*models.UpdateAlertDeliveryInput) (*AlertItem, error)
}

// AlertsTable encapsulates a connection to the Dynamo alerts table.
type AlertsTable struct {
	AlertsTableName                    string
	RuleIDCreationTimeIndexName        string
	TimePartitionCreationTimeIndexName string
	Client                             dynamodbiface.DynamoDBAPI
}

type AlertsTableEnvConfig struct {
	// env config for instantiating a table.AlertsTable
	AlertsTableName     string `required:"true" split_words:"true"`
	AlertsRuleIndexName string `required:"true" split_words:"true"`
	AlertsTimeIndexName string `required:"true" split_words:"true"`
}

func (config *AlertsTableEnvConfig) NewAlertsTable(client dynamodbiface.DynamoDBAPI) *AlertsTable {
	return &AlertsTable{
		AlertsTableName:                    config.AlertsTableName,
		Client:                             client,
		RuleIDCreationTimeIndexName:        config.AlertsRuleIndexName,
		TimePartitionCreationTimeIndexName: config.AlertsTimeIndexName,
	}
}

// The AlertsTable must satisfy the API interface.
var _ API = (*AlertsTable)(nil)

// DynamoItem is a type alias for the item format expected by the Dynamo SDK.
type DynamoItem = map[string]*dynamodb.AttributeValue

// AlertItem is a DDB representation of an Alert
type AlertItem struct {
	AlertID             string                     `json:"id"`
	Type                string                     `json:"type"`
	RuleID              string                     `json:"ruleId"`
	RuleVersion         string                     `json:"ruleVersion"`
	RuleDisplayName     *string                    `json:"ruleDisplayName"`
	Title               string                     `json:"title"`
	Description         *string                    `json:"description"`
	Reference           *string                    `json:"reference"`
	Runbook             *string                    `json:"runbook"`
	Destinations        []string                   `json:"destinations,omitempty" validate:"dive,uuid4"`
	DedupString         string                     `json:"dedup"`
	FirstEventMatchTime time.Time                  `json:"firstEventMatchTime"`
	CreationTime        time.Time                  `json:"creationTime"`
	DeliveryResponses   []*models.DeliveryResponse `json:"deliveryResponses"`
	// UpdateTime - stores the timestamp from an update from a dedup event
	UpdateTime time.Time `json:"updateTime"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	EventCount int       `json:"eventCount"`
	LogTypes   []string  `json:"logTypes"`
	// LastUpdatedBy - stores the UserID of the last person who modified the Alert
	LastUpdatedBy string `json:"lastUpdatedBy"`
	// LastUpdatedByTime - stores the timestamp of the last person who modified the Alert
	LastUpdatedByTime time.Time `json:"lastUpdatedByTime"`
	// Policy related fields
	PolicyID          string   `json:"policyId"`
	PolicyDisplayName string   `json:"policyDisplayName"`
	PolicySourceID    string   `json:"policySourceId"`
	PolicyVersion     string   `json:"policyVersion"`
	ResourceTypes     []string `json:"resourceTypes"`
	ResourceID        string   `json:"resourceId"`
}
