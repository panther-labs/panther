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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
)

// OutputsAPI defines the interface for the outputs table which can be used for mocking.
type OutputsAPI interface {
	GetOutputByName(*string) (*AlertOutputItem, error)
	DeleteOutput(*string) error
	GetOutputs() ([]*AlertOutputItem, error)
	GetOutput(*string) (*AlertOutputItem, error)
	PutOutput(*AlertOutputItem) error
	UpdateOutput(*AlertOutputItem) (*AlertOutputItem, error)
}

// OutputsTable encapsulates a connection to the Dynamo rules table.
type OutputsTable struct {
	Name             *string
	DisplayNameIndex *string
	client           dynamodbiface.DynamoDBAPI
}

// NewOutputs creates an AWS client to interface with the outputs table.
func NewOutputs(name string, displayNameIndex string, sess *session.Session) *OutputsTable {
	return &OutputsTable{
		Name:             aws.String(name),
		DisplayNameIndex: aws.String(displayNameIndex),
		client:           dynamodb.New(sess),
	}
}

// DynamoItem is a type alias for the item format expected by the Dynamo SDK.
type DynamoItem = map[string]*dynamodb.AttributeValue

// AlertOutputItem is the output configuration stored in DynamoDB.
type AlertOutputItem struct {

	// The user ID of the user that created the alert output
	CreatedBy *string `json:"createdBy"`

	// The time in epoch seconds when the alert output was created
	CreationTime *string `json:"creationTime"`

	// DisplayName is the user-provided name, e.g. "alert-channel".
	DisplayName *string `json:"displayName"`

	// EncryptedConfig is the encrypted JSON of the specific output details.
	EncryptedConfig []byte `json:"encryptedConfig"`

	// The user ID of the user that last modified the alert output last
	LastModifiedBy *string `json:"lastModifiedBy"`

	// The time in epoch seconds when the alert output was last modified
	LastModifiedTime *string `json:"lastModifiedTime"`

	// Identifies uniquely an alert output (table sort key)
	OutputID *string `json:"outputId"`

	// OutputType is the output class, e.g. "slack", "sns".
	// ("type" is a reserved Dynamo keyword, so we use "OutputType" instead)
	OutputType *string `json:"outputType"`

	DefaultForSeverity []*string `json:"defaultForSeverity" dynamodbav:"defaultForSeverity,stringset"`

	// AlertTypes is a whitelist of alert types to send to this destination.
	// To be backwards compatible, we cannot have a `min=1` and an empty list == all types.
	AlertTypes []string `json:"alertTypes" dynamodbav:"alertTypes,stringset"`
}
