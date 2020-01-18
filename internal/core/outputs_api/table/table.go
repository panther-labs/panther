// Package table manages all of the Dynamo calls (query, scan, get, write, etc).
package table

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

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// OutputsAPI defines the interface for the outputs table which can be used for mocking.
type OutputsAPI interface {
	GetOutputByName(*string) (*models.AlertOutputItem, error)
	DeleteOutput(*string) error
	GetOutputs() ([]*models.AlertOutputItem, error)
	GetOutput(*string) (*models.AlertOutputItem, error)
	PutOutput(*models.AlertOutputItem) error
	UpdateOutput(*models.AlertOutputItem) (*models.AlertOutputItem, error)
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

// DefaultsAPI defines the interface for the table storing the default output information
type DefaultsAPI interface {
	PutDefaults(item *models.DefaultOutputsItem) error
	GetDefaults() ([]*models.DefaultOutputsItem, error)
	GetDefault(severity *string) (*models.DefaultOutputsItem, error)
}

// DefaultsTable allows interacting with DDB table storing default outputs information
type DefaultsTable struct {
	Name   *string
	client dynamodbiface.DynamoDBAPI
}

// NewDefaults creates an AWS client to interface with the defaults table.
func NewDefaults(name string, sess *session.Session) *DefaultsTable {
	return &DefaultsTable{
		Name:   aws.String(name),
		client: dynamodb.New(sess),
	}
}

// DynamoItem is a type alias for the item format expected by the Dynamo SDK.
type DynamoItem = map[string]*dynamodb.AttributeValue
