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
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/pkg/errors"
)

// GetEvent retrieves an event from DDB
// FIXME: the string keys should be constants in _some_ model, but which?
func (table *AlertsTable) GetEvent(eventHash []byte) (*string, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			EventHash: {B: eventHash},
		},
		TableName: aws.String(table.EventsTableName),
	}

	ddbResult, err := table.Client.GetItem(input)
	if err != nil {
		return nil, errors.Wrap(err, "GetItem() failed for: "+string(eventHash))
	}

	return ddbResult.Item["event"].S, nil
}
