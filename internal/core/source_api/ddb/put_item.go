package ddb

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
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/pkg/errors"
)

// PutItem adds a source integration to the database
func (ddb *DDB) PutItem(input *Integration) error {
	item, err := dynamodbattribute.MarshalMap(input)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal integration metadata")
	}

	putRequest := &dynamodb.PutItemInput{
		TableName: &ddb.TableName,
		Item:      item,
	}
	_, err = ddb.Client.PutItem(putRequest)
	if err != nil {
		return errors.Wrap(err, "failed to put item")
	}
	return nil
}
