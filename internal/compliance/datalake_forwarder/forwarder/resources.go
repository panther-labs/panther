package forwarder

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
	lambdaevents "github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/internal/diff"
	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/internal/events"
)

type CloudSecuritySnapshotChange struct {
	ChangeType       string              `json:"changeType"`
	Changes          diff.Changelog      `json:"changes"`
	IntegrationID    string              `json:"integrationID"`
	IntegrationLabel string              `json:"integrationLabel"`
	LastUpdated      string              `json:"lastUpdated"`
	Resource         jsoniter.RawMessage `json:"resource"`
}

type resourceSnapshot struct {
	LastModified  string                 `json:"lastModified"`
	IntegrationID string                 `json:"integrationId"`
	Attributes    map[string]interface{} `json:"attributes"`
}

// processResourceChanges processes a record from the resources-table dynamoDB stream,
func (sh *StreamHandler) processResourceChanges(record *events.DynamoDBEventRecord) (snapshot *CloudSecuritySnapshotChange, err error) {
	// For INSERT and REMOVE events, we don't need to calculate a diff
	switch lambdaevents.DynamoDBOperationType(record.EventName) {
	case lambdaevents.DynamoDBOperationTypeInsert:
		snapshot, err = sh.processResourceSnapshot(ChangeTypeCreate, record.Change.NewImage)
	case lambdaevents.DynamoDBOperationTypeRemove:
		snapshot, err = sh.processResourceSnapshot(ChangeTypeDelete, record.Change.OldImage)
	default:
		snapshot, err = sh.processResourceSnapshotDiff(record.EventName, record.Change.OldImage, record.Change.NewImage)
	}

	if err != nil {
		zap.L().Error("unable to process resource snapshot",
			zap.Error(err),
			zap.String("EventID", record.EventID),
			zap.String("EventName", record.EventName),
		)
		zap.L().Debug("verbose error info",
			zap.Any("NewImage", record.Change.NewImage),
			zap.Any("OldImage", record.Change.OldImage))
		return nil, errors.WithMessagef(err, "unable to process resource snapshot for %q", record.EventName)
	}
	return snapshot, nil
}

func (sh *StreamHandler) processResourceSnapshotDiff(eventName string,
	oldImage, newImage map[string]*dynamodb.AttributeValue) (*CloudSecuritySnapshotChange, error) {

	oldSnapshot := resourceSnapshot{}
	if err := dynamodbattribute.UnmarshalMap(oldImage, &oldSnapshot); err != nil || oldSnapshot.Attributes == nil {
		return nil, errors.New("resources-table record old image did include top level key attributes")
	}
	newSnapshot := resourceSnapshot{}
	if err := dynamodbattribute.UnmarshalMap(newImage, &newSnapshot); err != nil || oldSnapshot.Attributes == nil {
		return nil, errors.New("resources-table record new image did include top level key attributes")
	}

	// First convert the old & new image from the useless dynamodb stream format into a JSON string
	newImageJSON, err := jsoniter.Marshal(newSnapshot.Attributes)
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing new resource snapshot")
	}
	oldImageJSON, err := jsoniter.Marshal(oldSnapshot.Attributes)
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing old resource snapshot")
	}

	// Do a very rudimentary JSON diff to determine which top level fields have changed
	changes, err := diff.CompJsons(string(oldImageJSON), string(newImageJSON))
	if err != nil {
		return nil, errors.WithMessage(err, "error comparing old resource snapshot with new resource snapshot")
	}
	zap.L().Debug(
		"processing resource record",
		zap.Any("record.EventName", eventName),
		zap.Any("newImage", newImageJSON),
		zap.Any("changes", changes),
		zap.Error(err),
	)

	// If nothing changed, no need to report it
	if changes == nil {
		return nil, nil
	}

	integrationLabel, err := sh.getIntegrationLabel(newSnapshot.IntegrationID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve integration label for %q", newSnapshot.IntegrationID)
	}
	// If the integration doesn't exist
	// nothing left to do
	if len(integrationLabel) == 0 {
		return nil, nil
	}

	return &CloudSecuritySnapshotChange{
		LastUpdated:      newSnapshot.LastModified,
		IntegrationID:    newSnapshot.IntegrationID,
		IntegrationLabel: integrationLabel,
		Resource:         newImageJSON,
		Changes:          changes,
		ChangeType:       ChangeTypeModify,
	}, nil
}

func (sh *StreamHandler) processResourceSnapshot(changeType string,
	image map[string]*dynamodb.AttributeValue) (*CloudSecuritySnapshotChange, error) {

	change := resourceSnapshot{}
	if err := dynamodbattribute.UnmarshalMap(image, &change); err != nil || change.Attributes == nil {
		return nil, errors.New("resources-table record image did include top level key attributes")
	}
	integrationLabel, err := sh.getIntegrationLabel(change.IntegrationID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve integration label for %q", change.IntegrationID)
	}
	// If we the integration doesn't exist
	// no more work to do
	if len(integrationLabel) == 0 {
		return nil, nil
	}
	rawResource, err := jsoniter.Marshal(change.Attributes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal resource")
	}
	return &CloudSecuritySnapshotChange{
		IntegrationID:    change.IntegrationID,
		IntegrationLabel: integrationLabel,
		LastUpdated:      change.LastModified,
		Resource:         rawResource,
		ChangeType:       changeType,
	}, nil
}
