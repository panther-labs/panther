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

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/diff"
	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/events"
)

type ResourceChange struct {
	ChangeType       string                 `json:"changeType"`
	Changes          diff.Changelog         `json:"changes"`
	IntegrationID    string                 `json:"integrationId"`
	IntegrationLabel string                 `json:"integrationLabel"`
	LastUpdated      string                 `json:"lastUpdated"`
	ID               string                 `json:"id"`
	Resource         map[string]interface{} `json:"resource"`
	ResourceAttributes
}

type ResourceAttributes struct {
	ResourceID   *string           `json:"resourceId,omitempty"`
	ResourceType *string           `json:"resourceType,omitempty"`
	TimeCreated  *string           `json:"timeCreated,omitempty"`
	AccountID    *string           `json:"accountId,omitempty"`
	Region       *string           `json:"region,omitempty"`
	ARN          *string           `json:"arn,omitempty"`
	Name         *string           `json:"name,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type resourceSnapshot struct {
	LastModified  string                 `json:"lastModified"`
	IntegrationID string                 `json:"integrationId"`
	ID            string                 `json:"id"`
	Deleted       bool                   `json:"deleted"`
	Attributes    map[string]interface{} `json:"attributes"`
}

// processResourceChanges processes a record from the resources-table dynamoDB stream,
func (sh *StreamHandler) processResourceChanges(record *events.DynamoDBEventRecord) (resource *ResourceChange, err error) {
	var oldSnapshot, newSnapshot *resourceSnapshot
	if r := record.Change.NewImage; r != nil {
		newSnapshot, err = marshalSnapshot(r)
		if err != nil {
			return nil, err
		}
	}
	if r := record.Change.OldImage; r != nil {
		oldSnapshot, err = marshalSnapshot(r)
		if err != nil {
			return nil, err
		}
	}

	// For INSERT and REMOVE events, we don't need to calculate a diff
	switch lambdaevents.DynamoDBOperationType(record.EventName) {
	case lambdaevents.DynamoDBOperationTypeInsert:
		resource, err = sh.processResourceSnapshot(ChangeTypeCreate, newSnapshot)
	case lambdaevents.DynamoDBOperationTypeRemove:
		// If it was marked deleted earlier, it means we already did send a "DELETED" change
		// Send a "DELETED" change only if it was no marked as deleted
		if !oldSnapshot.Deleted {
			resource, err = sh.processResourceSnapshot(ChangeTypeDelete, oldSnapshot)
		}
	case lambdaevents.DynamoDBOperationTypeModify:
		// If the new snapshot got marked as deleted  treat it as a delete
		if newSnapshot.Deleted && !oldSnapshot.Deleted {
			resource, err = sh.processResourceSnapshot(ChangeTypeDelete, oldSnapshot)
			break
		}
		// If the old snapshot was marked as deleted and the new one is not, treat it as resource created
		if !newSnapshot.Deleted && oldSnapshot.Deleted {
			resource, err = sh.processResourceSnapshot(ChangeTypeCreate, newSnapshot)
			break
		}
		resource, err = sh.processResourceSnapshotDiff(oldSnapshot, newSnapshot)
	default:
		zap.L().Error("Unknown Event Type", zap.String("record.EventName", record.EventName))
		return nil, nil
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
	return resource, nil
}

func (sh *StreamHandler) processResourceSnapshotDiff(oldSnapshot, newSnapshot *resourceSnapshot) (*ResourceChange, error) {
	// First convert the old & new image from the useless dynamodb stream format into a JSON string
	newImageJSON, err := jsoniter.Marshal(newSnapshot.Attributes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing new resource snapshot")
	}
	oldImageJSON, err := jsoniter.Marshal(oldSnapshot.Attributes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing old resource snapshot")
	}

	// Do a very rudimentary JSON diff to determine which top level fields have changed
	changes, err := diff.CompJsons(oldImageJSON, newImageJSON)
	if err != nil {
		return nil, errors.WithMessage(err, "error comparing old resource snapshot with new resource snapshot")
	}
	zap.L().Debug(
		"processing resource record",
		zap.Any("newImage", newImageJSON),
		zap.Any("changes", changes),
		zap.Error(err),
	)

	integrationLabel, err := sh.getIntegrationLabel(newSnapshot.IntegrationID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve integration label for %q", newSnapshot.IntegrationID)
	}
	// If the integration doesn't exist
	// nothing left to do
	if len(integrationLabel) == 0 {
		return nil, nil
	}

	var attributes ResourceAttributes
	if err := jsoniter.Unmarshal(newImageJSON, &attributes); err != nil {
		return nil, errors.Wrapf(err, "failed to populate attributes: %s", string(newImageJSON))
	}

	out := &ResourceChange{
		LastUpdated:        newSnapshot.LastModified,
		IntegrationID:      newSnapshot.IntegrationID,
		ID:                 newSnapshot.ID,
		IntegrationLabel:   integrationLabel,
		Resource:           newSnapshot.Attributes,
		Changes:            changes,
		ResourceAttributes: attributes,
	}

	// If nothing changed, report it as a sync
	if changes == nil {
		out.ChangeType = ChangeTypeSync
	} else {
		out.ChangeType = ChangeTypeModify
	}

	return out, nil
}

func (sh *StreamHandler) processResourceSnapshot(changeType string, change *resourceSnapshot) (*ResourceChange, error) {
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
		return nil, errors.Wrapf(err, "failed to marshal attributes: %#v", rawResource)
	}

	var attributes ResourceAttributes
	if err := jsoniter.Unmarshal(rawResource, &attributes); err != nil {
		return nil, errors.Wrapf(err, "failed to populate attributes: %s", string(rawResource))
	}

	return &ResourceChange{
		ID:                 change.ID,
		IntegrationID:      change.IntegrationID,
		IntegrationLabel:   integrationLabel,
		LastUpdated:        change.LastModified,
		Resource:           change.Attributes,
		ChangeType:         changeType,
		ResourceAttributes: attributes,
	}, nil
}

func marshalSnapshot(image map[string]*dynamodb.AttributeValue) (*resourceSnapshot, error) {
	var snapshot resourceSnapshot
	if err := dynamodbattribute.UnmarshalMap(image, &snapshot); err != nil {
		return nil, errors.Wrapf(err, "could not unmarshal new image %#v", image)
	}
	if snapshot.Attributes == nil {
		return nil, errors.Errorf("resources-table new image did include top level key attributes: %#v", image)
	}
	return &snapshot, nil
}
