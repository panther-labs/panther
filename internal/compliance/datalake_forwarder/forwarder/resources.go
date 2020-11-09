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
	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/utils"
)

type CloudSecuritySnapshotChange struct {
	ChangeType       string
	Changes          map[string]utils.Diff
	IntegrationID    string
	IntegrationLabel string
	LastUpdated      string
	Resource         jsoniter.RawMessage
}

func (sh StreamHandler) processResourceSnapshotDiff(record events.DynamoDBEventRecord) (*CloudSecuritySnapshotChange, error) {
	if record.Change.NewImage == nil || record.Change.OldImage == nil {
		return nil, errors.New("expected Change.NewImage and Change.OldImage to not be nil when processing resource diff")
	}
	oldImage := changeImage{}
	if err := unmarshalMap(record.Change.OldImage, &oldImage); err != nil || oldImage.Attributes == nil {
		return nil, errors.New("resources-table record old image did include top level key attributes")
	}
	newImage := changeImage{}
	if err := unmarshalMap(record.Change.NewImage, &newImage); err != nil || oldImage.Attributes == nil {
		return nil, errors.New("resources-table record new image did include top level key attributes")
	}

	// First convert the old & new image from the useless dynamodb stream format into a JSON string
	newImageJSON, err := jsoniter.Marshal(newImage.Attributes)
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing new resource snapshot")
	}
	oldImageJSON, err := jsoniter.Marshal(oldImage.Attributes)
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing old resource snapshot")
	}

	// Do a very rudimentary JSON diff to determine which top level fields have changed
	changes, err := utils.CompJsons(string(oldImageJSON), string(newImageJSON))
	if err != nil {
		return nil, errors.WithMessage(err, "error comparing old resource snapshot with new resource snapshot")
	}
	zap.L().Debug(
		"processing resource record",
		zap.Any("record.EventName", record.EventName),
		zap.Any("newImage", newImageJSON),
		zap.Any("changes", changes),
		zap.Error(err),
	)

	// If nothing changed, no need to report it
	if changes == nil {
		return nil, nil
	}

	integrationLabel, err := sh.getIntegrationLabel(newImage.IntegrationID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve integration label for %q", newImage.IntegrationID)
	}

	return &CloudSecuritySnapshotChange{
		LastUpdated:      newImage.LastModified,
		IntegrationID:    newImage.IntegrationID,
		IntegrationLabel: integrationLabel,
		Resource:         newImageJSON,
		Changes:          changes,
		ChangeType:       ChangeTypeModify,
	}, nil
}

func (sh StreamHandler) processResourceSnapshot(record events.DynamoDBEventRecord) (*CloudSecuritySnapshotChange, error) {
	var image map[string]events.DynamoDBAttributeValue
	var changeType string
	if record.EventName == string(events.DynamoDBOperationTypeInsert) {
		image = record.Change.NewImage
		changeType = ChangeTypeCreate
	}
	if record.EventName == string(events.DynamoDBOperationTypeRemove) {
		image = record.Change.OldImage
		changeType = ChangeTypeDelete
	}
	if image == nil {
		return nil, errors.New("expected Image to not be nil when processing resource diff")
	}
	change := changeImage{}
	if err := unmarshalMap(image, &change); err != nil || change.Attributes == nil {
		return nil, errors.New("resources-table record image did include top level key attributes")
	}
	integrationLabel, err := sh.getIntegrationLabel(change.IntegrationID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve integration label for %q", change.IntegrationID)
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

type changeImage struct {
	LastModified  string                 `json:"lastModified"`
	IntegrationID string                 `json:"integrationId"`
	Attributes    map[string]interface{} `json:"attributes"`
}
