package snapshotlogs

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
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const TypeResource = "Snapshot.ResourceHistory"

var logTypeResource = logtypes.MustBuild(logtypes.ConfigJSON{
	Name:         TypeResource,
	Description:  `Contains Cloud Security resource snapshots`,
	ReferenceURL: `https://docs.runpanther.io/cloud-security/resources`,
	NewEvent: func() interface{} {
		return &Resource{}
	},
	Validate: func(event interface{}) error {
		// This is a cheating a bit to reuse ConfigJSON for boilerplate code.
		// We know this functions is running right after the first JSON parsing,
		// so we 'sneak' some extra parsing code in here
		resource, ok := event.(*Resource)
		if !ok {
			return errors.Errorf("invalid event to validate %v", event)
		}
		if resource.Resource == nil {
			return errors.Errorf("nil resource %v", event)
		}
		if err := jsoniter.Unmarshal(*resource.Resource, &resource.NormalizedFields); err != nil {
			return errors.Wrap(err, "could not unmarshal resource fields")
		}
		// End of cheating

		return pantherlog.ValidateStruct(event)
	},
	// It is important to use case-insensitive JSON parser to avoid pitfalls with dynamodb.AttributeValues
	JSON: jsoniter.Config{
		CaseSensitive: false,
	}.Froze(),
})

// nolint:lll
type Resource struct {
	ChangeType       pantherlog.String              `json:"changeType" validate:"required,oneof=created deleted modified sync" description:"The type of change that initiated this snapshot creation."`
	Changes          map[string]jsoniter.RawMessage `json:"changes" description:"The changes, if any, from the prior snapshot to this one."`
	IntegrationID    pantherlog.String              `json:"integrationId" validate:"required" description:"The unique source ID of the account this resource lives in."`
	IntegrationLabel pantherlog.String              `json:"integrationLabel" validate:"required" description:"The friendly source name of the account this resource lives in."`
	LastUpdated      pantherlog.Time                `json:"lastUpdated" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The time this snapshot occurred."`
	Resource         *pantherlog.RawMessage         `json:"resource" description:"This object represents the state of the resource."`
	NormalizedFields SnapshotNormalizedFields       `json:"normalizedFields" description:"This object represents normalized fields extracted by the scanner."`
}

type SnapshotNormalizedFields struct {
	// Embedded from internal/compliance/snapshot_poller/models/aws/types.go
	ResourceID   pantherlog.String `json:"ResourceId" description:"A panther wide unique identifier of the resource."`
	ResourceType pantherlog.String `json:"ResourceType" description:"A panther defined resource type for the resource."`
	TimeCreated  pantherlog.Time   `json:"TimeCreated" description:"When this resource was created."`
	AccountID    pantherlog.String `json:"AccountId" panther:"aws_account_id" description:"The ID of the AWS Account the resource resides in."`
	Region       pantherlog.String `json:"Region" description:"The region the resource exists in."`
	ARN          pantherlog.String `json:"Arn,omitempty" panther:"aws_arn" description:"The Amazon Resource Name (ARN) of the resource."`
	ID           pantherlog.String `json:"Id,omitempty" description:"The AWS resource identifier of the resource."`
	Name         pantherlog.String `json:"Name,omitempty" description:"The AWS resource name of the resource."`
	Tags         map[string]string `json:"Tags,omitempty" description:"A standardized format for AWS key/value resource tags."`
}

// WriteValuesTo implements pantherlog.ValueWriterTo interface
func (n *SnapshotNormalizedFields) WriteValuesTo(w pantherlog.ValueWriter) {
	for key, value := range n.Tags {
		w.WriteValues(pantherlog.FieldAWSTag, key+":"+value)
	}
}
