package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import "github.com/aws/aws-sdk-go/service/configservice"

const (
	// ConfigServiceSchema is the schema ID for the ConfigService type.
	ConfigServiceSchema = "AWS.Config.Recorder"
	// ConfigServiceMetaSchema is the schema ID for the ConfigServiceMeta type.
	ConfigServiceMetaSchema = "AWS.Config.Recorder.Meta"
)

// ConfigService contains all information about a policy.
type ConfigService struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from configservice.ConfigurationRecorder
	RecordingGroup *configservice.RecordingGroup
	RoleARN        *string

	// Additional fields
	Status *configservice.ConfigurationRecorderStatus
}

// ConfigServiceMeta contains metadata about all Config Service Recorders in an account.
type ConfigServiceMeta struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Additional fields
	GlobalRecorderCount *int
	Recorders           []*string
}
