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

import (
	"time"

	"github.com/aws/aws-sdk-go/service/cloudformation"
)

const (
	CloudFormationStackSchema = "AWS.CloudFormation.Stack"
)

// CloudFormationStack contains all the information about a CloudFormation Stack
type CloudFormationStack struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from cloudformation.Stack
	Capabilities                []*string
	ChangeSetId                 *string
	DeletionTime                *time.Time
	Description                 *string
	DisableRollback             *bool
	DriftInformation            *cloudformation.StackDriftInformation
	EnableTerminationProtection *bool
	LastUpdatedTime             *time.Time
	NotificationARNs            []*string
	Outputs                     []*cloudformation.Output
	Parameters                  []*cloudformation.Parameter
	ParentId                    *string
	RoleARN                     *string
	RollbackConfiguration       *cloudformation.RollbackConfiguration
	RootId                      *string
	StackStatus                 *string
	StackStatusReason           *string
	TimeoutInMinutes            *int64

	// Additional fields
	Drifts []*cloudformation.StackResourceDrift
}
