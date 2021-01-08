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

	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	IAMPolicySchema = "AWS.IAM.Policy"
)

// IAMPolicy contains all information about a policy.
type IAMPolicy struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from iam.Policy
	AttachmentCount               *int64
	DefaultVersionId              *string
	Description                   *string
	IsAttachable                  *bool
	Path                          *string
	PermissionsBoundaryUsageCount *int64
	UpdateDate                    *time.Time

	// Additional fields
	Entities       *IAMPolicyEntities
	PolicyDocument *string
}

// IAMPolicyEntities provides detail on the attached entities to an IAM policy.
type IAMPolicyEntities struct {
	PolicyGroups []*iam.PolicyGroup
	PolicyRoles  []*iam.PolicyRole
	PolicyUsers  []*iam.PolicyUser
}
