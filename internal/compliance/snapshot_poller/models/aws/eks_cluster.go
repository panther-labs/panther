package aws

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
	"time"

	"github.com/aws/aws-sdk-go/service/eks"
)

const (
	EksClusterSchema = "AWS.EKS.Cluster"
)

// EksCluster contains all the information about an EKS Cluster
type EksCluster struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from eks.Cluster
	CertificateAuthority *eks.Certificate
	EncryptionConfig     []*eks.EncryptionConfig
	Endpoint             *string
	Identity             *eks.Identity
	Logging              *eks.Logging
	PlatformVersion      *string
	ResourcesVpcConfig   *eks.VpcConfigResponse
	RoleArn              *string
	Status               *string
	Version              *string

	// Additional fields
	NodeGroup      []*EksNodegroup
	FargateProfile []*EksFargateProfile
}

// EksNodegroup contains all the information about an EKS Service, for embedding into the EksCluster resource
type EksNodegroup struct {
	// Generic resource fields
	//
	// This is not a full resource, but it does have an ARN and Tags.
	GenericAWSResource

	// Fields embedded from eks.Service
	AmiType        *string
	DiskSize       *int64
	Health         *eks.NodegroupHealth
	InstanceTypes  []*string
	LaunchTemplate *eks.LaunchTemplateSpecification
	NodegroupArn   *string
	NodegroupName  *string
	NodeRole       *string
	ReleaseVersion *string
	RemoteAccess   *eks.RemoteAccessConfig
	Resources      *eks.NodegroupResources
	ScalingConfig  *eks.NodegroupScalingConfig
	Subnets        []*string
	Version        *string

	// Normalized name for CreatedAt
	TimeCreated *time.Time
}

// EksFargateProfile contains all the information about an EKS Fargate Profile, for embedding into the EksCluster resource
type EksFargateProfile struct {
	// Generic resource fields
	//
	// This is not a full resource, but it does have an ARN and Tags.
	GenericAWSResource

	// Fields embedded from eks.FargateProfile
	FargateProfileArn   *string
	FargateProfileName  *string
	PodExecutionRoleArn *string
	Selectors           []*eks.FargateProfileSelector
	Status              *string
	Subnets             []*string

	// Normalized name for CreatedAt
	TimeCreated *time.Time
}
