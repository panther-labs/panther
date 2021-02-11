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

// Exported set of ResourceTypes. This export was initially created to provide a hardcoded set of
// valid resource types to the analysis api so we could validate resource types on create/update
//
// NOTE! - This hardcoded data set is found in several places in our code base.
// Until this data is sourced from a single location you need to check if any additions
// or modifications to this data need to coincide with updates in the other places where this data
// is hardcoded.
//
// Locations may not be in this list! right now this data is hardcoded in
// • internal/compliance/snapshot_poller/models/aws/ResourceTypes.go
// • internal/compliance/snapshot_poller/pollers/aws/clients.go
//
// • web/src/constants.ts
//
var ResourceTypes = map[string]struct{}{
	AcmCertificateSchema:      {},
	CloudFormationStackSchema: {},
	CloudTrailSchema:          {},
	CloudTrailMetaSchema:      {},
	CloudWatchLogGroupSchema:  {},
	ConfigServiceSchema:       {},
	ConfigServiceMetaSchema:   {},
	DynamoDBTableSchema:       {},
	Ec2AmiSchema:              {},
	Ec2InstanceSchema:         {},
	Ec2NetworkAclSchema:       {},
	Ec2SecurityGroupSchema:    {},
	Ec2VolumeSchema:           {},
	Ec2VpcSchema:              {},
	EcsClusterSchema:          {},
	EksClusterSchema:          {},
	Elbv2LoadBalancerSchema:   {},
	GuardDutySchema:           {},
	IAMGroupSchema:            {},
	IAMPolicySchema:           {},
	IAMRoleSchema:             {},
	IAMRootUserSchema:         {},
	IAMUserSchema:             {},
	KmsKeySchema:              {},
	LambdaFunctionSchema:      {},
	PasswordPolicySchema:      {},
	RDSInstanceSchema:         {},
	RedshiftClusterSchema:     {},
	S3BucketSchema:            {},
	WafRegionalWebAclSchema:   {},
	WafWebAclSchema:           {},
}
