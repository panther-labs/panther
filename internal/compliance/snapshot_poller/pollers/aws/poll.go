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
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	resourcesapimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// resourcePoller is a simple struct to be used only for invoking the ResourcePollers in order.
type resourcePoller struct {
	description    string
	resourcePoller awsmodels.ResourcePoller
}

var (
	// Default region to use when building clients for the individual resource poller
	defaultRegion = endpoints.UsWest2RegionID

	auditRoleName = os.Getenv("AUDIT_ROLE_NAME")

	// IndividualARNResourcePollers maps resource types to their corresponding individual polling
	// functions for resources whose ID is their ARN.
	IndividualARNResourcePollers = map[string]func(
		input *awsmodels.ResourcePollerInput, arn arn.ARN, entry *pollermodels.ScanEntry) (interface{}, error){
		awsmodels.AcmCertificateSchema:      PollACMCertificate,
		awsmodels.CloudFormationStackSchema: PollCloudFormationStack,
		awsmodels.CloudTrailSchema:          PollCloudTrailTrail,
		awsmodels.CloudWatchLogGroupSchema:  PollCloudWatchLogsLogGroup,
		awsmodels.DynamoDBTableSchema:       PollDynamoDBTable,
		awsmodels.Ec2AmiSchema:              PollEC2Image,
		awsmodels.Ec2InstanceSchema:         PollEC2Instance,
		awsmodels.Ec2NetworkAclSchema:       PollEC2NetworkACL,
		awsmodels.Ec2SecurityGroupSchema:    PollEC2SecurityGroup,
		awsmodels.Ec2VolumeSchema:           PollEC2Volume,
		awsmodels.Ec2VpcSchema:              PollEC2VPC,
		awsmodels.EcsClusterSchema:          PollECSCluster,
		awsmodels.Elbv2LoadBalancerSchema:   PollELBV2LoadBalancer,
		awsmodels.IAMGroupSchema:            PollIAMGroup,
		awsmodels.IAMPolicySchema:           PollIAMPolicy,
		awsmodels.IAMRoleSchema:             PollIAMRole,
		awsmodels.IAMUserSchema:             PollIAMUser,
		awsmodels.IAMRootUserSchema:         PollIAMRootUser,
		awsmodels.KmsKeySchema:              PollKMSKey,
		awsmodels.LambdaFunctionSchema:      PollLambdaFunction,
		awsmodels.RDSInstanceSchema:         PollRDSInstance,
		awsmodels.RedshiftClusterSchema:     PollRedshiftCluster,
		awsmodels.S3BucketSchema:            PollS3Bucket,
		awsmodels.WafWebAclSchema:           PollWAFWebACL,
		awsmodels.WafRegionalWebAclSchema:   PollWAFRegionalWebACL,
	}

	// IndividualResourcePollers maps resource types to their corresponding individual polling
	// functions for resources whose ID is not their ARN.
	IndividualResourcePollers = map[string]func(
		input *awsmodels.ResourcePollerInput, id *utils.ParsedResourceID, entry *pollermodels.ScanEntry) (interface{}, error){
		awsmodels.ConfigServiceSchema:  PollConfigService,
		awsmodels.GuardDutySchema:      PollGuardDutyDetector,
		awsmodels.PasswordPolicySchema: PollPasswordPolicyResource,
	}

	// ServicePollers maps a resource type to its Poll function
	ServicePollers = map[string]resourcePoller{
		awsmodels.AcmCertificateSchema:      {"ACMCertificate", PollAcmCertificates},
		awsmodels.CloudTrailSchema:          {"CloudTrail", PollCloudTrails},
		awsmodels.Ec2AmiSchema:              {"EC2AMI", PollEc2Amis},
		awsmodels.Ec2InstanceSchema:         {"EC2Instance", PollEc2Instances},
		awsmodels.Ec2NetworkAclSchema:       {"EC2NetworkACL", PollEc2NetworkAcls},
		awsmodels.Ec2SecurityGroupSchema:    {"EC2SecurityGroup", PollEc2SecurityGroups},
		awsmodels.Ec2VolumeSchema:           {"EC2Volume", PollEc2Volumes},
		awsmodels.Ec2VpcSchema:              {"EC2VPC", PollEc2Vpcs},
		awsmodels.EcsClusterSchema:          {"ECSCluster", PollEcsClusters},
		awsmodels.Elbv2LoadBalancerSchema:   {"ELBV2LoadBalancer", PollElbv2ApplicationLoadBalancers},
		awsmodels.KmsKeySchema:              {"KMSKey", PollKmsKeys},
		awsmodels.S3BucketSchema:            {"S3Bucket", PollS3Buckets},
		awsmodels.WafWebAclSchema:           {"WAFWebAcl", PollWafWebAcls},
		awsmodels.WafRegionalWebAclSchema:   {"WAFRegionalWebAcl", PollWafRegionalWebAcls},
		awsmodels.CloudFormationStackSchema: {"CloudFormationStack", PollCloudFormationStacks},
		awsmodels.CloudWatchLogGroupSchema:  {"CloudWatchLogGroup", PollCloudWatchLogsLogGroups},
		awsmodels.ConfigServiceSchema:       {"ConfigService", PollConfigServices},
		awsmodels.DynamoDBTableSchema:       {"DynamoDBTable", PollDynamoDBTables},
		awsmodels.GuardDutySchema:           {"GuardDutyDetector", PollGuardDutyDetectors},
		awsmodels.IAMUserSchema:             {"IAMUser", PollIAMUsers},
		// Service scan for the resource type IAMRootUserSchema is not defined! Do not do it!
		awsmodels.IAMRoleSchema:         {"IAMRoles", PollIAMRoles},
		awsmodels.IAMGroupSchema:        {"IAMGroups", PollIamGroups},
		awsmodels.IAMPolicySchema:       {"IAMPolicies", PollIamPolicies},
		awsmodels.LambdaFunctionSchema:  {"LambdaFunctions", PollLambdaFunctions},
		awsmodels.PasswordPolicySchema:  {"PasswordPolicy", PollPasswordPolicy},
		awsmodels.RDSInstanceSchema:     {"RDSInstance", PollRDSInstances},
		awsmodels.RedshiftClusterSchema: {"RedshiftCluster", PollRedshiftClusters},
	}
)

// Poll coordinates AWS generatedEvents gathering across all relevant resources for compliance monitoring.
func Poll(scanRequest *pollermodels.ScanEntry) (
	generatedEvents []*resourcesapimodels.AddResourceEntry, err error) {

	if scanRequest.AWSAccountID == nil {
		return nil, errors.New("no valid AWS AccountID provided")
	}

	// Build the audit role manually
	// 	Format: arn:aws:iam::$(ACCOUNT_ID):role/PantherAuditRole-($REGION)
	if len(auditRoleName) == 0 {
		return nil, errors.New("no audit role configured")
	}
	auditRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s",
		*scanRequest.AWSAccountID, auditRoleName) // the auditRole name is for form: PantherAuditRole-($REGION)

	zap.L().Debug("constructed audit role", zap.String("role", auditRoleARN))

	// Extract the role ARN to construct various ResourceIDs.
	roleArn, err := arn.Parse(auditRoleARN)
	if err != nil {
		return nil, err
	}

	pollerResourceInput := &awsmodels.ResourcePollerInput{
		AuthSource:          &auditRoleARN,
		AuthSourceParsedARN: roleArn,
		IntegrationID:       scanRequest.IntegrationID,
		// This will be overwritten if this is not a single resource or single region service scan
		Regions: []*string{scanRequest.Region},
		// Note: The resources-api expects a strfmt.DateTime formatted string.
		Timestamp: utils.DateTimeFormat(utils.TimeNowFunc()),
	}

	// If this is an individual resource scan or the region is provided,
	// we don't need to lookup the active regions.
	//
	// Individual resource scan
	if scanRequest.ResourceID != nil {
		zap.L().Info("processing single resource scan")
		return singleResourceScan(scanRequest, pollerResourceInput)

		// Single region service scan
	} else if scanRequest.Region != nil && scanRequest.ResourceType != nil {
		zap.L().Info("processing single region service scan")
		if poller, ok := ServicePollers[*scanRequest.ResourceType]; ok {
			return serviceScan(
				[]resourcePoller{poller},
				pollerResourceInput,
			)
		} else {
			return nil, errors.Errorf("invalid single region resource type '%s' scan requested", *scanRequest.ResourceType)
		}
	}

	ec2Client, err := getEC2Client(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err // getClient() logs error
	}

	regions := utils.GetRegions(ec2Client)
	if regions == nil {
		zap.L().Info("no valid regions to scan")
		return nil, nil
	}
	pollerResourceInput.Regions = regions

	// Full account scan
	if scanRequest.ScanAllResources != nil && *scanRequest.ScanAllResources {
		zap.L().Warn("DEPRECATED: processing full account scan, this operation should not occur during normal operations." +
			"Either input was malformed or someone has manually initiated this scan.")
		allPollers := make([]resourcePoller, 0, len(ServicePollers))
		for _, poller := range ServicePollers {
			allPollers = append(allPollers, poller)
		}
		return serviceScan(allPollers, pollerResourceInput)

		// Account wide resource type scan
	} else if scanRequest.ResourceType != nil {
		zap.L().Info("processing full account resource type scan")
		if poller, ok := ServicePollers[*scanRequest.ResourceType]; ok {
			return serviceScan(
				[]resourcePoller{poller},
				pollerResourceInput,
			)
		} else {
			return nil, errors.Errorf("invalid single region resource type '%s' scan requested", *scanRequest.ResourceType)
		}
	}

	zap.L().Error("Invalid scan request input")
	return nil, nil
}

func serviceScan(
	pollers []resourcePoller,
	pollerInput *awsmodels.ResourcePollerInput,
) (generatedEvents []*resourcesapimodels.AddResourceEntry, err error) {

	var generatedResources []*resourcesapimodels.AddResourceEntry
	for _, resourcePoller := range pollers {
		generatedResources, err = resourcePoller.resourcePoller(pollerInput)
		if err != nil {
			zap.L().Error(
				"an error occurred while polling",
				zap.String("resourcePoller", resourcePoller.description),
				zap.String("errorMessage", err.Error()),
			)
			return
		} else if generatedResources != nil {
			zap.L().Info(
				"resources generated",
				zap.Int("numResources", len(generatedResources)),
				zap.String("resourcePoller", resourcePoller.description),
			)
			generatedEvents = append(generatedEvents, generatedResources...)
		}
	}
	return
}

func singleResourceScan(
	scanRequest *pollermodels.ScanEntry,
	pollerInput *awsmodels.ResourcePollerInput,
) (generatedEvent []*resourcesapimodels.AddResourceEntry, err error) {

	var resource interface{}

	// TODO: does this accept short names?
	if pollFunction, ok := IndividualResourcePollers[*scanRequest.ResourceType]; ok {
		// Handle cases where the ResourceID is not an ARN
		parsedResourceID := utils.ParseResourceID(*scanRequest.ResourceID)
		resource, err = pollFunction(pollerInput, parsedResourceID, scanRequest)
		if err != nil {
			return nil, errors.Wrapf(err, "could not scan %#v", *scanRequest)
		}
	} else if pollFunction, ok := IndividualARNResourcePollers[*scanRequest.ResourceType]; ok {
		// Handle cases where the ResourceID is an ARN
		resourceARN, err := arn.Parse(*scanRequest.ResourceID)
		if err != nil {
			zap.L().Error("unable to parse resourceID",
				zap.Error(err),
			)
			return nil, err
		}
		resource, err = pollFunction(pollerInput, resourceARN, scanRequest)
		if err != nil {
			return nil, errors.Wrapf(err, "could not scan %#v", *scanRequest)
		}
	}

	if resource == nil {
		zap.L().Info("could not build resource",
			zap.Error(err))
		return
	}

	generatedEvent = []*resourcesapimodels.AddResourceEntry{{
		Attributes:      resource,
		ID:              resourcesapimodels.ResourceID(*scanRequest.ResourceID),
		IntegrationID:   resourcesapimodels.IntegrationID(*scanRequest.IntegrationID),
		IntegrationType: resourcesapimodels.IntegrationTypeAws,
		Type:            resourcesapimodels.ResourceType(*scanRequest.ResourceType),
	}}

	return generatedEvent, nil
}
