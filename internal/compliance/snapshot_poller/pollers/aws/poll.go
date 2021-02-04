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
	"math/rand"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	resourcesapimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
	"github.com/panther-labs/panther/pkg/awsutils"
)

// resourcePoller is a simple struct to be used only for invoking the ResourcePollers in order.
type resourcePoller struct {
	description    string
	resourcePoller awsmodels.ResourcePoller
}

const (
	integrationType = "aws"
	// How long to wait before re-scanning a resource that was rate limited during scanning
	rateLimitDelay = time.Minute * 5
)

var (
	// Default region to use when building clients for the individual resource poller
	// defaultRegion = endpoints.UsWest2RegionID
	defaultRegion = os.Getenv("AWS_REGION")

	// Exported for top-level unit tests to mock out
	AuditRoleName = os.Getenv("AUDIT_ROLE_NAME")

	// The default max number of resources to scan at once. We will keep paging until we scan this
	// many resources, then do one additional page worth of resources
	defaultBatchSize   = 100
	pageRequeueDelayer = rand.New(rand.NewSource(time.Now().UnixNano())) // nolint:gosec

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
		awsmodels.EksClusterSchema:     PollEKSCluster, // This function is never entered - lacking event-processor
		awsmodels.GuardDutySchema:      PollGuardDutyDetector,
		awsmodels.PasswordPolicySchema: PollPasswordPolicyResource,
	}

	// ServicePollers maps a resource type to its Poll function
	ServicePollers = map[string]resourcePoller{
		awsmodels.AcmCertificateSchema:      {"ACMCertificate", PollAcmCertificates},
		awsmodels.CloudFormationStackSchema: {"CloudFormationStack", PollCloudFormationStacks},
		awsmodels.CloudTrailSchema:          {"CloudTrail", PollCloudTrails},
		awsmodels.CloudWatchLogGroupSchema:  {"CloudWatchLogGroup", PollCloudWatchLogsLogGroups},
		awsmodels.ConfigServiceSchema:       {"ConfigService", PollConfigServices},
		awsmodels.DynamoDBTableSchema:       {"DynamoDBTable", PollDynamoDBTables},
		awsmodels.Ec2AmiSchema:              {"EC2AMI", PollEc2Amis},
		awsmodels.Ec2InstanceSchema:         {"EC2Instance", PollEc2Instances},
		awsmodels.Ec2NetworkAclSchema:       {"EC2NetworkACL", PollEc2NetworkAcls},
		awsmodels.Ec2SecurityGroupSchema:    {"EC2SecurityGroup", PollEc2SecurityGroups},
		awsmodels.Ec2VolumeSchema:           {"EC2Volume", PollEc2Volumes},
		awsmodels.Ec2VpcSchema:              {"EC2VPC", PollEc2Vpcs},
		awsmodels.EcsClusterSchema:          {"ECSCluster", PollEcsClusters},
		awsmodels.EksClusterSchema:          {"EKSCluster", PollEksClusters},
		awsmodels.Elbv2LoadBalancerSchema:   {"ELBV2LoadBalancer", PollElbv2ApplicationLoadBalancers},
		awsmodels.GuardDutySchema:           {"GuardDutyDetector", PollGuardDutyDetectors},
		awsmodels.IAMGroupSchema:            {"IAMGroups", PollIamGroups},
		awsmodels.IAMPolicySchema:           {"IAMPolicies", PollIamPolicies},
		awsmodels.IAMRoleSchema:             {"IAMRoles", PollIAMRoles},
		awsmodels.IAMUserSchema:             {"IAMUser", PollIAMUsers},
		// Service scan for the resource type IAMRootUserSchema is not defined! Do not do it!
		awsmodels.KmsKeySchema:            {"KMSKey", PollKmsKeys},
		awsmodels.LambdaFunctionSchema:    {"LambdaFunctions", PollLambdaFunctions},
		awsmodels.PasswordPolicySchema:    {"PasswordPolicy", PollPasswordPolicy},
		awsmodels.RDSInstanceSchema:       {"RDSInstance", PollRDSInstances},
		awsmodels.RedshiftClusterSchema:   {"RedshiftCluster", PollRedshiftClusters},
		awsmodels.S3BucketSchema:          {"S3Bucket", PollS3Buckets},
		awsmodels.WafWebAclSchema:         {"WAFWebAcl", PollWafWebAcls},
		awsmodels.WafRegionalWebAclSchema: {"WAFRegionalWebAcl", PollWafRegionalWebAcls},
	}
)

// Poll coordinates AWS generatedEvents gathering across all relevant resources for compliance monitoring.
func Poll(scanRequest *pollermodels.ScanEntry) (
	generatedEvents []resourcesapimodels.AddResourceEntry, err error) {

	if scanRequest.AWSAccountID == nil {
		return nil, errors.New("no AWS AccountID provided")
	}

	// Build the audit role manually
	// Format: arn:aws:iam::$(ACCOUNT_ID):role/PantherAuditRole-($REGION)
	if len(AuditRoleName) == 0 {
		return nil, errors.New("no audit role configured")
	}
	auditRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s",
		*scanRequest.AWSAccountID, AuditRoleName)

	zap.L().Debug("constructed audit role", zap.String("role", auditRoleARN))

	// Extract the role ARN to construct various ResourceIDs.
	roleArn, err := arn.Parse(auditRoleARN)
	// This error cannot be retried so we don't return it
	if err != nil {
		zap.L().Error("unable to parse constructed audit role", zap.Error(err), zap.String("roleARN", auditRoleARN))
		return nil, nil
	}

	pollerResourceInput := &awsmodels.ResourcePollerInput{
		AuthSource:          &auditRoleARN,
		AuthSourceParsedARN: roleArn,
		IntegrationID:       scanRequest.IntegrationID,
		// This field may be nil
		Region: scanRequest.Region,
		// Note: The resources-api expects a time.Time formatted string.
		Timestamp:               aws.Time(utils.TimeNowFunc()),
		NextPageToken:           scanRequest.NextPageToken,
		RegionIgnoreList:        scanRequest.RegionIgnoreList,
		ResourceRegexIgnoreList: scanRequest.ResourceRegexIgnoreList,
		ResourceTypeIgnoreList:  scanRequest.ResourceTypeIgnoreList,
	}
	err = pollerResourceInput.CompileRegex()
	if err != nil {
		zap.L().Error("unable to compile passed regex",
			zap.Any("resource regex ignore list", scanRequest.ResourceRegexIgnoreList))
		return nil, err
	}

	// Check if integration is disabled
	if scanRequest.Enabled != nil && !*scanRequest.Enabled {
		zap.L().Info("source integration disabled",
			zap.String("integration id", *scanRequest.IntegrationID))
		return nil, nil
	}

	// Check if resource type is filtered
	for _, resourceType := range pollerResourceInput.ResourceTypeIgnoreList {
		if resourceType == *scanRequest.ResourceType {
			zap.L().Info("resource type filtered", zap.String("resource type", resourceType))
			return nil, nil
		}
	}

	// If this is an individual resource scan or the region is provided,
	// we don't need to lookup the active regions.
	if scanRequest.ResourceID != nil {
		// Individual resource scan
		zap.L().Debug("processing single resource scan")
		return singleResourceScan(scanRequest, pollerResourceInput)
	}

	// If a resource ID is not provided, a resource type must be present
	// This error cannot be retried so we don't return it
	if scanRequest.ResourceType == nil {
		zap.L().Error(
			"Invalid scan request input - resourceID or resourceType must be specified",
			zap.Any("input", scanRequest),
		)
		return nil, nil
	}

	// If a region is provided, we're good to start the scan
	if scanRequest.Region != nil {
		zap.L().Info("processing single region service scan",
			zap.String("region", *scanRequest.Region),
			zap.String("resourceType", *scanRequest.ResourceType))
		// Check if provided region is in ignoreList
		for _, region := range pollerResourceInput.RegionIgnoreList {
			if region == *scanRequest.Region {
				zap.L().Info("matched ignoreList region - skipping scan",
					zap.String("region", region))
				return nil, nil
			}
		}
		if poller, ok := ServicePollers[*scanRequest.ResourceType]; ok {
			return serviceScan(
				poller,
				pollerResourceInput,
				scanRequest,
			)
		} else {
			return nil, errors.Errorf("invalid single region resource type '%s' scan requested", *scanRequest.ResourceType)
		}
	}

	// If no region was specified, we need to re-queue one new scan request for each active region
	return multiRegionScan(pollerResourceInput, scanRequest)
}

func multiRegionScan(
	pollerInput *awsmodels.ResourcePollerInput,
	scanRequest *pollermodels.ScanEntry,
) (generatedEvents []resourcesapimodels.AddResourceEntry, err error) {
	// If a region is not provided, then an 'all regions' scan is being requested. We don't
	// support scanning multiple regions in one request, so we translate this request into a single
	// region scan in each region.
	//
	// Lookup the regions that are both enabled and supported by this service
	regions, err := GetRegionsToScan(pollerInput, *scanRequest.ResourceType)
	if err != nil {
		return nil, err
	}

	zap.L().Info(
		"processing full account resource type scan",
		zap.Any("regions", regions),
		zap.String("resourceType", *scanRequest.ResourceType),
	)
	// For simplicity, region ignoreList is not checked here
	for _, region := range regions {
		err = utils.Requeue(pollermodels.ScanMsg{
			Entries: []*pollermodels.ScanEntry{
				{
					AWSAccountID:            scanRequest.AWSAccountID,
					IntegrationID:           scanRequest.IntegrationID,
					Region:                  region,
					ResourceType:            scanRequest.ResourceType,
					Enabled:                 scanRequest.Enabled,
					RegionIgnoreList:        scanRequest.RegionIgnoreList,
					ResourceRegexIgnoreList: scanRequest.ResourceRegexIgnoreList,
					ResourceTypeIgnoreList:  scanRequest.ResourceTypeIgnoreList,
				},
			},
		}, int64(pageRequeueDelayer.Intn(30)+1)) // Delay between 1 & 30 seconds to spread out region scans
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func serviceScan(
	poller resourcePoller,
	pollerInput *awsmodels.ResourcePollerInput,
	scanRequest *pollermodels.ScanEntry,
) (generatedEvents []resourcesapimodels.AddResourceEntry, err error) {

	var marker *string
	generatedEvents, marker, err = poller.resourcePoller(pollerInput)
	if err != nil {
		zap.L().Info(
			"an error occurred while polling",
			zap.String("resourcePoller", poller.description),
			zap.String("errorMessage", err.Error()),
		)
		return
	}

	zap.L().Info(
		"resources generated",
		zap.Int("numResources", len(generatedEvents)),
		zap.String("resourcePoller", poller.description),
	)

	// If we exited early because we hit the max batch size, re-queue a scan starting from where we
	// left off
	if marker != nil {
		zap.L().Debug("hit max batch size")
		scanRequest.NextPageToken = marker
		err = utils.Requeue(pollermodels.ScanMsg{
			Entries: []*pollermodels.ScanEntry{
				scanRequest,
			},
		}, int64(pageRequeueDelayer.Intn(30)+1)) // Delay between 1 & 30 seconds to spread out page scans
		if err != nil {
			return nil, err
		}
	}

	return generatedEvents, nil
}

func singleResourceScan(
	scanRequest *pollermodels.ScanEntry,
	pollerInput *awsmodels.ResourcePollerInput,
) ([]resourcesapimodels.AddResourceEntry, error) {

	var resource interface{}
	var err error

	// First, check if we've been rate limited recently while attempting to scan this resource. If
	// so, discard the scan request. There is already one in the ether waiting to be picked up.
	if timestamp, ok := RateLimitTracker.Get(*scanRequest.ResourceID); ok {
		if timestamp.(time.Time).After(time.Now()) {
			// We were recently rate limited while scanning this resource, ignore it
			zap.L().Debug("rate limit encountered, skipping resource scan")
			return nil, nil
		} else {
			RateLimitTracker.Remove(*scanRequest.ResourceID)
		}
	}

	// I don't know why this comment is here and I'm too scared to remove it
	// TODO: does this accept short names?
	if pollFunction, ok := IndividualResourcePollers[*scanRequest.ResourceType]; ok {
		// Handle cases where the ResourceID is not an ARN
		parsedResourceID := utils.ParseResourceID(*scanRequest.ResourceID)
		resource, err = pollFunction(pollerInput, parsedResourceID, scanRequest)
	} else if pollFunction, ok := IndividualARNResourcePollers[*scanRequest.ResourceType]; ok {
		// Handle cases where the ResourceID is an ARN
		var resourceARN arn.ARN
		resourceARN, err = arn.Parse(*scanRequest.ResourceID)
		if err != nil {
			zap.L().Error("unable to parse resourceID", zap.Error(err), zap.String("resourceID", *scanRequest.ResourceID))
			// This error is not retryable
			return nil, nil
		}
		// Check if ResourceID matches the integration's regex filter
		if pollerInput.ShouldIgnoreResource(*scanRequest.ResourceID) {
			return nil, nil
		}
		resource, err = pollFunction(pollerInput, resourceARN, scanRequest)
	} else {
		zap.L().Error("unable to perform scan of specified resource type", zap.String("resourceType", *scanRequest.ResourceType))
		// This error is not retryable
		return nil, nil
	}

	if err != nil {
		// Check for region ignoreList error
		var e *RegionIgnoreListError
		if errors.As(err, &e) {
			zap.L().Info("Skipping denied region in single resource scan")
			return nil, nil
		}
		// Check for rate limit errors. We don't want to blindly retry rate limit errors as this will
		// cause more rate limit errors, so we re-schedule one new scan several minutes in the future
		// and suppress all other scans for this resource until that time.
		if awsutils.IsAnyError(err, "ThrottlingException") {
			// If we parallelize this function, we will need to see if this is already cached before
			// re-queueing. For now, this is not necessary.
			err = utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{scanRequest},
			}, int64(rateLimitDelay.Seconds())+int64(pageRequeueDelayer.Intn(60)+5))
			// If the requeue failed, give up and just let lambda error retrying handle it
			if err != nil {
				return nil, err
			}
			RateLimitTracker.Add(*scanRequest.ResourceID, time.Now().Add(rateLimitDelay))
			return nil, nil
		}

		// If this was not a rate limit error, return the error
		return nil, errors.Wrapf(
			err,
			"could not scan aws resource: %s, in account: %s",
			aws.StringValue(scanRequest.ResourceID),
			aws.StringValue(scanRequest.AWSAccountID),
		)
	}

	// This can happen for a number of reasons, most commonly that the resource no longer exists
	// or there is custom retry logic built into the specific scanner in use
	if resource == nil {
		return nil, nil
	}

	return []resourcesapimodels.AddResourceEntry{{
		Attributes:      resource,
		ID:              *scanRequest.ResourceID,
		IntegrationID:   *scanRequest.IntegrationID,
		IntegrationType: integrationType,
		Type:            *scanRequest.ResourceType,
	}}, nil
}
