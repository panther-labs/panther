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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	// The amount of time credentials are valid
	assumeRoleDuration = time.Hour
	// retries on default session
	maxRetries = 6
)

var (
	snapshotPollerSession *session.Session
	// assumeRoleFunc is the function to return valid AWS credentials.
	assumeRoleFunc         = assumeRole
	verifyAssumedCredsFunc = verifyAssumedCreds
	GetServiceRegionsFunc  = GetServiceRegions

	// This maps the name we have given to a type of resource to the corresponding AWS name for the
	// service that the resource type is a part of.
	typeToIDMapping = map[string]string{
		awsmodels.AcmCertificateSchema:      acm.ServiceName,
		awsmodels.CloudFormationStackSchema: cloudformation.ServiceName,
		awsmodels.CloudTrailSchema:          cloudtrail.ServiceName,
		awsmodels.CloudWatchLogGroupSchema:  cloudwatchlogs.ServiceName,
		awsmodels.ConfigServiceSchema:       configservice.ServiceName,
		awsmodels.DynamoDBTableSchema:       dynamodb.ServiceName,
		awsmodels.Ec2AmiSchema:              ec2.ServiceName,
		awsmodels.Ec2InstanceSchema:         ec2.ServiceName,
		awsmodels.Ec2NetworkAclSchema:       ec2.ServiceName,
		awsmodels.Ec2SecurityGroupSchema:    ec2.ServiceName,
		awsmodels.Ec2VolumeSchema:           ec2.ServiceName,
		awsmodels.Ec2VpcSchema:              ec2.ServiceName,
		awsmodels.EcsClusterSchema:          ecs.ServiceName,
		awsmodels.Elbv2LoadBalancerSchema:   elbv2.ServiceName,
		awsmodels.GuardDutySchema:           guardduty.ServiceName,
		awsmodels.IAMGroupSchema:            iam.ServiceName,
		awsmodels.IAMPolicySchema:           iam.ServiceName,
		awsmodels.IAMRoleSchema:             iam.ServiceName,
		awsmodels.IAMRootUserSchema:         iam.ServiceName,
		awsmodels.IAMUserSchema:             iam.ServiceName,
		awsmodels.KmsKeySchema:              kms.ServiceName,
		awsmodels.LambdaFunctionSchema:      lambda.ServiceName,
		awsmodels.PasswordPolicySchema:      iam.ServiceName,
		awsmodels.RDSInstanceSchema:         rds.ServiceName,
		awsmodels.RedshiftClusterSchema:     redshift.ServiceName,
		awsmodels.S3BucketSchema:            s3.ServiceName,
		awsmodels.WafRegionalWebAclSchema:   waf.ServiceName,
		awsmodels.WafWebAclSchema:           wafregional.ServiceName,
	}

	// These services do not support regional scans, either because the resource itself is not
	// regional or because we construct a "Meta" resource that needs the full context of every
	// resource to be updated.
	globalOnlyTypes = map[string]struct{}{
		awsmodels.CloudTrailSchema:     {}, // Has a meta resource
		awsmodels.ConfigServiceSchema:  {}, // Has a meta resource
		awsmodels.GuardDutySchema:      {}, // Has a meta resource
		awsmodels.IAMGroupSchema:       {}, // Global service
		awsmodels.IAMPolicySchema:      {}, // Global service
		awsmodels.IAMRoleSchema:        {}, // Global service
		awsmodels.IAMRootUserSchema:    {}, // Global service
		awsmodels.IAMUserSchema:        {}, // Global service
		awsmodels.PasswordPolicySchema: {}, // Global service
		awsmodels.WafWebAclSchema:      {}, // Global service
	}
)

// Key used for the client cache to neatly encapsulate an integration, service, and region
type clientKey struct {
	IntegrationID string
	Service       string
	Region        string
}

type cachedClient struct {
	Client      interface{}
	Credentials *credentials.Credentials
}

var clientCache = make(map[clientKey]cachedClient)

func Setup() {
	awsConfig := aws.NewConfig().WithMaxRetries(maxRetries)
	snapshotPollerSession = session.Must(session.NewSession(request.WithRetryer(awsConfig,
		awsretry.NewConnectionErrRetryer(*awsConfig.MaxRetries))))
}

// GetRegionsToScan determines what regions need to be scanned in order to perform a full account
// scan for a given resource type
func GetRegionsToScan(pollerInput *awsmodels.ResourcePollerInput, resourceType string) (regions []*string, err error) {
	// For resources where we are always going to perform a full account scan anyways, just return a
	// single region.
	if _, ok := globalOnlyTypes[resourceType]; ok {
		return []*string{&defaultRegion}, nil
	}

	return GetServiceRegions(pollerInput, resourceType)
}

// GetServiceRegions determines what regions are both enabled in the account and are supported by
// AWS for the given resource type.
func GetServiceRegions(pollerInput *awsmodels.ResourcePollerInput, resourceType string) ([]*string, error) {
	// Determine the service ID based on the resource type
	serviceID, ok := typeToIDMapping[resourceType]
	if !ok {
		return nil, errors.Errorf("no service mapping for resource type %s", resourceType)
	}

	// Lookup the regions that the account has enabled
	ec2Svc, err := getClient(pollerInput, EC2ClientFunc, "ec2", defaultRegion)
	if err != nil {
		return nil, err
	}
	describeRegionsOutput, err := ec2Svc.(ec2iface.EC2API).DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, errors.Wrap(err, "EC2.DescribeRegions")
	}

	// Create a set of regions to union with the service enabled regions below
	enabledRegions := make(map[string]struct{})
	for _, region := range describeRegionsOutput.Regions {
		enabledRegions[*region.RegionName] = struct{}{}
	}

	// Lookup the regions that AWS supports for the service, storing the ones that are also enabled
	// for this account.
	// Important to note that we are not creating this client with credentials from the account being
	// scanned, we are creating this client with the credentials of the snapshot-poller lambda execution
	// role. This for two reasons:
	// 	1. We would have to update all PantherAuditRole's to include this permission, which would be
	//		a painful migration
	//	2. This information is globally the same, it doesn't matter what account you're in when you
	//		make this particular API call the response is always the same
	ssmSvc := ssm.New(snapshotPollerSession)
	var regions []*string
	err = ssmSvc.GetParametersByPathPages(&ssm.GetParametersByPathInput{
		Path: aws.String("/aws/service/global-infrastructure/services/" + serviceID + "/regions"),
	}, func(page *ssm.GetParametersByPathOutput, b bool) bool {
		for _, param := range page.Parameters {
			if _, ok := enabledRegions[*param.Value]; ok {
				regions = append(regions, param.Value)
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	return regions, nil
}

// getClient returns a valid client for a given integration, service, and region using caching.
func getClient(pollerInput *awsmodels.ResourcePollerInput,
	clientFunc func(session *session.Session, config *aws.Config) interface{},
	service string, region string) (interface{}, error) {

	cacheKey := clientKey{
		IntegrationID: *pollerInput.IntegrationID,
		Service:       service,
		Region:        region,
	}

	// Return the cached client if the credentials used to build it are not expired
	if cachedClient, exists := clientCache[cacheKey]; exists {
		if !cachedClient.Credentials.IsExpired() {
			if cachedClient.Client != nil {
				return cachedClient.Client, nil
			}
			zap.L().Debug("expired client was cached", zap.Any("cache key", cacheKey))
		}
	}

	// Build a new client on cache miss OR if the client in the cache has expired credentials
	creds := assumeRoleFunc(pollerInput, snapshotPollerSession, region)
	err := verifyAssumedCredsFunc(creds, region)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get %s client in %s region", service, region)
	}
	client := clientFunc(snapshotPollerSession, &aws.Config{
		Credentials: creds,
		Region:      &region,
	})
	clientCache[cacheKey] = cachedClient{
		Client:      client,
		Credentials: creds,
	}
	return client, nil
}

//  assumes an IAM role associated with an AWS Snapshot Integration.
func assumeRole(pollerInput *awsmodels.ResourcePollerInput, sess *session.Session, region string) *credentials.Credentials {
	zap.L().Debug("assuming role", zap.String("roleArn", *pollerInput.AuthSource))

	if pollerInput.AuthSource == nil {
		panic("must pass non-nil authSource to AssumeRole")
	}

	creds := stscreds.NewCredentials(
		sess.Copy(&aws.Config{
			Region: &region, // this makes it work with regional endpoints
		}),
		*pollerInput.AuthSource,
		func(p *stscreds.AssumeRoleProvider) {
			p.Duration = assumeRoleDuration
		},
	)

	return creds
}

func verifyAssumedCreds(creds *credentials.Credentials, region string) error {
	svc := sts.New(
		snapshotPollerSession,
		&aws.Config{
			Credentials: creds,
			Region:      &region,
		},
	)
	_, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	return err
}
