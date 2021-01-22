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
	"github.com/aws/aws-sdk-go/aws/endpoints"
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
	"github.com/aws/aws-sdk-go/service/eks"
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
	lru "github.com/hashicorp/golang-lru"
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
	// Maximum number of rate limited resources to remember
	rateLimitCacheSize = 5000
)

var (
	SnapshotPollerSession *session.Session

	// These are exported so the top-level unit tests can mock them out.
	// AssumeRoleFunc is the function to return valid AWS credentials.
	AssumeRoleFunc         = assumeRole
	VerifyAssumedCredsFunc = verifyAssumedCreds
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
		awsmodels.EksClusterSchema:          eks.ServiceName,
		// For every other service, the service name aligns with how SSM refers to the service. For
		// just the elb and elbv2 service, this is not the case. AWS just had to do it to 'em.
		awsmodels.Elbv2LoadBalancerSchema: "elb",
		awsmodels.GuardDutySchema:         guardduty.ServiceName,
		awsmodels.IAMGroupSchema:          iam.ServiceName,
		awsmodels.IAMPolicySchema:         iam.ServiceName,
		awsmodels.IAMRoleSchema:           iam.ServiceName,
		awsmodels.IAMRootUserSchema:       iam.ServiceName,
		awsmodels.IAMUserSchema:           iam.ServiceName,
		awsmodels.KmsKeySchema:            kms.ServiceName,
		awsmodels.LambdaFunctionSchema:    lambda.ServiceName,
		awsmodels.PasswordPolicySchema:    iam.ServiceName,
		awsmodels.RDSInstanceSchema:       rds.ServiceName,
		awsmodels.RedshiftClusterSchema:   redshift.ServiceName,
		awsmodels.S3BucketSchema:          s3.ServiceName,
		awsmodels.WafRegionalWebAclSchema: waf.ServiceName,
		awsmodels.WafWebAclSchema:         wafregional.ServiceName,
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

	// Used to cache region & account specific AWS clients
	clientCache = make(map[clientKey]cachedClient)

	// Used to remember resource IDs that have recently been rate limited so we avoid re-scanning them
	RateLimitTracker *lru.ARCCache
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

type RegionIgnoreListError struct {
	Err error
}

func (r *RegionIgnoreListError) Error() string {
	return r.Err.Error()
}

func Setup() {
	awsSession := session.Must(session.NewSession()) // use default retries for fetching creds, avoids hangs!
	SnapshotPollerSession = awsSession.Copy(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries)))

	var err error
	RateLimitTracker, err = lru.NewARC(rateLimitCacheSize)
	if err != nil {
		panic(err)
	}
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
	ssmSvc := ssm.New(SnapshotPollerSession)
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

	// Check if provided region is in the ignoreList
	for _, deniedRegion := range pollerInput.RegionIgnoreList {
		if region == deniedRegion {
			return nil, &RegionIgnoreListError{
				Err: errors.New("requested region was in region ignoreList"),
			}
		}
	}

	cacheKey := clientKey{
		IntegrationID: *pollerInput.IntegrationID,
		Service:       service,
		Region:        region,
	}

	// Return the cached client
	if cachedClient, exists := clientCache[cacheKey]; exists {
		zap.L().Debug("client was cached", zap.Any("cache key", cacheKey))
		return cachedClient.Client, nil
	}

	// Build a new client on cache miss

	// First we need to use our existing AWS session (in the Panther account) to create credentials
	// for the IAM role in the account to be scanned
	creds := AssumeRoleFunc(pollerInput, SnapshotPollerSession)

	// Second, we need to create a new session in the account to be scanned using the credentials
	// we just created. This works around a situation where the account being scanned has an opt-in
	// region enabled that the Panther account does not.
	//
	// The region does not matter here, since we are just creating the session. When we create the
	// client, we will need to specify the region.
	clientSession := SnapshotPollerSession.Copy(aws.NewConfig().WithCredentials(creds))

	// Verify that the session is valid
	if err := VerifyAssumedCredsFunc(clientSession, region); err != nil {
		return nil, errors.Wrapf(err, "failed to get %s client in %s region", service, region)
	}

	// Finally, actually create the client based on the specified service in the specified region
	client := clientFunc(clientSession, &aws.Config{
		Region: &region, // This makes it work with regional endpoints
	})
	clientCache[cacheKey] = cachedClient{
		Client:      client,
		Credentials: creds,
	}
	return client, nil
}

//  assumes an IAM role associated with an AWS Snapshot Integration.
func assumeRole(pollerInput *awsmodels.ResourcePollerInput, sess *session.Session) *credentials.Credentials {
	zap.L().Debug("assuming role", zap.String("roleArn", *pollerInput.AuthSource))

	if pollerInput.AuthSource == nil {
		panic("must pass non-nil authSource to AssumeRole")
	}

	creds := stscreds.NewCredentials(
		sess.Copy(aws.NewConfig().WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)),
		*pollerInput.AuthSource,
		func(p *stscreds.AssumeRoleProvider) {
			p.Duration = assumeRoleDuration
		},
	)

	return creds
}

func verifyAssumedCreds(sess *session.Session, region string) error {
	svc := sts.New(sess, aws.NewConfig().WithRegion(region))
	_, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	return err
}
