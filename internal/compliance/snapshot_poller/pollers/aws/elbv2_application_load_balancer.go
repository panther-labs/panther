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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/elbv2/elbv2iface"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/aws/aws-sdk-go/service/wafregional/wafregionaliface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	Elbv2ClientFunc = setupElbv2Client
	sslPolicies     = map[string]*elbv2.SslPolicy{}
)

func setupElbv2Client(sess *session.Session, cfg *aws.Config) interface{} {
	return elbv2.New(sess, cfg)
}

func getElbv2Client(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (elbv2iface.ELBV2API, error) {
	client, err := getClient(pollerResourceInput, Elbv2ClientFunc, "elbv2", region)
	if err != nil {
		return nil, err
	}

	return client.(elbv2iface.ELBV2API), nil
}

// PollELBV2 LoadBalancer polls a single ELBV2 Application Load Balancer resource
func PollELBV2LoadBalancer(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	elbv2Client, err := getElbv2Client(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	wafClient, err := getWafRegionalClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	loadBalancer, err := getApplicationLoadBalancer(elbv2Client, scanRequest.ResourceID)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildElbv2ApplicationLoadBalancerSnapshot(elbv2Client, wafClient, loadBalancer)
	if err != nil || snapshot == nil {
		return nil, err
	}

	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// getApplicationLoadBalancer returns a specifc ELBV2 application load balancer
func getApplicationLoadBalancer(svc elbv2iface.ELBV2API, loadBalancerARN *string) (*elbv2.LoadBalancer, error) {
	loadBalancer, err := svc.DescribeLoadBalancers(&elbv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []*string{loadBalancerARN},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == elbv2.ErrCodeLoadBalancerNotFoundException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *loadBalancerARN),
				zap.String("resourceType", awsmodels.Elbv2LoadBalancerSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "ELBV2.DescribeLoadBalancers: %s", aws.StringValue(loadBalancerARN))
	}

	if len(loadBalancer.LoadBalancers) != 1 {
		return nil, errors.WithMessagef(
			errors.New("ELBV2.DescribeLoadBalancers"),
			"expected exactly one ELBV2 load balancer when describing %s, but found %d load balancers",
			aws.StringValue(loadBalancerARN),
			len(loadBalancer.LoadBalancers),
		)
	}
	return loadBalancer.LoadBalancers[0], nil
}

// describeLoadBalancers returns a list of all Load Balancers in the account in the current region
func describeLoadBalancers(elbv2Svc elbv2iface.ELBV2API, nextMarker *string) (
	loadBalancers []*elbv2.LoadBalancer, marker *string, err error) {

	err = elbv2Svc.DescribeLoadBalancersPages(&elbv2.DescribeLoadBalancersInput{
		Marker:   nextMarker,
		PageSize: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *elbv2.DescribeLoadBalancersOutput, lastPage bool) bool {
			return loadBalancerIterator(page, &loadBalancers, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "ELBV2.DescribeLoadBalancersPages")
	}
	return
}

func loadBalancerIterator(page *elbv2.DescribeLoadBalancersOutput, loadBalancers *[]*elbv2.LoadBalancer, marker **string) bool {
	*loadBalancers = append(*loadBalancers, page.LoadBalancers...)
	*marker = page.NextMarker
	return len(*loadBalancers) < defaultBatchSize
}

// describeListeners returns all the listeners for a given ELBV2 load balancer
func describeListeners(elbv2Svc elbv2iface.ELBV2API, arn *string) (listeners []*elbv2.Listener, err error) {
	err = elbv2Svc.DescribeListenersPages(&elbv2.DescribeListenersInput{LoadBalancerArn: arn},
		func(page *elbv2.DescribeListenersOutput, lastPage bool) bool {
			listeners = append(listeners, page.Listeners...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "ELBV2.DescribeListenersPages: %s", aws.StringValue(arn))
	}
	return
}

// describeTags returns all the tags associated to the given load balancer
func describeTags(svc elbv2iface.ELBV2API, arn *string) ([]*elbv2.Tag, error) {
	tags, err := svc.DescribeTags(&elbv2.DescribeTagsInput{ResourceArns: []*string{arn}})
	if err != nil {
		return nil, errors.Wrapf(err, "ELBV2.DescribeTags: %s", aws.StringValue(arn))
	}

	return tags.TagDescriptions[0].Tags, nil
}

// describeSSLPolicies returns all the SSL policies in the current region
func describeSSLPolicies(svc elbv2iface.ELBV2API) ([]*elbv2.SslPolicy, error) {
	sslPoliciesDescription, err := svc.DescribeSSLPolicies(&elbv2.DescribeSSLPoliciesInput{})
	if err != nil {
		return nil, errors.Wrap(err, "ELBV2.DescribeSSLPolicies")
	}
	return sslPoliciesDescription.SslPolicies, nil
}

// getWebACLForResource returns the web ACL ID for the given application load balancer
func getWebACLForResource(wafRegionalSvc wafregionaliface.WAFRegionalAPI, arn *string) (*string, error) {
	out, err := wafRegionalSvc.GetWebACLForResource(
		&wafregional.GetWebACLForResourceInput{ResourceArn: arn},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "WAF.GetWebACLForResource: %s", aws.StringValue(arn))
	}

	if out.WebACLSummary == nil {
		return nil, nil
	}

	return out.WebACLSummary.WebACLId, nil
}

// generateSSLPolices sets up the sslPolicies map for reference
func generateSSLPolicies(svc elbv2iface.ELBV2API) error {
	policies, err := describeSSLPolicies(svc)
	if err == nil {
		sslPolicies = make(map[string]*elbv2.SslPolicy, len(policies))
		for _, policy := range policies {
			sslPolicies[*policy.Name] = policy
		}
	}
	return err
}

// buildElbv2ApplicationLoadBalancerSnapshot makes all the calls to build up a snapshot of a given
// application load balancer
func buildElbv2ApplicationLoadBalancerSnapshot(
	elbv2Svc elbv2iface.ELBV2API,
	wafRegionalSvc wafregionaliface.WAFRegionalAPI,
	lb *elbv2.LoadBalancer,
) (*awsmodels.Elbv2ApplicationLoadBalancer, error) {

	if lb == nil {
		return nil, nil
	}

	applicationLoadBalancer := &awsmodels.Elbv2ApplicationLoadBalancer{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   lb.LoadBalancerArn,
			TimeCreated:  lb.CreatedTime,
			ResourceType: aws.String(awsmodels.Elbv2LoadBalancerSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  lb.LoadBalancerArn,
			Name: lb.LoadBalancerName,
		},
		AvailabilityZones:      lb.AvailabilityZones,
		CanonicalHostedZonedId: lb.CanonicalHostedZoneId,
		DNSName:                lb.DNSName,
		IpAddressType:          lb.IpAddressType,
		Scheme:                 lb.Scheme,
		SecurityGroups:         lb.SecurityGroups,
		State:                  lb.State,
		Type:                   lb.Type,
		VpcId:                  lb.VpcId,
	}

	tags, err := describeTags(elbv2Svc, lb.LoadBalancerArn)
	if err != nil {
		return nil, err
	}
	applicationLoadBalancer.Tags = utils.ParseTagSlice(tags)

	// Build the list of listeners and associated SSL Policies for the load balancer
	listeners, err := describeListeners(elbv2Svc, lb.LoadBalancerArn)
	if err != nil {
		return nil, err
	}
	if len(listeners) != 0 {
		applicationLoadBalancer.Listeners = listeners
		applicationLoadBalancer.SSLPolicies = make(map[string]*elbv2.SslPolicy)
		for _, listener := range listeners {
			if listener.SslPolicy == nil {
				continue
			}
			if sslPolicies == nil {
				// This list doesn't ever change, so we generate it once and cache it for the
				// lifetime of the lambda if it is ever needed. We have to check here as the cache
				// may not be populated for single resource scanning.
				//
				// TODO: implement a proper cache setup here and don't nest it away like this. Just build the cache when expired.
				err = generateSSLPolicies(elbv2Svc)
				if err != nil {
					return nil, err
				}
			}
			if policy, ok := sslPolicies[*listener.SslPolicy]; ok {
				applicationLoadBalancer.SSLPolicies[*listener.SslPolicy] = policy
			}
		}
	}

	// currently, waf is only supported in ALB
	if aws.StringValue(lb.Type) == elbv2.LoadBalancerTypeEnumApplication {
		// Try to find a webACL ID
		if applicationLoadBalancer.WebAcl, err = getWebACLForResource(wafRegionalSvc, lb.LoadBalancerArn); err != nil {
			return nil, err
		}
	}

	return applicationLoadBalancer, nil
}

// PollElbv2ApplicationLoadBalancers gathers information on each application load balancer for an AWS account.
func PollElbv2ApplicationLoadBalancers(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting ELBV2 Application Load Balancer resource poller")

	elbv2Svc, err := getElbv2Client(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	wafRegionalSvc, err := getWafRegionalClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all load balancers
	loadBalancers, marker, err := describeLoadBalancers(elbv2Svc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	// Next generate a list of SSL policies to be shared by the load balancer snapshots
	err = generateSSLPolicies(elbv2Svc)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(loadBalancers))
	for _, loadBalancer := range loadBalancers {
		elbv2LoadBalancer, err := buildElbv2ApplicationLoadBalancerSnapshot(
			elbv2Svc,
			wafRegionalSvc,
			loadBalancer,
		)
		if err != nil {
			return nil, nil, err
		}

		elbv2LoadBalancer.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		elbv2LoadBalancer.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      elbv2LoadBalancer,
			ID:              *elbv2LoadBalancer.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.Elbv2LoadBalancerSchema,
		})
	}

	return resources, marker, nil
}
