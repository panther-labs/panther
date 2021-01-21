package processor

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyELBV2(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_elasticloadbalancingv2.html
	var parseErr error
	lbARN := arn.ARN{
		Partition: "aws",
		Service:   "elasticloadbalancing",
		Region:    metadata.region,
		AccountID: metadata.accountID,
	}

	// We don't have a separate resource for listeners or listener rules yet, but they're built into
	// the load balancer so we need to update it. Fortunately, the load balancer ARN can be exactly
	// determined from the the ARNs of its components:
	// arn:aws:elasticloadbalancing:region:account-id:loadbalancer/[app|net]/lb-name/lb-id
	// arn:aws:elasticloadbalancing:region:account-id:listener/[app|net]/lb-name/lb-id/listener-id
	// arn:aws:elasticloadbalancing:region:account-id:listener-rule/[app|net]/lb-name/lb-id/listener-id/rule-id
	// So if we split the resource on the '/' character, we always need the elements at indices one,
	// two and three.
	switch metadata.eventName {
	case "AddListenerCertificates", "CreateRule", "DeleteListener", "ModifyListener", "RemoveListenerCertificates":
		listenerARN := detail.Get("requestParameters.listenerArn").Str
		arnComponents := strings.Split(listenerARN, "/")
		lbARN.Resource = strings.Join([]string{
			"loadbalancer",
			arnComponents[1],
			arnComponents[2],
			arnComponents[3],
		}, "/")
	case "DeleteRule", "ModifyRule":
		ruleARN := detail.Get("requestParameters.ruleArn").Str
		arnComponents := strings.Split(ruleARN, "/")
		lbARN.Resource = strings.Join([]string{
			"loadbalancer",
			arnComponents[1],
			arnComponents[2],
			arnComponents[3],
		}, "/")
	case "AddTags", "RemoveTags":
		var changes []*resourceChange
		for _, resource := range detail.Get("requestParameters.resourceArns").Array() {
			resourceARN, err := arn.Parse(resource.Str)
			if err != nil {
				zap.L().Error("elbv2: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
				return nil
			}
			if strings.HasPrefix(resourceARN.Resource, "targetgroup/") {
				continue
			}
			changes = append(changes, &resourceChange{
				AwsAccountID: metadata.accountID,
				Delete:       false,
				EventName:    metadata.eventName,
				ResourceID:   resourceARN.String(),
				ResourceType: schemas.Elbv2LoadBalancerSchema,
			})
		}
		return changes
	case "CreateListener", "DeleteLoadBalancer", "ModifyLoadBalancerAttributes", "SetIpAddressType", "SetSecurityGroups", "SetSubnets":
		lbARN, parseErr = arn.Parse(detail.Get("requestParameters.loadBalancerArn").Str)
		// If no LB ARN is present, this may be a classic load balancer. We don't support classic
		// load balancers. We can tell the difference based on the structure of the request parameters
		if parseErr != nil {
			lbName := detail.Get("requestParameters.loadBalancerName")
			if lbName.Exists() {
				return nil
			}
			zap.L().Error("elbv2: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Any("event", metadata), zap.Error(parseErr))
			return nil
		}
	case "CreateLoadBalancer":
		var changes []*resourceChange
		for _, lb := range detail.Get("responseElements.loadBalancers").Array() {
			lbARN, err := arn.Parse(lb.Get("loadBalancerArn").Str)
			if err != nil {
				zap.L().Error("elbv2: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
				return nil
			}
			changes = append(changes, &resourceChange{
				AwsAccountID: metadata.accountID,
				Delete:       false,
				EventName:    metadata.eventName,
				ResourceID:   lbARN.String(),
				ResourceType: schemas.Elbv2LoadBalancerSchema,
			})
		}
		return changes
	case "SetRulePriorities":
		var changes []*resourceChange
		for _, rule := range detail.Get("requestParameters.rulePriorities").Array() {
			ruleARN := rule.Get("ruleArn").Str
			arnComponents := strings.Split(ruleARN, "/")
			lbARN.Resource = strings.Join([]string{
				"loadbalancer",
				arnComponents[1],
				arnComponents[2],
				arnComponents[3],
			}, "/")
			changes = append(changes, &resourceChange{
				AwsAccountID: metadata.accountID,
				Delete:       false,
				EventName:    metadata.eventName,
				ResourceID:   lbARN.String(),
				ResourceType: schemas.Elbv2LoadBalancerSchema,
			})
		}
		return changes
	default:
		zap.L().Info("elbv2: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteLoadBalancer",
		EventName:    metadata.eventName,
		ResourceID:   lbARN.String(),
		ResourceType: schemas.Elbv2LoadBalancerSchema,
	}}
}
