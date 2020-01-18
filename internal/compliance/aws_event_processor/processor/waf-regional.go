package processor

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

func classifyWAFRegional(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// These cases are tough because they don't link these resources back to any attached Web ACLs,
	// of which there could be several. Just scan all web ACLs for now until there is a link table
	// or a sub-resource for each of these. This catches 11 API calls to WAF non Web ACL resources.
	if strings.HasPrefix(eventName, "Update") && eventName != "UpdateWebACL" {
		return []*resourceChange{{
			AwsAccountID: accountID,
			EventName:    eventName,
			Region:       schemas.GlobalRegion,
			ResourceType: schemas.WafWebAclSchema,
		}}
	}

	// All the API calls we don't care about (until we build resources for them)
	if strings.HasSuffix(eventName, "Set") || // 11
		strings.HasSuffix(eventName, "Rule") || // 6
		strings.HasSuffix(eventName, "RuleGroup") || // 3
		// Permission policies affect rule groups
		eventName == "DeletePermissionPolicy" ||
		eventName == "PutPermissionPolicy" {

		zap.L().Debug("waf-regional: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awswafregional.html
	var wafRegionalARN string
	switch eventName {
	case "CreateWebACL":
		wafRegionalARN = detail.Get("responseElements.webACL.webACLArn").Str
	case "DeleteLoggingConfiguration":
		wafRegionalARN = detail.Get("requestParameters.resourceArn").Str
	case "DeleteWebACL", "UpdateWebACL":
		// arn:aws:waf::account-id:resource-type/resource-id
		wafRegionalARN = strings.Join([]string{
			"arn",
			"aws",                       // Partition
			"waf-regional",              // Service
			detail.Get("awsRegion").Str, // Region
			accountID,                   // Account ID
			"webacl/" + detail.Get("requestParameters.webACLId").Str, // Resource-type/id
		}, ":")
	case "PutLoggingConfiguration":
		wafRegionalARN = detail.Get("requestParameters.loggingConfiguration.resourceArn").Str
	case "AssociateWebACL":
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceArn").Str)
		if err != nil {
			zap.L().Error("waf-regional: error parsing ARN", zap.String("eventName", eventName), zap.Error(err))
		}
		var changes []*resourceChange
		if strings.HasPrefix(resourceARN.Resource, "loadbalancer/") {
			// This Web ACL is being attached to a load balancer, as opposed to an API gateway
			changes = append(changes, &resourceChange{
				AwsAccountID: accountID,
				EventName:    eventName,
				ResourceID:   resourceARN.String(),
				ResourceType: schemas.Elbv2LoadBalancerSchema,
			})
		}
		changes = append(changes, &resourceChange{
			AwsAccountID: accountID,
			EventName:    eventName,
			ResourceID: arn.ARN{
				Partition: "aws",
				Service:   "waf-regional",
				Region:    detail.Get("awsRegion").Str,
				AccountID: accountID,
				Resource:  "webacl/" + detail.Get("requestParameters.webAclId").Str,
			}.String(),
			ResourceType: schemas.WafRegionalWebAclSchema,
		})
		return changes
	case "DisassociateWebACL":
		// Similar to AssociateWebACL, however since a resource can only have one Web ACL attached
		// to it you do not have to specify the web ACL to disassociate in this request so we must
		// do a full waf-regional scan to figure out which one it was. If we later start supporting
		// doing resource lookups against the resources-api table from within the event processor,
		// we can look up which ACL exactly is the one to be scanned and save some polling work here.
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceArn").Str)
		if err != nil {
			zap.L().Error("waf-regional: error parsing ARN", zap.String("eventName", eventName), zap.Error(err))
		}
		var changes []*resourceChange
		if strings.HasPrefix(resourceARN.Resource, "loadbalancer/") {
			// This Web ACL is being attached to a load balancer, as opposed to an API gateway
			changes = append(changes, &resourceChange{
				AwsAccountID: accountID,
				EventName:    eventName,
				ResourceID:   resourceARN.String(),
				ResourceType: schemas.Elbv2LoadBalancerSchema,
			})
		}
		changes = append(changes, &resourceChange{
			AwsAccountID: accountID,
			EventName:    eventName,
			Region:       detail.Get("awsRegion").Str,
			ResourceType: schemas.WafRegionalWebAclSchema,
		})
		return changes

	default:
		zap.L().Warn("waf-regional: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	parsedARN, err := arn.Parse(wafRegionalARN)
	if err != nil {
		zap.L().Error("waf-regional: error parsing ARN", zap.String("eventName", eventName), zap.Error(err))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteWebACL",
		EventName:    eventName,
		ResourceID:   parsedARN.String(),
		ResourceType: schemas.WafWebAclSchema,
	}}
}
