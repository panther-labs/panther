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

func classifyWAF(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// These cases are tough because they don't link these resources back to any attached Web ACLs,
	// of which there could be several. Just scan all web ACLs for now until there is a link table
	// or a sub-resource for each of these. This catches 11 API calls to WAF non Web ACL resources.
	if strings.HasPrefix(metadata.eventName, "Update") && metadata.eventName != "UpdateWebACL" {
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			Region:       schemas.GlobalRegion,
			ResourceType: schemas.WafWebAclSchema,
		}}
	}

	// All the API calls we don't care about (until we build resources for them)
	if strings.HasSuffix(metadata.eventName, "Set") || // 11
		strings.HasSuffix(metadata.eventName, "Rule") || // 6
		strings.HasSuffix(metadata.eventName, "RuleGroup") { // 3

		zap.L().Debug("waf: ignoring event", zap.String("eventName", metadata.eventName))
		return nil
	}

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awswaf.html
	var wafARN string
	switch metadata.eventName {
	case "CreateWebACL":
		wafARN = detail.Get("responseElements.webACL.webACLArn").Str
	case "DeleteLoggingConfiguration":
		wafARN = detail.Get("requestParameters.resourceArn").Str
	case "DeleteWebACL", "UpdateWebACL":
		// arn:aws:waf::account-id:resource-type/resource-id
		wafARN = strings.Join([]string{
			"arn",
			"aws",              // Partition
			"waf",              // Service
			"",                 // Region (global service so no region)
			metadata.accountID, // Account ID
			"webacl/" + detail.Get("requestParameters.webACLId").Str, // Resource-type/id
		}, ":")
	case "PutLoggingConfiguration":
		wafARN = detail.Get("requestParameters.loggingConfiguration.resourceArn").Str
	default:
		zap.L().Info("waf: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	parsedARN, err := arn.Parse(wafARN)
	if err != nil {
		zap.L().Warn("waf: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteWebACL",
		EventName:    metadata.eventName,
		ResourceID:   parsedARN.String(),
		ResourceType: schemas.WafWebAclSchema,
	}}
}
