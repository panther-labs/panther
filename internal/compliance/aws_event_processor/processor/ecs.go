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

func classifyECS(detail gjson.Result, accountID string) []*resourceChange {
	eventName := detail.Get("eventName").Str

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awscertificatemanager.html
	if eventName == "READONLY" {
		zap.L().Debug("ecs: ignoring event", zap.String("eventName", eventName))
		return nil
	}

	var clusterARN string
	switch eventName {
	case "CreateTaskSet", "DeleteCluster", "DeleteTaskSet", "UpdateServicePrimaryTaskSet", "UpdateTaskSet":
		clusterARN = detail.Get("requestParameters.cluster").Str
	case "CreateService", "DeleteAttributes", "DeleteService", "DeregisterContainerInstance", "PutAttributes",
		"RegisterContainerInstance", "RunTask", "StartTask", "StopTask", "SubmitAttachmentStateChanges", "SubmitContainerStateChange",
		"SubmitTaskStateChange", "UpdateContainerInstancesState", "UpdateService":
		// These API calls understand an absent cluster value to mean the default cluster.
		//
		// Sadly we can't differentiate between a failed extraction (rare), and a request to modify the
		// default cluster. We will just default to scanning the default cluster.
		clusterARN = detail.Get("requestParameters.cluster").Str
		if clusterARN == "" {
			clusterARN = "default"
		}
	case "CreateCluster":
		clusterARN = detail.Get("responseElements.cluster.clusterArn").Str
	case "TagResource", "UntagResource":
		// This is the same child resource issue we've encountered many times (see EC2 for an example)
		// Since we don't know who the parent resource is that changed, we have to scan all resources

		// In the case of clusters at least we can continue
		clusterARN = detail.Get("requestParameters.resourceArn").Str
		parsed, err := arn.Parse(clusterARN)
		if err != nil {
			zap.L().Error(
				"ecs: unable to parse resource ARN",
				zap.String("eventName", eventName),
				zap.String("resource ARN", clusterARN),
			)
			return nil
		}
		if strings.HasPrefix("cluster", parsed.Resource) {
			break
		}

		// It wasn't a cluster, so we have to scan the whole region.
		return []*resourceChange{{
			AwsAccountID: accountID,
			Delete:       false,
			EventName:    eventName,
			Region:       detail.Get("awsRegion").Str,
			ResourceType: schemas.EcsClusterSchema,
		}}
	case "DeleteAccountSetting", "DeregisterTaskDefinition", "PutAccountSetting", "PutAccountSettingDefault",
		"RegisterTaskDefinition", "UpdateContainerAgent":
		// Nothing to do here
		//
		// If we add an ECS account wide resource or an ECS TaskDefinition resource we can use these
		return nil
	default:
		zap.L().Warn("ecs: encountered unknown event name", zap.String("eventName", eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: accountID,
		Delete:       eventName == "DeleteCluster",
		EventName:    eventName,
		ResourceID:   clusterARN,
		ResourceType: schemas.EcsClusterSchema,
	}}
}
