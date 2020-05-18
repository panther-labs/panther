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
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyECS(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonelasticcontainerservice.html
	var clusterARN string
	switch metadata.eventName {
	case "CreateTaskSet", "DeleteCluster", "DeleteTaskSet", "UpdateServicePrimaryTaskSet", "UpdateTaskSet":
		clusterARN = detail.Get("requestParameters.cluster").Str
	case "CreateService", "DeleteAttributes", "DeleteService", "DeregisterContainerInstance", "PutAttributes",
		"RegisterContainerInstance", "RunTask", "StartTask", "StopTask", "SubmitAttachmentStateChanges", "SubmitContainerStateChange",
		"SubmitTaskStateChange", "UpdateContainerInstancesState", "UpdateService":
		// These API calls interpret a missing cluster value to mean the default cluster.
		//
		// Sadly we can't differentiate between a failed extraction (rare), and a request to modify the
		// default cluster. We will just default to scanning the default cluster, which is the cluster
		// with the name "default".
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
				zap.String("eventName", metadata.eventName),
				zap.String("resource ARN", clusterARN),
				zap.Error(errors.WithStack(err)),
			)
			return nil
		}
		if strings.HasPrefix(parsed.Resource, "cluster") {
			break
		}

		// If it wasn't a cluster, we have to scan the whole region.
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: schemas.EcsClusterSchema,
		}}
	default:
		zap.L().Info("ecs: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	// If clusterARN is empty, we failed to parse the ARN out at some point despite trying
	if clusterARN == "" {
		zap.L().Error("ecs: known event name, but still failed to parse clusterARN", zap.String("eventName", metadata.eventName))
		return nil
	}

	// All ECS Cluster API calls can be made with the full ARN or just the cluster name as the 'cluster' parameter.
	// If we received just the cluster name we can construct the full ARN, which we do in order to reduce
	// complexity for the snapshot poller.
	if _, err := arn.Parse(clusterARN); err != nil {
		// A short cluster name was provided, construct the full ARN
		clusterARN = arn.ARN{
			Partition: "aws",
			Service:   "ecs",
			Region:    metadata.region,
			AccountID: metadata.accountID,
			Resource:  "cluster/" + clusterARN,
		}.String()
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteCluster",
		EventName:    metadata.eventName,
		ResourceID:   clusterARN,
		ResourceType: schemas.EcsClusterSchema,
	}}
}
