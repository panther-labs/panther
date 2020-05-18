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

func classifyRedshift(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonredshift.html
	redshiftARN := arn.ARN{
		Partition: "aws",
		Service:   "redshift",
		Region:    metadata.region,
		AccountID: metadata.accountID,
		Resource:  "cluster:",
	}

	switch metadata.eventName {
	case "AuthorizeSnapshotAccess", "CopyClusterSnapshot", "DeleteClusterSnapshot", "ModifyClusterSnapshot", "RevokeSnapshotAccess":
		// If we add a cluster snapshot resource, this should be updated to include that as well
		redshiftARN.Resource += detail.Get("responseElements.snapshot.clusterIdentifier").Str
	case "AuthorizeClusterSecurityGroupIngress", "BatchDeleteClusterSnapshots", "BatchModifyClusterSnapshots", "CreateSnapshotCopyGrant":
		// We don't have a good way to tie this back to a single cluster, so do a region wide scan
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: schemas.RedshiftClusterSchema,
		}}
	case "CancelResize", "CreateCluster", "CreateClusterSnapshot", "DeleteCluster", "DisableLogging", "DisableSnapshotCopy",
		"EnableLogging", "EnableSnapshotCopy", "ModifyCluster", "ModifyClusterDbRevision", "ModifyClusterIamRoles",
		"ModifyClusterMaintenance", "ModifyClusterSnapshotSchedule", "ModifySnapshotCopyRetentionPeriod", "RebootCluster",
		"ResizeCluster", "RestoreFromClusterSnapshot", "ClusterIdentifier", "RotateEncryptionKey":
		redshiftARN.Resource += detail.Get("requestParameters.clusterIdentifier").Str
	case "CreateClusterSubnetGroup":
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID: arn.ARN{
				Partition: "aws",
				Service:   "ec2",
				Region:    metadata.region,
				AccountID: metadata.accountID,
				Resource:  "vpc/" + detail.Get("responseElements.clusterSubnetGroup.vpcId").Str,
			}.String(),
			ResourceType: schemas.Ec2VpcSchema,
		}}
	case "CreateEventSubscription", "ModifyEventSubscription":
		// Optional parameters
		resourceType := detail.Get("requestParameters.sourceType").Str
		resourceIDs := detail.Get("requestParameters.sourceIds").Array()

		// Handle the case where this is explicitly for non-cluster resources
		if resourceType != "cluster" && resourceType != "" {
			return nil
		}

		// Handle the cases where this is for all resources, or all cluster resources
		if resourceType == "" || len(resourceIDs) == 0 {
			// The documentation says this means it applies to every Redshift resource in the
			// account, but I suspect it may be regional. Further testing required.
			return []*resourceChange{{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceType: schemas.RedshiftClusterSchema,
			}}
		}

		// Handle the case where this is for an explicit list of resources
		changes := make([]*resourceChange, len(resourceIDs))
		for i, resourceID := range resourceIDs {
			changes[i] = &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   redshiftARN.String() + resourceID.Str,
				ResourceType: schemas.RedshiftClusterSchema,
			}
		}
		return changes
	case "CreateSnapshotSchedule", "ModifySnapshotSchedule":
		clusters := detail.Get("responseElements.associatedClusters").Array()
		changes := make([]*resourceChange, len(clusters))
		for i, cluster := range clusters {
			changes[i] = &resourceChange{
				AwsAccountID: metadata.accountID,
				EventName:    metadata.eventName,
				ResourceID:   redshiftARN.String() + cluster.Get("clusterIdentifier").Str,
				ResourceType: schemas.RedshiftClusterSchema,
			}
		}
		return changes
	case "CreateTags", "DeleteTags":
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceName").Str)
		if err != nil {
			zap.L().Error("redshift: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
			return nil
		}
		if strings.HasPrefix(resourceARN.Resource, "cluster:") {
			redshiftARN = resourceARN
			break
		}
		return nil
	default:
		zap.L().Info("redshift: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteCluster",
		EventName:    metadata.eventName,
		ResourceID:   redshiftARN.String(),
		ResourceType: schemas.RedshiftClusterSchema,
	}}
}
