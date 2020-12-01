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

func classifyRDS(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	if strings.HasSuffix(metadata.eventName, "DBCluster") || // 9 APIs
		strings.HasSuffix(metadata.eventName, "ParameterGroup") || // 10 APIs
		strings.HasSuffix(metadata.eventName, "Subscription") || // 5 APIs
		strings.HasSuffix(metadata.eventName, "OptionGroup") || // 4 APIs
		strings.HasSuffix(metadata.eventName, "GlobalCluster") || // 4 APIs
		strings.HasSuffix(metadata.eventName, "ClusterSnapshot") { // 3 APIs

		zap.L().Debug("rds: ignoring event", zap.String("eventName", metadata.eventName))
		return nil
	}

	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonrds.html
	rdsARN := arn.ARN{
		Partition: "aws",
		Service:   "rds",
		Region:    metadata.region,
		AccountID: metadata.accountID,
		Resource:  "db:",
	}
	switch metadata.eventName {
	case "AddRoleToDBInstance", "CreateDBInstance", "CreateDBSnapshot", "DeleteDBInstance", "ModifyDBInstance",
		"PromoteReadReplica", "RebootDBInstance", "RemoveRoleFromDBInstance", "RestoreDBInstanceFromDBSnapshot",
		"RestoreDBInstanceFromS3", "StartDBInstance", "StopDBInstance":
		instanceID := detail.Get("requestParameters.dBInstanceIdentifier")
		if !instanceID.Exists() {
			zap.L().Info("unable to extract dBInstanceIdentifier from event", zap.Any("requestParameters", detail.Get("requestParameters").Raw))
			return nil
		}
		rdsARN.Resource += instanceID.Str
	case "AddTagsToResource", "RemoveTagsFromResource":
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceName").Str)
		if err != nil {
			zap.L().Error("rds: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
			return nil
		}
		if strings.HasPrefix(resourceARN.Resource, "db:") {
			rdsARN = resourceARN
			break
		}
		return nil
	case "ApplyPendingMaintenanceAction":
		// Similar to AddTagsToResource except that it uses a different parameter name
		resourceARN, err := arn.Parse(detail.Get("requestParameters.resourceIdentifier").Str)
		if err != nil {
			zap.L().Error("rds: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
			return nil
		}
		if strings.HasPrefix(resourceARN.Resource, "db:") {
			rdsARN = resourceARN
			break
		}
		return nil
	case "CopyDBSnapshot", "DeleteDBSnapshot", "ModifyDBSnapshot":
		// Similar to the common case, but looking at the responseElements
		instanceID := detail.Get("responseElements.dBSnapshot.dBInstanceIdentifier")
		// This can happen when a snapshot for a DB that no longer exists is changed
		if !instanceID.Exists() {
			zap.L().Info("unable to extract dBInstanceIdentifier from event", zap.Any("responseElements", detail.Get("responseElements").Raw))
			return nil
		}
		rdsARN.Resource += instanceID.Str
	case "CreateDBInstanceReadReplica":
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.dBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}, {
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.sourcedBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}}
	case "CreateDBSubnetGroup", "ModifyDBSubnetGroup":
		// If we create an RDS DBSubnetGroup resource, we will need to update this to scan that as well
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID: arn.ARN{
				Partition: "aws",
				Service:   "ec2",
				Region:    metadata.region,
				AccountID: metadata.accountID,
				Resource:  "vpc/" + detail.Get("responseElements.dBSubnetGroup.vpcId").Str,
			}.String(),
			ResourceType: schemas.Ec2VpcSchema,
		}}
	case "DeleteDBInstanceAutomatedBackup":
		instanceID := detail.Get("responseElements.dBInstanceAutomatedBackup.dBInstanceIdentifier")
		if !instanceID.Exists() {
			zap.L().Info("unable to extract dBInstanceIdentifier from event", zap.Any("responseElements", detail.Get("responseElements").Raw))
			return nil
		}
		rdsARN.Resource += instanceID.Str
	case "ModifyDBSnapshotAttribute":
		// Since we can't tie this back to the corresponding RDS Instance with just the context of
		// this event, we send the panther-snapshot-poller the ID of the db snapshot and let the
		// poller make the appropriate API call to tie this snapshot back to a particular instance.
		snapshotID := detail.Get("requestParameters.dBSnapshotIdentifier").Str
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID: arn.ARN{
				Partition: "aws",
				Service:   "rds",
				Region:    metadata.region,
				AccountID: metadata.accountID,
				Resource:  "snapshot:" + snapshotID,
			}.String(),
			ResourceType: schemas.RDSInstanceSchema,
		}}
	case "RestoreDBInstanceToPointInTime":
		// Similar to CreateDBInstanceReadReplica but with different field names
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.targetdBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}, {
			AwsAccountID: metadata.accountID,
			EventName:    metadata.eventName,
			ResourceID:   rdsARN.String() + detail.Get("requestParameters.sourcedBInstanceIdentifier").Str,
			ResourceType: schemas.RDSInstanceSchema,
		}}
	default:
		zap.L().Info("rds: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       metadata.eventName == "DeleteDBInstance",
		EventName:    metadata.eventName,
		ResourceID:   rdsARN.String(),
		ResourceType: schemas.RDSInstanceSchema,
	}}
}
