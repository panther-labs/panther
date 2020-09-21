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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

func classifyCloudFormation(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awscloudformation.html
	stackARN := arn.ARN{
		Partition: "aws",
		Service:   "cloudformation",
		Region:    metadata.region,
		AccountID: metadata.accountID,
		Resource:  "stack/",
	}

	switch metadata.eventName {
	case "CancelUpdateStack", "CreateChangeSet", "ContinueUpdateRollback", "DeleteStack", "SetStackPolicy", "UpdateStack", "ExecuteChangeSet":

		// stackName can either be the stack name or the stack ARN
		stackName := detail.Get("requestParameters.stackName").Str
		if stackName == "" {
			zap.L().Error("cloudformation: unable to process known event", zap.String("eventName", metadata.eventName))
			return nil
		}

		// Handle case where stackName is an ARN
		fullARN, err := arn.Parse(stackName)
		if err == nil {
			stackARN = fullARN
			break
		}

		// Handle case where stackName is the stack name.
		//
		// Note that this is technically an incorrect resourceID, as it is missing the additional
		// identifiers portion of the ARN (if any exist). That is ok for us as of now because the
		// cloudformation resource poller in the SnapshotPoller will just extract the name
		// and handle it appropriately.
		stackARN.Resource += stackName
	case "CreateStack":
		// technically these could be handled by the above, but this has less wasted effort
		var err error
		stackARN, err = arn.Parse(detail.Get("responseElements.stackId").Str)
		if err != nil {
			zap.L().Error("cloudformation: error parsing ARN", zap.Error(err))
			return nil
		}
	case "UpdateTerminationProtection":
		// The UpdateTerminationProtection log in CloudTrail does not include the request parameters,
		// so we must perform a region wide scan, I suspect an AWS bug. Ticket opened with support.
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			Delete:       false,
			EventName:    metadata.eventName,
			Region:       metadata.region,
			ResourceType: schemas.CloudFormationStackSchema,
		}}
	case "CreateStackInstances", "DeleteStackInstances":
		// The documentation says one thing about what this API requires, but in practice I have not
		// observed those fields being present. In practice, I see virtually nothing useful submitted
		// with this API call. Kick off a full account CloudFormation scan. Case opened with support.
		// TODO: I believe every stack created by this also requires a CreateStack call, maybe we
		// ignore this for now? research required.
		return []*resourceChange{{
			AwsAccountID: metadata.accountID,
			Delete:       false,
			EventName:    metadata.eventName,
			ResourceType: schemas.CloudFormationStackSchema,
		}}
	default:
		zap.L().Info("cloudformation: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		// Give the stacks time to finish updating so the detect stack drift call doesn't get stuck
		// for as long. Measured in seconds.
		Delay:        120,
		Delete:       metadata.eventName == "DeleteStack",
		EventName:    metadata.eventName,
		ResourceID:   stackARN.String(),
		ResourceType: schemas.CloudFormationStackSchema,
	}}
}
