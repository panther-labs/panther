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
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

var lambdaNameRegex = regexp.MustCompile(`(arn:(aws[a-zA-Z-]*)?:lambda:)?([a-z]{2}(-gov)?-[a-z]+-\d{1}:)?(\d{12}:)?` +
	`(function:)?([a-zA-Z0-9-_]+)(:(\$LATEST|[a-zA-Z0-9-_]+))?`)

func classifyLambda(detail gjson.Result, metadata *CloudTrailMetadata) []*resourceChange {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_awslambda.html
	lambdaARN := arn.ARN{
		Partition: "aws",
		Service:   "lambda",
		Region:    metadata.region,
		AccountID: metadata.accountID,
		Resource:  "function:",
	}
	eventName := getLambdaBaseEventName(metadata.eventName)
	switch eventName {
	case "AddPermission",
		"CreateAlias",
		"CreateEventSourceMapping",
		"CreateFunction",
		"DeleteAlias",
		"DeleteFunction",
		"DeleteFunctionConcurrency",
		"PublishVersion",
		"PutFunctionConcurrency",
		"RemovePermission",
		"UpdateAlias",
		"UpdateEventSourceMapping",
		"UpdateFunctionCode",
		"UpdateFunctionConfiguration":
		functionName := detail.Get("requestParameters.functionName").Str
		// Lambda Fun! This will need to be updated once we support tracking multiple aliases.
		// Legal formats:
		// Function name - my-function (name-only), my-function:v1 (with alias).
		// Function ARN - arn:aws:lambda:us-west-2:123456789012:function:my-function.
		// Partial ARN - 123456789012:function:my-function.
		// Regex taken from lambda user documentation referenced above.
		lambdaARN.Resource += lambdaNameRegex.FindStringSubmatch(functionName)[7]
	case "DeleteEventSourceMapping":
		functionName := detail.Get("responseElements.functionArn").Str
		lambdaARN.Resource += lambdaNameRegex.FindStringSubmatch(functionName)[7]
	case "AddLayerVersionPermission",
		"DeleteLayerVersion",
		"PublishLayerVersion",
		"RemoveLayerVersionPermission":
		// Normally we would add these as ignored events in process.go to save time, but then we would not have the
		// special lambda event version suffix stripping logic applied which we need
		return nil
	case "TagResource",
		"UntagResource":
		var err error
		lambdaARN, err = arn.Parse(detail.Get("requestParameters.resource").Str)
		if err != nil {
			zap.L().Error("lambda: error parsing ARN", zap.String("eventName", metadata.eventName), zap.Error(err))
			return nil
		}
	default:
		zap.L().Info("lambda: encountered unknown event name", zap.String("eventName", metadata.eventName))
		return nil
	}

	return []*resourceChange{{
		AwsAccountID: metadata.accountID,
		Delete:       eventName == "DeleteFunction",
		EventName:    metadata.eventName,
		ResourceID:   lambdaARN.String(),
		ResourceType: schemas.LambdaFunctionSchema,
	}}
}

// lambda has a number of "sets" of versioned event names. We do not care about the specific versions so strip off.
var lambdaVersions = []string{
	"20181031",
	"20170331",
	"20170331v2",
	"20150331",
	"20150331v2",
}

func init() {
	sort.Sort(sort.Reverse(sort.StringSlice(lambdaVersions))) // sort desc
}

func getLambdaBaseEventName(eventName string) string {
	// this must be sorted desc (longest strings first, per run) to work properly!
	for _, version := range lambdaVersions {
		strippedEventName := strings.Replace(eventName, version, "", 1)
		if len(strippedEventName) < len(eventName) { // we can stop on first match
			return strippedEventName
		}
	}
	return eventName
}
