package resources

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
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"

	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/awsutils"
)

const (
	PantherWorkGroup          = previewWorkgroup
	PantherDynamodbDataSource = "ddb" // must match the CF tha creates the application

	// FIXME: remove when DDB connector is GA https://docs.aws.amazon.com/athena/latest/ug/connect-to-a-data-source.html
	// Available Regions – The Athena federated query feature is available in preview in the US East (N. Virginia),
	//                     Asia Pacific (Mumbai), Europe (Ireland), and US West (Oregon) Regions.
	previewWorkgroup = "AmazonAthenaPreviewFunctionality"
	workgroup        = "primary" // workgroup "primary" is default and always present
)

type AthenaInitProperties struct {
	LambdaARN           string `validate:"required"`
	AthenaResultsBucket string `validate:"required"`
}

func customAthenaInit(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:athena:init"
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props AthenaInitProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		// FIXME: remove this when the DDB connector is GA
		athenaClient := athena.New(awsSession)
		previewWorkGroupInput := &athena.CreateWorkGroupInput{
			Name: aws.String(previewWorkgroup),
			Configuration: &athena.WorkGroupConfiguration{
				ResultConfiguration: &athena.ResultConfiguration{
					OutputLocation: aws.String("s3://" + props.AthenaResultsBucket + "/preview"),
				},
			},
		}
		if _, err := athenaClient.CreateWorkGroup(previewWorkGroupInput); err != nil {
			// InvalidRequestException happens when it already exists
			if awsutils.IsAnyError(err, "InvalidRequestException") {
				if err := awsathena.WorkgroupAssociateS3(awsSession, previewWorkgroup, props.AthenaResultsBucket); err != nil {
					return resourceID, nil, fmt.Errorf("failed to associate %s Athena workgroup with %s bucket: %v",
						previewWorkgroup, props.AthenaResultsBucket, err)
				}
			} else {
				return resourceID, nil, fmt.Errorf("failed to create %s Athena workgroup with %s bucket: %v",
					previewWorkgroup, props.AthenaResultsBucket, err)
			}
		}

		if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, props.AthenaResultsBucket); err != nil {
			return resourceID, nil, fmt.Errorf("failed to associate %s Athena workgroup with %s bucket: %v",
				workgroup, props.AthenaResultsBucket, err)
		}

		/*
			// this binds the lambda created by the serverless app to Athena for the ddb connector
			// https://docs.aws.amazon.com/athena/latest/ug/athena-prebuilt-data-connectors-dynamodb.html
			catalogName := PantherDynamodbDataSource
			ddbCreateCatalogInput := &athena.CreateDataCatalogInput{
				Name: &catalogName,
				Type: aws.String(athena.DataCatalogTypeLambda),
				Parameters: map[string]*string{
					"function": &props.LambdaARN,
				},
			}
			if _, err := athenaClient.CreateDataCatalog(ddbCreateCatalogInput); err != nil &&
				!awsutils.IsAnyError(err, "InvalidRequestException") { // InvalidRequestException happens when it already exists

				return resourceID, nil, fmt.Errorf("failed to create %s Athena catalog with %s lambda: %v",
					catalogName, props.LambdaARN, err)
			}
		*/

		return resourceID, nil, nil

	default: // ignore deletes
		return event.PhysicalResourceID, nil, nil
	}
}
