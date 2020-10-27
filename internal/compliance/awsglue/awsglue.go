package awsglue

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/awsutils"
)

const (
	CloudSecurityDatabase            = "panther_cloudsecurity"
	CloudSecurityDatabaseDescription = "Hold tables related to Panther cloud security scanning"

	// https://github.com/awslabs/aws-athena-query-federation/tree/master/athena-dynamodb

	// FIXME: Update the description when the DDB connector is GA
	ResourcesTableDDB         = "panther-resources"
	ResourcesTable            = "resources"
	ResourcesTableDescription = "The resources discovered by Panther scanning (Note: The Athena federated query feature is available in preview in the US East (N. Virginia), Asia Pacific (Mumbai), Europe (Ireland), and US West (Oregon) Regions.)" // nolint:lll

	ComplianceTableDDB         = "panther-compliance"
	ComplianceTable            = "compliance"
	ComplianceTableDescription = "The policies and statuses from Panther scanning (Note: The Athena federated query feature is available in preview in the US East (N. Virginia), Asia Pacific (Mumbai), Europe (Ireland), and US West (Oregon) Regions.)" // nolint:lll
)

var (
	// FIXME: Remove when the DDB connector is GA
	// Available Regions – The Athena federated query feature is available in preview in the US East (N. Virginia),
	//                     Asia Pacific (Mumbai), Europe (Ireland), and US West (Oregon) Regions.
	anthenaDDBConnectorRegions = map[string]struct{}{
		"us-east-1":  {},
		"ap-south-1": {},
		"eu-west-1":  {},
		"us-west-2":  {},
	}
)

func CreateOrUpdateCloudSecurityDatabase(glueClient glueiface.GlueAPI) error {
	dbInput := &glue.DatabaseInput{
		Description: aws.String(CloudSecurityDatabaseDescription),
		LocationUri: aws.String("dynamo-db-flag"),
		Name:        aws.String(CloudSecurityDatabase),
	}

	_, err := glueClient.CreateDatabase(&glue.CreateDatabaseInput{
		CatalogId:     nil,
		DatabaseInput: dbInput,
	})
	if awsutils.IsAnyError(err, glue.ErrCodeAlreadyExistsException) {
		return nil // nothing to do
	}
	return errors.Wrap(err, "could not create cloud security database")
}

func CreateOrUpdateResourcesTable(glueClient glueiface.GlueAPI, locationARN string) error {
	// FIXME: Remove when the DDB connector is GA
	parsedARN, err := arn.Parse(locationARN)
	if err != nil {
		return err
	}
	if _, found := anthenaDDBConnectorRegions[parsedARN.Region]; !found {
		return nil // not supported
	}

	tableInput := &glue.TableInput{
		Name:        aws.String(ResourcesTable),
		Description: aws.String(ResourcesTableDescription),
		Parameters: map[string]*string{
			// per https://github.com/awslabs/aws-athena-query-federation/tree/master/athena-dynamodb
			"classification": aws.String("dynamodb"),
			"sourceTable":    aws.String(ResourcesTableDDB),
			// for attrs with upper case
			"columnMapping": aws.String(`expiresat=expiresAt,lastmodified=lastModified,integrationtype=integrationType`),
		},
		StorageDescriptor: &glue.StorageDescriptor{
			Location: &locationARN,

			// FIXME: add descriptions to each field
			Columns: []*glue.Column{
				{
					Name:    aws.String("integrationtype"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("deleted"),
					Type:    aws.String("boolean"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("integrationid"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("attributes"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("lowerid"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("lastmodified"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("id"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("type"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("expiresat"),
					Type:    aws.String("bigint"),
					Comment: aws.String(""),
				},
			},
		},
		TableType: aws.String("EXTERNAL_TABLE"),
	}

	createTableInput := &glue.CreateTableInput{
		DatabaseName: aws.String(CloudSecurityDatabase),
		TableInput:   tableInput,
	}

	_, err = glueClient.CreateTable(createTableInput)
	if err != nil {
		if awsutils.IsAnyError(err, glue.ErrCodeAlreadyExistsException) {
			// need to do an update
			updateTableInput := &glue.UpdateTableInput{
				DatabaseName: aws.String(CloudSecurityDatabase),
				TableInput:   tableInput,
			}
			_, err := glueClient.UpdateTable(updateTableInput)
			return errors.Wrapf(err, "failed to update table %s.%s", CloudSecurityDatabase, ResourcesTable)
		}
		return errors.Wrapf(err, "failed to create table %s.%s", CloudSecurityDatabase, ResourcesTable)
	}

	return nil
}

func CreateOrUpdateComplianceTable(glueClient glueiface.GlueAPI, locationARN string) error {
	// FIXME: Remove when the DDB connector is GA
	parsedARN, err := arn.Parse(locationARN)
	if err != nil {
		return err
	}
	if _, found := anthenaDDBConnectorRegions[parsedARN.Region]; !found {
		return nil // not supported
	}

	tableInput := &glue.TableInput{
		Name:        aws.String(ComplianceTable),
		Description: aws.String(ComplianceTableDescription),
		Parameters: map[string]*string{
			// per https://github.com/awslabs/aws-athena-query-federation/tree/master/athena-dynamodb
			"classification": aws.String("dynamodb"),
			"sourceTable":    aws.String(ComplianceTableDDB),
			// for attrs with upper case
			"columnMapping": aws.String(`errormessage=errorMessage,expiresat=expiresAt,lastupdated=lastUpdated,resourcetype=resourceType`),
		},
		StorageDescriptor: &glue.StorageDescriptor{
			Location: &locationARN,

			// FIXME: add descriptions to each field
			Columns: []*glue.Column{
				{
					Name:    aws.String("lastupdated"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("resourceid"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("policyseverity"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("policyid"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("integrationid"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("suppressed"),
					Type:    aws.String("boolean"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("expiresat"),
					Type:    aws.String("bigint"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("resourcetype"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("status"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
				{
					Name:    aws.String("errormessage"),
					Type:    aws.String("string"),
					Comment: aws.String(""),
				},
			},
		},
		TableType: aws.String("EXTERNAL_TABLE"),
	}

	createTableInput := &glue.CreateTableInput{
		DatabaseName: aws.String(CloudSecurityDatabase),
		TableInput:   tableInput,
	}

	_, err = glueClient.CreateTable(createTableInput)
	if err != nil {
		if awsutils.IsAnyError(err, glue.ErrCodeAlreadyExistsException) {
			// need to do an update
			updateTableInput := &glue.UpdateTableInput{
				DatabaseName: aws.String(CloudSecurityDatabase),
				TableInput:   tableInput,
			}
			_, err := glueClient.UpdateTable(updateTableInput)
			return errors.Wrapf(err, "failed to update table %s.%s", CloudSecurityDatabase, ResourcesTable)
		}
		return errors.Wrapf(err, "failed to create table %s.%s", CloudSecurityDatabase, ResourcesTable)
	}

	return nil
}
