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
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/pkg/awsutils"
)

const (
	CloudSecurityDatabase            = "panther_cloudsecurity"
	CloudSecurityDatabaseDescription = "Hold tables related to Panther cloud security scanning"

	ResourcesTable            = "resources"
	ResourcesTableDescription = "The resources discovered by Panther scanning"

	ComplianceTable            = "compliance"
	ComplianceTableDescription = "The policies and statues from Panther scanning"
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
	tableInput := &glue.TableInput{
		Name:        aws.String(ResourcesTable),
		Description: aws.String(ResourcesTableDescription),
		Parameters: map[string]*string{
			"classification": aws.String("dynamodb"),
		},
		StorageDescriptor: &glue.StorageDescriptor{ // configure as JSON
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

	_, err := glueClient.CreateTable(createTableInput)
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
	tableInput := &glue.TableInput{
		Name:        aws.String(ComplianceTable),
		Description: aws.String(ComplianceTableDescription),
		Parameters: map[string]*string{
			"classification": aws.String("dynamodb"),
		},
		StorageDescriptor: &glue.StorageDescriptor{ // configure as JSON
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

	_, err := glueClient.CreateTable(createTableInput)
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
