package api

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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"

	lpmodels "github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

func addGlueTables(input *models.PutIntegrationInput) error {
	for _, logType := range input.LogTypes {
		err := addGlueTablesForLogType(*logType)
		if err != nil {
			return err
		}
	}

	// update the views with the new tables
	err := athenaviews.CreateOrReplaceViews(glueClient, athenaClient)
	if err != nil {
		return err
	}

	return nil
}

func addGlueTablesForLogType(logType string) error {
	logTable := registry.AvailableParsers().LookupParser(logType).GlueTableMetadata // get the table description

	_, err := logTable.CreateTable(glueClient, env.ProcessedDataBucket)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); (ok && awsErr.Code() != glue.ErrCodeAlreadyExistsException) || !ok {
			return errors.Wrapf(err, "could not create glue log table for %s", logType)
		}
	}

	// the corresponding rule table shares the same structure as the log table + some columns
	ruleTable := awsglue.NewGlueTableMetadata(
		lpmodels.RuleData, logTable.LogType(), logTable.Description(), awsglue.GlueTableHourly, logTable.EventStruct())
	_, err = ruleTable.CreateTable(glueClient, env.ProcessedDataBucket)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); (ok && awsErr.Code() != glue.ErrCodeAlreadyExistsException) || !ok {
			return errors.Wrapf(err, "could not create glue rule table for %s", logType)
		}
	}

	return nil
}
