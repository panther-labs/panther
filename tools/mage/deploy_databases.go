package mage

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
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/tools/athenaviews"
)

const (
	databasesStack    = "panther-app-databases"
	databasesTemplate = "deployments/databases.yml"
)

func deployDatabases(awsSession *session.Session, bucket string, backendOutputs map[string]string) {
	if backendOutputs["ProcessedDataBucket"] == "" {
		logger.Fatal("ProcessedDataBucket is not set in stack output")
	}
	if backendOutputs["AthenaResultsBucket"] == "" {
		logger.Fatal("AthenaResultsBucket is not set in stack output")
	}

	if err := generateGlueTables(); err != nil {
		logger.Fatal(err)
	}

	params := map[string]string{
		"ProcessedDataBucket": backendOutputs["ProcessedDataBucket"],
	}
	deployTemplate(awsSession, databasesTemplate, bucket, databasesStack, params)

	// Athena views are created via API call because CF is not well supported. Workgroup "primary" is default.
	workgroup, bucket := "primary", backendOutputs["AthenaResultsBucket"]
	if err := awsathena.WorkgroupAssociateS3(awsSession, workgroup, bucket); err != nil {
		logger.Fatalf("failed to associate %s Athena workgroup with %s bucket: %v", workgroup, bucket, err)
	}
	if err := athenaviews.CreateOrReplaceViews(bucket); err != nil {
		logger.Fatalf("failed to create/replace athena views for %s bucket: %v", bucket, err)
	}
}
