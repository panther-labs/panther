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
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

const (
	presignedLinkTimeLimit = time.Minute
)

func (api API) GetQueryResultsLink(input *models.GetQueryResultsLinkInput) (*models.GetQueryResultsLinkOutput, error) {
	var output models.GetQueryResultsLinkOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}

		// allows tracing queries
		zap.L().Info("GetQueryResultsLink",
			zap.String("queryId", input.QueryID),
			zap.Error(err))
	}()

	executionStatus, err := awsathena.Status(athenaClient, input.QueryID)
	if err != nil {
		return &output, err
	}

	output.Status = getQueryStatus(executionStatus)

	if output.Status != models.QuerySucceeded {
		output.SQLError = "results not available"
		return &output, nil
	}

	s3path := *executionStatus.QueryExecution.ResultConfiguration.OutputLocation

	parsedPath, err := url.Parse(s3path)
	if err != nil {
		err = errors.Errorf("bad s3 url: %s,", err)
		return &output, err
	}

	if parsedPath.Scheme != "s3" {
		err = errors.Errorf("not s3 protocol (expecting s3://): %s,", s3path)
		return &output, err
	}

	bucket := parsedPath.Host
	if bucket == "" {
		err = errors.Errorf("missing bucket: %s,", s3path)
		return &output, err
	}
	var key string
	if len(parsedPath.Path) > 0 {
		key = parsedPath.Path[1:] // remove leading '/'
	}

	req, _ := s3Client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	output.PresignedLink, err = req.Presign(presignedLinkTimeLimit)
	if err != nil {
		err = errors.Errorf("failed to sign: %s,", s3path)
		return &output, err
	}
	return &output, nil
}
