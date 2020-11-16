package handlers

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
	"bytes"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

// Delete one or more policies from S3.
//
// It is the caller's responsibility to ensure there are not more than 1000 policies in the request.
func s3BatchDelete(input *models.DeletePoliciesInput) error {
	objects := make([]*s3.ObjectIdentifier, len(input.Entries))
	for i, entry := range input.Entries {
		objects[i] = &s3.ObjectIdentifier{Key: aws.String(entry.ID)}
	}

	_, err := s3Client.DeleteObjects(&s3.DeleteObjectsInput{
		Bucket: &env.Bucket,
		Delete: &s3.Delete{Objects: objects},
	})
	if err != nil {
		zap.L().Error("s3Client.DeleteObjects failed", zap.Error(err))
		return err
	}

	return nil
}

// Load a policy from the S3 bucket.
func s3Get(policyID, versionID string) (*tableItem, error) {
	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket:    &env.Bucket,
		Key:       &policyID,
		VersionId: &versionID,
	})
	if err != nil {
		zap.L().Error("s3Client.GetObject failed", zap.Error(err))
		return nil, err
	}

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		zap.L().Error("ioutil.ReadAll failed", zap.Error(err))
		return nil, err
	}

	var policy tableItem
	if err = jsoniter.Unmarshal(body, &policy); err != nil {
		zap.L().Error("policy unmarshal failed", zap.Error(err))
		return nil, err
	}
	policy.VersionID = versionID

	return &policy, nil
}

// Upload a policy to S3 and set the VersionID accordingly.
func s3Upload(policy *tableItem) error {
	// We don't need to store auto-generated fields - keep the S3 copy clean and minimal
	policy.LowerDisplayName = ""
	policy.LowerID = ""
	policy.LowerTags = nil
	policy.VersionID = ""

	body, err := jsoniter.Marshal(policy)
	if err != nil {
		zap.L().Error("policy marshal failed", zap.Error(err))
		return err
	}

	result, err := s3Client.PutObject(&s3.PutObjectInput{
		Body:   bytes.NewReader(body),
		Bucket: &env.Bucket,
		Key:    &policy.ID,
	})
	if err != nil {
		zap.L().Error("s3Client.PutObject failed", zap.Error(err))
		return err
	}

	policy.VersionID = *result.VersionId
	return nil
}
