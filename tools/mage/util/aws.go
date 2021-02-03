package util

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
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var accountID string

// Returns the 12-digit account ID associated with the current session.
//
// The result will be cached for subsequent queries.
func AccountID(config aws.Config) string {
	if accountID == "" {
		identity, err := sts.NewFromConfig(config).GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
		if err != nil {
			log.Fatalf("failed to get caller identity: %v", err)
		}
		accountID = *identity.Account
	}

	return accountID
}

// The name of the bucket containing published Panther releases
func PublicAssetsBucket(region string) string {
	return "panther-community-" + region
}

// Returns ECR image repo uri
func EcrRepoURI(accountID, region, repoName string) string {
	return fmt.Sprintf("%s.dkr.ecr.%s.%s/%s", accountID, region, URLSuffix(region), repoName)
}

// Returns s3 URI ("s3://bucket/key")
func S3URI(bucket, key string) string {
	result := "s3://" + bucket
	if key != "" {
		result += "/" + key
	}
	return result
}

// Returns S3 URL using virtual addressing ("BUCKET.s3.REGION.SUFFIX/KEY")
func S3ObjectURL(region, bucket, key string) string {
	return fmt.Sprintf("https://%s.s3.%s.%s/%s", bucket, region, URLSuffix(region), key)
}

// Return the URL suffix for the partition associated with the given region.
func URLSuffix(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}
