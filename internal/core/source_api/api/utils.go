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
	"strings"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

func integrationToItem(input *models.SourceIntegration) *ddb.Integration {
	// Initializing the fields common for all integration types
	item := &ddb.Integration{
		CreatedAtTime:    input.CreatedAtTime,
		CreatedBy:        input.CreatedBy,
		IntegrationID:    input.IntegrationID,
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
		PantherVersion:   input.PantherVersion,
	}
	item.LastEventReceived = input.LastEventReceived

	switch input.IntegrationType {
	case models.IntegrationTypeAWS3:
		item.AWSAccountID = input.AWSAccountID
		item.S3Bucket = input.S3Bucket
		item.S3PrefixLogTypes = input.S3PrefixLogTypes
		item.KmsKey = input.KmsKey
		item.StackName = input.StackName
		item.LogProcessingRole = generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
		item.ManagedBucketNotifications = input.ManagedBucketNotifications
	case models.IntegrationTypeAWSScan:
		item.AWSAccountID = input.AWSAccountID
		item.CWEEnabled = input.CWEEnabled
		item.EventStatus = input.EventStatus
		item.LastScanErrorMessage = input.LastScanErrorMessage
		item.LastScanEndTime = input.LastScanEndTime
		item.LastScanStartTime = input.LastScanStartTime
		item.LogProcessingRole = input.LogProcessingRole
		item.RemediationEnabled = input.RemediationEnabled
		item.S3Bucket = input.S3Bucket
		item.ScanIntervalMins = input.ScanIntervalMins
		item.ScanStatus = input.ScanStatus
		item.StackName = input.StackName
		item.Enabled = input.Enabled
		item.RegionIgnoreList = input.RegionIgnoreList
		item.ResourceTypeIgnoreList = input.ResourceTypeIgnoreList
		item.ResourceRegexIgnoreList = input.ResourceRegexIgnoreList
	case models.IntegrationTypeSqs:
		item.SqsConfig = &ddb.SqsConfig{
			QueueURL:             input.SqsConfig.QueueURL,
			S3Bucket:             input.SqsConfig.S3Bucket,
			LogProcessingRole:    input.SqsConfig.LogProcessingRole,
			LogTypes:             input.SqsConfig.LogTypes,
			AllowedPrincipalArns: input.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    input.SqsConfig.AllowedSourceArns,
		}
	}
	return item
}

// reduceNoPrefixStrings reduces a list of strings to a list where no string is a prefix of another.
// e.g [pref, prefi, prefix, abc] -> [pref, abc]
func reduceNoPrefixStrings(strs []string) (reduced []string) {
	uniques := make(map[string]struct{})
	for i := 0; i < len(strs); i++ {
		smallestPrefix := strs[i]
		for j := 0; j < len(strs); j++ {
			if strings.HasPrefix(smallestPrefix, strs[j]) {
				smallestPrefix = strs[j]
			}
		}
		uniques[smallestPrefix] = struct{}{}
	}
	for k := range uniques {
		reduced = append(reduced, k)
	}
	return
}
