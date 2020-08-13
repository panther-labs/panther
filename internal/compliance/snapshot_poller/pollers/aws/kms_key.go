package aws

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

const (
	customerKeyManager = "CUSTOMER"
)

// Set as variables to be overridden in testing
var (
	KmsClientFunc     = setupKmsClient
	defaultPolicyName = "default"
)

func setupKmsClient(sess *session.Session, cfg *aws.Config) interface{} {
	return kms.New(sess, cfg)
}

func getKMSClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (kmsiface.KMSAPI, error) {
	client, err := getClient(pollerResourceInput, KmsClientFunc, "kms", region)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	return client.(kmsiface.KMSAPI), nil
}

// PollKMSKey polls a single KMS Key resource
func PollKMSKey(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getKMSClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	keyID := strings.Replace(resourceARN.Resource, "key/", "", 1)
	key := &kms.KeyListEntry{
		KeyId:  aws.String(keyID),
		KeyArn: scanRequest.ResourceID,
	}

	snapshot := buildKmsKeySnapshot(client, key)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// listKeys returns a list of all keys in the account
func listKeys(kmsSvc kmsiface.KMSAPI, nextMarker *string) (keys []*kms.KeyListEntry, marker *string) {
	err := kmsSvc.ListKeysPages(
		&kms.ListKeysInput{
			Marker: nextMarker,
		},
		func(page *kms.ListKeysOutput, lastPage bool) bool {
			keys = append(keys, page.Keys...)
			if len(keys) >= defaultBatchSize {
				if !lastPage {
					marker = page.NextMarker
				}
				return false
			}
			return true
		},
	)
	if err != nil {
		utils.LogAWSError("KMS.ListKeysPages", err)
	}
	return
}

// getKeyRotationStatus returns the rotation status for a given KMS key
func getKeyRotationStatus(
	kmsSvc kmsiface.KMSAPI, keyID *string) (rotationEnabled *bool, err error) {

	out, err := kmsSvc.GetKeyRotationStatus(&kms.GetKeyRotationStatusInput{KeyId: keyID})
	if err != nil {
		return
	}

	rotationEnabled = out.KeyRotationEnabled
	return
}

// getKeyRotationStatus returns the rotation status for a given KMS key
func listResourceTags(kmsSvc kmsiface.KMSAPI, keyID *string) ([]*kms.Tag, error) {
	tags, err := kmsSvc.ListResourceTags(&kms.ListResourceTagsInput{KeyId: keyID})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AccessDeniedException" {
				zap.L().Info(
					"AccessDeniedException, additional permissions were not granted or key is in another account",
					zap.String("API", "KMS.ListResourceTags"),
					zap.String("key", *keyID))
				return nil, err
			}
		}
		utils.LogAWSError("KMS.ListResourceTags", err)
		return nil, err
	}

	return tags.Tags, err
}

// describeKey returns detailed key meta data for a given kms key
func describeKey(kmsSvc kmsiface.KMSAPI, keyID *string) (metadata *kms.KeyMetadata, err error) {
	out, err := kmsSvc.DescribeKey(&kms.DescribeKeyInput{KeyId: keyID})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AccessDeniedException" {
				zap.L().Info(
					"AccessDeniedException, additional permissions were not granted or key is in another account",
					zap.String("API", "KMS.DescribeKey"),
					zap.String("key", *keyID))
				return nil, err
			}
		}
		utils.LogAWSError("KMS.DescribeKey", err)
		return nil, err
	}

	metadata = out.KeyMetadata
	return
}

// getKeyPolicy returns the policy document for a given KMS key
func getKeyPolicy(kmsSvc kmsiface.KMSAPI, keyID *string) (*string, error) {
	out, err := kmsSvc.GetKeyPolicy(
		&kms.GetKeyPolicyInput{KeyId: keyID, PolicyName: &defaultPolicyName},
	)
	if err != nil {
		utils.LogAWSError("KMS.GetKeyPolicy", err)
		return nil, err
	}

	return out.Policy, err
}

// buildKmsKeySnapshot makes all the calls to build up a snapshot of a given KMS key
func buildKmsKeySnapshot(kmsSvc kmsiface.KMSAPI, key *kms.KeyListEntry) *awsmodels.KmsKey {
	if key == nil {
		return nil
	}
	metadata, err := describeKey(kmsSvc, key.KeyId)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == kms.ErrCodeNotFoundException {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *key.KeyId),
					zap.String("resourceType", awsmodels.KmsKeySchema))
				return nil
			}
		}
		utils.LogAWSError("KMS.DescribeKey", err)
		return nil
	}

	if metadata == nil {
		zap.L().Error("KMS key metadata is nil", zap.String("resource", *key.KeyId))
		return nil
	}

	kmsKey := &awsmodels.KmsKey{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   key.KeyArn,
			ResourceType: aws.String(awsmodels.KmsKeySchema),
			TimeCreated:  utils.DateTimeFormat(aws.TimeValue(metadata.CreationDate)),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN: key.KeyArn,
			ID:  key.KeyId,
		},
		CloudHsmClusterId: metadata.CloudHsmClusterId,
		CustomKeyStoreId:  metadata.CustomKeyStoreId,
		DeletionDate:      metadata.DeletionDate,
		Description:       metadata.Description,
		Enabled:           metadata.Enabled,
		ExpirationModel:   metadata.ExpirationModel,
		KeyManager:        metadata.KeyManager,
		KeyState:          metadata.KeyState,
		KeyUsage:          metadata.KeyUsage,
		Origin:            metadata.Origin,
		ValidTo:           metadata.ValidTo,
	}

	policy, err := getKeyPolicy(kmsSvc, key.KeyId)
	if err == nil {
		kmsKey.Policy = policy
	}

	tags, err := listResourceTags(kmsSvc, key.KeyId)
	if err == nil {
		kmsKey.Tags = utils.ParseTagSlice(tags)
	}

	// Check that the key was created by the customer's account and not AWS
	if *metadata.KeyManager == customerKeyManager {
		rotationStatus, err := getKeyRotationStatus(kmsSvc, key.KeyId)
		if err != nil {
			utils.LogAWSError("KMS.GetKeyRotationStatus", err)
		} else {
			kmsKey.KeyRotationEnabled = rotationStatus
		}
	}

	return kmsKey
}

// PollKmsKeys gathers information on each KMS key for an AWS account.
func PollKmsKeys(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting KMS Key resource poller")
	kmsKeySnapshots := make(map[string]*awsmodels.KmsKey)

	kmsSvc, err := getKMSClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all keys
	keys, marker := listKeys(kmsSvc, pollerInput.NextPageToken)
	if keys == nil {
		return nil, nil, nil
	}

	for _, key := range keys {
		kmsKeySnapshot := buildKmsKeySnapshot(kmsSvc, key)
		if kmsKeySnapshot == nil {
			continue
		}
		kmsKeySnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		kmsKeySnapshot.Region = pollerInput.Region

		if _, ok := kmsKeySnapshots[*kmsKeySnapshot.ARN]; !ok {
			kmsKeySnapshots[*kmsKeySnapshot.ARN] = kmsKeySnapshot
		} else {
			zap.L().Info(
				"overwriting existing KMS Key snapshot",
				zap.String("resourceId", *kmsKeySnapshot.ARN),
			)
			kmsKeySnapshots[*kmsKeySnapshot.ARN] = kmsKeySnapshot
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(kmsKeySnapshots))
	for resourceID, kmsKeySnapshot := range kmsKeySnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      kmsKeySnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.KmsKeySchema,
		})
	}

	return resources, marker, nil
}
