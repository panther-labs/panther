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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
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
		return nil, err
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

	snapshot, err := buildKmsKeySnapshot(client, key)
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	return snapshot, nil
}

// listKeys returns a list of all keys in the account
func listKeys(kmsSvc kmsiface.KMSAPI, nextMarker *string) (keys []*kms.KeyListEntry, marker *string, err error) {
	err = kmsSvc.ListKeysPages(
		&kms.ListKeysInput{
			Marker: nextMarker,
			Limit:  aws.Int64(int64(defaultBatchSize)),
		},
		func(page *kms.ListKeysOutput, lastPage bool) bool {
			return kmsKeyIterator(page, &keys, &marker)
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "KMS.ListKeysPages")
	}
	return
}

func kmsKeyIterator(page *kms.ListKeysOutput, keys *[]*kms.KeyListEntry, marker **string) bool {
	*keys = append(*keys, page.Keys...)
	*marker = page.NextMarker
	return len(*keys) < defaultBatchSize
}

// getKeyRotationStatus returns the rotation status for a given KMS key
func getKeyRotationStatus(kmsSvc kmsiface.KMSAPI, keyID *string) (*bool, error) {
	out, err := kmsSvc.GetKeyRotationStatus(&kms.GetKeyRotationStatusInput{KeyId: keyID})
	if err != nil {
		return nil, errors.Wrapf(err, "KMS.GetKeyRotationStatus: %s", aws.StringValue(keyID))
	}

	return out.KeyRotationEnabled, nil
}

// getKeyRotationStatus returns the rotation status for a given KMS key
func listResourceTags(kmsSvc kmsiface.KMSAPI, keyID *string) ([]*kms.Tag, error) {
	tags, err := kmsSvc.ListResourceTags(&kms.ListResourceTagsInput{KeyId: keyID})
	if err != nil {
		return nil, errors.Wrapf(err, "KMS.ListResourceTags: %s", aws.StringValue(keyID))
	}

	return tags.Tags, nil
}

// describeKey returns detailed key meta data for a given kms key
func describeKey(kmsSvc kmsiface.KMSAPI, keyID *string) (*kms.KeyMetadata, error) {
	out, err := kmsSvc.DescribeKey(&kms.DescribeKeyInput{KeyId: keyID})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) {
			switch awsErr.Code() {
			case "AccessDeniedException":
				zap.L().Warn(
					"AccessDeniedException, additional permissions were not granted or key is in another account",
					zap.String("API", "KMS.DescribeKey"),
					zap.String("key", *keyID))
				return nil, nil
			case kms.ErrCodeNotFoundException:
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *keyID),
					zap.String("resourceType", awsmodels.KmsKeySchema))
				return nil, nil
			}
		}
		return nil, errors.Wrapf(err, "KMS.DescribeKey: %s", aws.StringValue(keyID))
	}

	return out.KeyMetadata, err
}

// getKeyPolicy returns the policy document for a given KMS key
func getKeyPolicy(kmsSvc kmsiface.KMSAPI, keyID *string) (*string, error) {
	out, err := kmsSvc.GetKeyPolicy(
		&kms.GetKeyPolicyInput{KeyId: keyID, PolicyName: &defaultPolicyName},
	)
	if err != nil {
		return nil, errors.Wrapf(err, "KMS.GetKeyPolicy: key %s, default policy %s", aws.StringValue(keyID), defaultPolicyName)
	}

	return out.Policy, nil
}

// buildKmsKeySnapshot makes all the calls to build up a snapshot of a given KMS key
func buildKmsKeySnapshot(kmsSvc kmsiface.KMSAPI, key *kms.KeyListEntry) (*awsmodels.KmsKey, error) {
	if key == nil {
		return nil, nil
	}
	metadata, err := describeKey(kmsSvc, key.KeyId)
	if err != nil {
		return nil, err
	}

	// This means we don't have permission to scan the key, likely because it exists in another account
	if metadata == nil {
		return nil, nil
	}

	kmsKey := &awsmodels.KmsKey{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   key.KeyArn,
			ResourceType: aws.String(awsmodels.KmsKeySchema),
			TimeCreated:  metadata.CreationDate,
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
	if err != nil {
		return nil, err
	}
	kmsKey.Policy = policy

	// The AWS managed default ACM master key FOR SOME REASON denies the list-resource-tags API call
	// to all customer owned entities. Not documented behavior btw. All other AWS managed keys that
	// I have checked do not exhibit this behavior.
	if aws.StringValue(kmsKey.Description) != "Default master key that protects my ACM private keys when no other key is defined" {
		tags, err := listResourceTags(kmsSvc, key.KeyId)
		if err != nil {
			return nil, err
		}
		kmsKey.Tags = utils.ParseTagSlice(tags)
	}

	// Check that the key was created by the customer's account and not AWS
	if *metadata.KeyManager == customerKeyManager {
		if kmsKey.KeyRotationEnabled, err = getKeyRotationStatus(kmsSvc, key.KeyId); err != nil {
			return nil, err
		}
	}

	return kmsKey, nil
}

// PollKmsKeys gathers information on each KMS key for an AWS account.
func PollKmsKeys(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting KMS Key resource poller")

	kmsSvc, err := getKMSClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all keys
	keys, marker, err := listKeys(kmsSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(keys))
	for _, key := range keys {
		kmsKeySnapshot, err := buildKmsKeySnapshot(kmsSvc, key)
		if err != nil {
			return nil, nil, err
		}
		if kmsKeySnapshot == nil {
			continue
		}

		kmsKeySnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		kmsKeySnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      kmsKeySnapshot,
			ID:              *kmsKeySnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.KmsKeySchema,
		})
	}

	return resources, marker, nil
}
