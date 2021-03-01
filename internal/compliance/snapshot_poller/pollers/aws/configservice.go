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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	ConfigServiceClientFunc = setupConfigServiceClient
)

func setupConfigServiceClient(sess *session.Session, cfg *aws.Config) interface{} {
	return configservice.New(sess, cfg)
}

func getConfigServiceClient(pollerResourceInput *awsmodels.ResourcePollerInput,
	region string) (configserviceiface.ConfigServiceAPI, error) {

	client, err := getClient(pollerResourceInput, ConfigServiceClientFunc, "configservice", region)
	if err != nil {
		return nil, err
	}

	return client.(configserviceiface.ConfigServiceAPI), nil
}

// PollConfigService polls a single AWS Config resource
func PollConfigService(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	parsedResourceID *utils.ParsedResourceID,
	scanRequest *pollermodels.ScanEntry) (interface{}, error) {

	configClient, err := getConfigServiceClient(pollerResourceInput, parsedResourceID.Region)
	if err != nil {
		return nil, err
	}

	recorder, err := getConfigRecorder(configClient)
	if err != nil || recorder == nil {
		return nil, errors.WithMessagef(err, "region: %s", parsedResourceID.Region)
	}
	snapshot, err := buildConfigServiceSnapshot(configClient, recorder, parsedResourceID.Region, pollerResourceInput)
	if err != nil {
		return nil, err
	}
	// Handles situation where the config service is ignored
	if snapshot == nil {
		return nil, nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(pollerResourceInput.AuthSourceParsedARN.AccountID)
	return snapshot, nil
}

// getConfigRecorder returns a specific config recorder
func getConfigRecorder(svc configserviceiface.ConfigServiceAPI) (*configservice.ConfigurationRecorder, error) {
	recorder, err := svc.DescribeConfigurationRecorders(&configservice.DescribeConfigurationRecordersInput{
		ConfigurationRecorderNames: []*string{aws.String("default")},
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == configservice.ErrCodeNoSuchConfigurationRecorderException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resourceType", awsmodels.ConfigServiceSchema))
			return nil, nil
		}
		return nil, errors.Wrap(err, "ConfigService.DescribeConfigurationRecorders")
	}

	if recorder == nil || len(recorder.ConfigurationRecorders) != 1 {
		return nil, errors.New("unexpected response from config.DescribeConfigurationRecorders")
	}
	return recorder.ConfigurationRecorders[0], nil
}

// describeConfigurationRecorders returns a slice of all config recorders in the given region/account
func describeConfigurationRecorders(
	configServiceSvc configserviceiface.ConfigServiceAPI,
) ([]*configservice.ConfigurationRecorder, error) {

	recorders, err := configServiceSvc.DescribeConfigurationRecorders(
		&configservice.DescribeConfigurationRecordersInput{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "ConfigService.DescribeConfigurationRecorderStatus")
	}

	return recorders.ConfigurationRecorders, nil
}

// describeConfigurationRecorderStatus returns the status of the given configuration recorder
func describeConfigurationRecorderStatus(
	configServiceSvc configserviceiface.ConfigServiceAPI, name *string,
) (*configservice.ConfigurationRecorderStatus, error) {

	status, err := configServiceSvc.DescribeConfigurationRecorderStatus(
		&configservice.DescribeConfigurationRecorderStatusInput{
			ConfigurationRecorderNames: []*string{name},
		})
	if err != nil {
		return nil, errors.Wrapf(err, "ConfigService.DescribeConfigurationRecorderStatus: %s", aws.StringValue(name))
	}

	if len(status.ConfigurationRecordersStatus) > 0 {
		return status.ConfigurationRecordersStatus[0], nil
	}
	return nil, nil
}

// buildConfigServiceSnapshot makes the required calls to build a ConfigServiceSnapshot object
func buildConfigServiceSnapshot(
	configServiceSvc configserviceiface.ConfigServiceAPI,
	recorder *configservice.ConfigurationRecorder,
	regionID string,
	pollerInput *awsmodels.ResourcePollerInput,
) (*awsmodels.ConfigService, error) {

	configSnapshot := &awsmodels.ConfigService{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.ConfigServiceSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name:   recorder.Name,
			Region: &regionID,
		},
		RecordingGroup: recorder.RecordingGroup,
		RoleARN:        recorder.RoleARN,
	}
	if pollerInput != nil {
		// Check if ResourceID matches the integration's regex filter
		if pollerInput.ShouldIgnoreResource(*recorder.Name) {
			return nil, nil
		}
	}

	status, err := describeConfigurationRecorderStatus(configServiceSvc, recorder.Name)
	if err != nil {
		return nil, err
	}
	configSnapshot.Status = status

	return configSnapshot, nil
}

// PollConfigServices gathers information on each config service for an AWS account.
func PollConfigServices(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting ConfigService poller")
	configSnapshots := make(map[string]*awsmodels.ConfigService)

	regions, err := GetServiceRegionsFunc(pollerInput, awsmodels.ConfigServiceSchema)
	if err != nil {
		return nil, nil, err
	}

	for _, regionID := range regions {
		zap.L().Debug("building Config snapshots", zap.String("region", *regionID))
		configServiceSvc, err := getConfigServiceClient(pollerInput, *regionID)
		if err != nil {
			var e *RegionIgnoreListError
			if errors.As(err, &e) {
				zap.L().Debug("Skipping denied region in Config scan")
				continue
			}
			return nil, nil, err
		}

		// Start with generating a list of all recorders
		recorders, err := describeConfigurationRecorders(configServiceSvc)
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "region: %s", *regionID)
		}

		for _, recorder := range recorders {
			configServiceSnapshot, err := buildConfigServiceSnapshot(configServiceSvc, recorder, *regionID, pollerInput)
			if err != nil {
				return nil, nil, err
			}
			// Handles the situation where the resource is ignored
			if configServiceSnapshot == nil {
				continue
			}
			configServiceSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

			resourceID := utils.GenerateResourceID(
				pollerInput.AuthSourceParsedARN.AccountID,
				*regionID,
				awsmodels.ConfigServiceSchema,
			)
			configServiceSnapshot.ResourceID = aws.String(resourceID)

			if _, ok := configSnapshots[resourceID]; !ok {
				configSnapshots[resourceID] = configServiceSnapshot
			} else {
				zap.L().Info(
					"overwriting existing ConfigService snapshot", zap.String("resourceId", resourceID))
				configSnapshots[resourceID] = configServiceSnapshot
			}
		}
	}

	configMetaSnapshot := &awsmodels.ConfigServiceMeta{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.ConfigServiceMetaSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: aws.String(pollerInput.AuthSourceParsedARN.AccountID),
			Name:      aws.String(awsmodels.ConfigServiceMetaSchema),
			Region:    aws.String(awsmodels.GlobalRegion),
		},
		GlobalRecorderCount: aws.Int(0),
		Recorders:           []*string{},
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(configSnapshots)+1)
	for resourceID, configSnapshot := range configSnapshots {
		configMetaSnapshot.Recorders = append(configMetaSnapshot.Recorders, aws.String(resourceID))
		if *configSnapshot.RecordingGroup.AllSupported && *configSnapshot.RecordingGroup.IncludeGlobalResourceTypes {
			*configMetaSnapshot.GlobalRecorderCount++
		}

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      configSnapshot,
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.ConfigServiceSchema,
		})
	}

	configMetaSnapshot.GlobalRecorderCount = aws.Int(len(resources))
	configMetaResourceID := utils.GenerateResourceID(
		pollerInput.AuthSourceParsedARN.AccountID,
		"",
		awsmodels.ConfigServiceMetaSchema,
	)
	configMetaSnapshot.ResourceID = aws.String(configMetaResourceID)

	resources = append(resources, apimodels.AddResourceEntry{
		Attributes:      configMetaSnapshot,
		ID:              configMetaResourceID,
		IntegrationID:   *pollerInput.IntegrationID,
		IntegrationType: integrationType,
		Type:            awsmodels.ConfigServiceMetaSchema,
	})

	// We don't support paging for Config resources. Since you can only have one config recorder per
	// region anyways, this shouldn't be an issue.
	return resources, nil, nil
}
