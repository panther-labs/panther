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
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	IAMClientFunc = setupIAMClient
)

func setupIAMClient(sess *session.Session, cfg *aws.Config) interface{} {
	return iam.New(sess, cfg)
}

func getIAMClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (iamiface.IAMAPI, error) {
	client, err := getClient(pollerResourceInput, IAMClientFunc, "iam", region)
	if err != nil {
		return nil, err
	}

	return client.(iamiface.IAMAPI), nil
}

// PollPasswordPolicyResource polls a password policy and returns it as a resource
func PollPasswordPolicyResource(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	_ *utils.ParsedResourceID,
	_ *pollermodels.ScanEntry,
) (interface{}, error) {

	// Throw away the dummy next page response, password policy resources don't need paging
	// during scanning
	snapshot, _, err := PollPasswordPolicy(pollerResourceInput)
	if err != nil || snapshot == nil {
		return nil, err
	}
	return snapshot[0].Attributes, nil
}

// getPasswordPolicy returns the password policy for the account
func getPasswordPolicy(svc iamiface.IAMAPI) (*iam.PasswordPolicy, error) {
	out, err := svc.GetAccountPasswordPolicy(&iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, errors.Wrap(err, "IAM.GetAccountPasswordPolicy")
	}

	return out.PasswordPolicy, nil
}

// PollPasswordPolicy gathers information on all PasswordPolicy in an AWS account.
func PollPasswordPolicy(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting Password Policy resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, nil, err
	}

	anyExist := true
	passwordPolicy, err := getPasswordPolicy(iamSvc)
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			anyExist = false
		} else {
			// The error wasn't caused by the password policy not existing: return it
			return nil, nil, err
		}
	}

	resourceID := utils.GenerateResourceID(
		pollerInput.AuthSourceParsedARN.AccountID,
		"",
		awsmodels.PasswordPolicySchema,
	)

	// Check if ResourceID matches the integration's regex filter
	if pollerInput.ShouldIgnoreResource(resourceID) {
		return nil, nil, nil
	}
	genericFields := awsmodels.GenericResource{
		ResourceID:   aws.String(resourceID),
		ResourceType: aws.String(awsmodels.PasswordPolicySchema),
	}
	genericAWSFields := awsmodels.GenericAWSResource{
		AccountID: aws.String(pollerInput.AuthSourceParsedARN.AccountID),
		Name:      aws.String(awsmodels.PasswordPolicySchema),
		Region:    aws.String(awsmodels.GlobalRegion),
	}

	// Password Policy never pages
	if anyExist && passwordPolicy != nil {
		return []apimodels.AddResourceEntry{{
			Attributes: &awsmodels.PasswordPolicy{
				GenericResource:    genericFields,
				GenericAWSResource: genericAWSFields,
				AnyExist:           anyExist,
				PasswordPolicy:     *passwordPolicy,
			},
			ID:              resourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.PasswordPolicySchema,
		}}, nil, nil
	}

	return []apimodels.AddResourceEntry{{
		Attributes: &awsmodels.PasswordPolicy{
			GenericResource:    genericFields,
			GenericAWSResource: genericAWSFields,
			AnyExist:           anyExist,
		},
		ID:              resourceID,
		IntegrationID:   *pollerInput.IntegrationID,
		IntegrationType: integrationType,
		Type:            awsmodels.PasswordPolicySchema,
	}}, nil, nil
}
