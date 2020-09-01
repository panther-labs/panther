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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"go.uber.org/zap"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	// The amount of time credentials are valid
	assumeRoleDuration = time.Hour
	// retries on default session
	maxRetries = 6

	// error message for failure
	clientErrMessage = "failed to get service client"
)

var (
	snapshotPollerSession *session.Session
	// assumeRoleFunc is the function to return valid AWS credentials.
	assumeRoleFunc         = assumeRole
	verifyAssumedCredsFunc = verifyAssumedCreds
)

// Key used for the client cache to neatly encapsulate an integration, service, and region
type clientKey struct {
	IntegrationID string
	Service       string
	Region        string
}

type cachedClient struct {
	Client      interface{}
	Credentials *credentials.Credentials
}

var clientCache = make(map[clientKey]cachedClient)

func Setup() {
	awsConfig := aws.NewConfig().WithMaxRetries(maxRetries)
	snapshotPollerSession = session.Must(session.NewSession(request.WithRetryer(awsConfig,
		awsretry.NewConnectionErrRetryer(*awsConfig.MaxRetries))))
}

// getClient returns a valid client for a given integration, service, and region using caching.
func getClient(pollerInput *awsmodels.ResourcePollerInput,
	clientFunc func(session *session.Session, config *aws.Config) interface{},
	service string, region string) (interface{}, error) {

	cacheKey := clientKey{
		IntegrationID: *pollerInput.IntegrationID,
		Service:       service,
		Region:        region,
	}

	// Return the cached client if the credentials used to build it are not expired
	if cachedClient, exists := clientCache[cacheKey]; exists {
		if !cachedClient.Credentials.IsExpired() {
			if cachedClient.Client != nil {
				return cachedClient.Client, nil
			}
			zap.L().Debug("expired client was cached", zap.Any("cache key", cacheKey))
		}
	}

	// Build a new client on cache miss OR if the client in the cache has expired credentials
	creds := assumeRoleFunc(pollerInput, snapshotPollerSession, region)
	err := verifyAssumedCredsFunc(creds, region)
	if err != nil {
		zap.L().Error(clientErrMessage,
			zap.Error(err),
			zap.String("service", service),
			zap.String("region", region),
			zap.Any("pollerInput", *pollerInput))
		return nil, err
	}
	client := clientFunc(snapshotPollerSession, &aws.Config{
		Credentials: creds,
		Region:      &region,
	})
	clientCache[cacheKey] = cachedClient{
		Client:      client,
		Credentials: creds,
	}
	return client, nil
}

//  assumes an IAM role associated with an AWS Snapshot Integration.
func assumeRole(pollerInput *awsmodels.ResourcePollerInput, sess *session.Session, region string) *credentials.Credentials {
	zap.L().Debug("assuming role", zap.String("roleArn", *pollerInput.AuthSource))

	if pollerInput.AuthSource == nil {
		panic("must pass non-nil authSource to AssumeRole")
	}

	creds := stscreds.NewCredentials(
		sess.Copy(&aws.Config{
			Region: &region, // this makes it work with regional endpoints
		}),
		*pollerInput.AuthSource,
		func(p *stscreds.AssumeRoleProvider) {
			p.Duration = assumeRoleDuration
		},
	)

	return creds
}

func verifyAssumedCreds(creds *credentials.Credentials, region string) error {
	svc := sts.New(
		snapshotPollerSession,
		&aws.Config{
			Credentials: creds,
			Region:      &region,
		},
	)
	_, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	return err
}
