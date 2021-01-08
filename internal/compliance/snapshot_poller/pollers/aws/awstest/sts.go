package awstest

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/stretchr/testify/mock"
)

var (
	MockSTSForSetup = &MockSTS{}
)

func SetupMockSTSClient(sess *session.Session, cfg *aws.Config) stsiface.STSAPI {
	return MockSTSForSetup
}

// MockSTS is a mock STS client.
type MockSTS struct {
	TestInput func(*sts.AssumeRoleInput)
	stsiface.STSAPI
	mock.Mock
}

// AssumeRole mocks a STS.AssumeRole function call.
// This is adopted from AWS' testing for the stscreds library: https://bit.ly/2ZOnVqg
func (s *MockSTS) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	if s.TestInput != nil {
		s.TestInput(input)
	}
	expiry := time.Now().Add(15 * time.Minute)

	return &sts.AssumeRoleOutput{
		Credentials: &sts.Credentials{
			AccessKeyId:     input.RoleArn,
			SecretAccessKey: aws.String("assumedSecretAccessKey"),
			SessionToken:    aws.String("assumedSessionToken"),
			Expiration:      &expiry,
		},
	}, nil
}

// GetCallerIdentity is a mock function to return the caller identity.
func (s *MockSTS) GetCallerIdentity(
	in *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {

	args := s.Called(in)
	return args.Get(0).(*sts.GetCallerIdentityOutput), args.Error(1)
}

// MockSTSClient is the client attached to the assume role provider.
// This can be overridden to return errors, etc.
var MockSTSClient = &MockSTS{}

// STSAssumeRoleProviderMock is used to override the assumeRoleProviderFunc in testing.
func STSAssumeRoleProviderMock() func(p *stscreds.AssumeRoleProvider) {
	return func(p *stscreds.AssumeRoleProvider) {
		p.Client = MockSTSClient
		p.ExpiryWindow = 15 * time.Minute
	}
}
