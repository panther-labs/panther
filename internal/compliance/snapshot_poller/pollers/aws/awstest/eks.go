package awstest

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
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/stretchr/testify/mock"
)

// Example Eks API return values
var (
	ExampleEksClusterName      = aws.String("example-cluster")
	ExampleEksClusterNameMulti = aws.String("example-cluster-multi-profile")
	ExampleEksClusterArn       = aws.String("arn:aws:eks:us-west-2:123456789012:cluster/example-cluster")
	ExampleFargateProfileName  = aws.String("example-fargate-profile")
	ExampleNodegroupName       = aws.String("example-nodegroup-name")
	ExampleNodegroupArn        = aws.String("arn:aws:eks:us-west-2:123456789012:service/example-service")
	ExampleTags                = map[string]*string{*aws.String("test-tag-key"): aws.String("test-tag-value")}
	ExampleLabels              = map[string]*string{*aws.String("test-label-key"): aws.String("test-label-value")}
	ExampleCreatedAt           = aws.Time(time.Unix(1579896067, 0))

	ExampleEksListClusters = &eks.ListClustersOutput{
		Clusters: []*string{
			ExampleEksClusterName,
		},
	}

	ExampleEksListClustersContinue = &eks.ListClustersOutput{
		Clusters: []*string{
			ExampleEksClusterName,
			ExampleEksClusterName,
		},
		NextToken: aws.String("1"),
	}

	ExampleEncryptionProvider = []*eks.Provider{{KeyArn: aws.String("example-encryption-key-provider-arn")}}
	ExampleEncryptionConfig   = []*eks.EncryptionConfig{
		{
			Provider:  ExampleEncryptionProvider[0],
			Resources: []*string{aws.String("example-resource")},
		},
	}

	ExampleLogSetup = []*eks.LogSetup{{
		Enabled: aws.Bool(true),
		Types:   []*string{aws.String("example-type")},
	}}

	ExampleEksNodegroup = [1]*eks.Nodegroup{
		{
			AmiType:     aws.String("example-ami-type"),
			ClusterName: aws.String("example-cluster"),
			CreatedAt:   ExampleCreatedAt,
			DiskSize:    aws.Int64(128),
			Health: &eks.NodegroupHealth{
				Issues: []*eks.Issue{
					{
						Code:        aws.String("AccessDenied"),
						Message:     aws.String("Example Issue Message"),
						ResourceIds: []*string{ExampleEksClusterName},
					},
				},
			},
			InstanceTypes: []*string{aws.String("T2.micro")},
			Labels:        ExampleLabels,
			LaunchTemplate: &eks.LaunchTemplateSpecification{
				Id:      nil,
				Name:    aws.String("example-launch-template-id"),
				Version: aws.String("v1.0"),
			},
			ModifiedAt:     ExampleCreatedAt,
			NodeRole:       aws.String("example-node-role"),
			NodegroupArn:   ExampleNodegroupArn,
			NodegroupName:  ExampleNodegroupName,
			ReleaseVersion: aws.String("v1.0"),
			Status:         aws.String("ACTIVE"),
			Subnets:        []*string{aws.String("a"), aws.String("b")},
			Tags:           ExampleTags,
			Version:        aws.String("v1.0"),
		},
	}

	ExampleEksFargateProfile = [1]*eks.FargateProfile{
		{
			ClusterName: aws.String("example-cluster"),
			CreatedAt:   ExampleCreatedAt,
			FargateProfileArn: aws.String("arn:aws:eks:us-west-2:012345678910:fargateprofile/fargate/" +
				"default-with-infrastructure-label/06b7453e-ef9a-82fc-f0c3-736633e31d41"),
			FargateProfileName:  aws.String("example-fargate-profile-name"),
			PodExecutionRoleArn: aws.String("arn:aws:iam::012345678910:role/AmazonEKSPodExecutionRole"),
			Selectors:           []*eks.FargateProfileSelector{},
			Status:              aws.String("ACTIVE"),
			Subnets:             []*string{aws.String("a"), aws.String("b")},
			Tags:                ExampleTags,
		},
	}

	ExampleListFargateProfile = &eks.ListFargateProfilesOutput{
		FargateProfileNames: []*string{
			ExampleFargateProfileName,
		},
	}

	ExampleListFargateProfilesMulti = &eks.ListFargateProfilesOutput{
		FargateProfileNames: []*string{
			ExampleFargateProfileName,
			ExampleFargateProfileName,
		},
	}

	ExampleListNodegroups = &eks.ListNodegroupsOutput{
		Nodegroups: []*string{
			ExampleNodegroupName,
			ExampleNodegroupName,
		},
	}

	ExampleEksDescribeClusterOutput = &eks.DescribeClusterOutput{
		Cluster: &eks.Cluster{
			Arn:                  ExampleEksClusterArn,
			CertificateAuthority: &eks.Certificate{Data: aws.String("example-certificate-data")},
			ClientRequestToken:   aws.String("example-client-request-token"),
			CreatedAt:            ExampleCreatedAt,
			EncryptionConfig:     ExampleEncryptionConfig,
			Endpoint:             aws.String("example-endpoint"),
			Identity:             &eks.Identity{Oidc: &eks.OIDC{Issuer: aws.String("example-oidc-issuer")}},
			Logging:              &eks.Logging{ClusterLogging: ExampleLogSetup},
			Name:                 ExampleEksClusterName,
			PlatformVersion:      aws.String("example-cluster-platform-version"),
			ResourcesVpcConfig: &eks.VpcConfigResponse{
				ClusterSecurityGroupId: aws.String("example-cluster-security-group-id"),
				EndpointPrivateAccess:  aws.Bool(true),
				EndpointPublicAccess:   aws.Bool(true),
				PublicAccessCidrs:      []*string{aws.String("10.0.0.0/24")},
				SecurityGroupIds:       []*string{aws.String("sg-0123456789")},
				SubnetIds:              []*string{aws.String("subnet-0123456789")},
				VpcId:                  aws.String("vpc-0123456789"),
			},
			RoleArn: aws.String("arn:aws:iam::012345678910:role/EksServiceRole"),
			Status:  aws.String("CREATING"),
			Tags:    ExampleTags,
			Version: aws.String("v1.0.0"),
		},
	}

	ExampleEksDescribeNodegroupOutput      = &eks.DescribeNodegroupOutput{Nodegroup: ExampleEksNodegroup[0]}
	ExampleEksDescribeFargateProfileOutput = &eks.DescribeFargateProfileOutput{FargateProfile: ExampleEksFargateProfile[0]}

	svcEksSetupCalls = map[string]func(*MockEks){
		"ListClustersPages": func(svc *MockEks) {
			svc.On("ListClustersPages", mock.Anything).
				Return(nil)
		},
		"ListNodegroupsPages": func(svc *MockEks) {
			svc.On("ListNodegroupsPages", mock.Anything).
				Return(nil)
		},
		"ListFargateProfilesPages": func(svc *MockEks) {
			svc.On("ListFargateProfilesPages", mock.Anything).
				Return(nil)
		},
		"DescribeCluster": func(svc *MockEks) {
			svc.On("DescribeCluster", mock.Anything).
				Return(ExampleEksDescribeClusterOutput, nil)
		},
		"DescribeNodegroup": func(svc *MockEks) {
			svc.On("DescribeNodegroup", mock.Anything).
				Return(ExampleEksDescribeNodegroupOutput, nil)
		},
		"DescribeFargateProfile": func(svc *MockEks) {
			svc.On("DescribeFargateProfile", mock.Anything).
				Return(ExampleEksDescribeFargateProfileOutput, nil)
		},
	}

	svcEksSetupCallsError = map[string]func(*MockEks){
		"ListClustersPages": func(svc *MockEks) {
			svc.On("ListClustersPages", mock.Anything).
				Return(errors.New("Eks.ListClustersPages error"))
		},
		"ListNodegroupsPages": func(svc *MockEks) {
			svc.On("ListNodegroupsPages", mock.Anything).
				Return(errors.New("Eks.ListNodegroupsPages error"))
		},
		"ListFargateProfilesPages": func(svc *MockEks) {
			svc.On("ListFargateProfilesPages", mock.Anything).
				Return(errors.New("Eks.ListFargateProfilesPages error"))
		},
		"DescribeCluster": func(svc *MockEks) {
			svc.On("DescribeCluster", mock.Anything).
				Return(&eks.DescribeClusterOutput{},
					errors.New("Eks.DescribeCluster error"),
				)
		},
		"DescribeNodegroup": func(svc *MockEks) {
			svc.On("DescribeNodegroup", mock.Anything).
				Return(&eks.DescribeNodegroupOutput{},
					errors.New("Eks.DescribeNodegroup error"),
				)
		},
		"DescribeFargateProfile": func(svc *MockEks) {
			svc.On("DescribeFargateProfile", mock.Anything).
				Return(&eks.DescribeFargateProfileOutput{},
					errors.New("Eks.DescribeFargateProfile error"),
				)
		},
	}

	MockEksForSetup = &MockEks{}
)

// Eks mock

// SetupMockEks is used to override the Eks Client initializer
func SetupMockEks(_ *session.Session, _ *aws.Config) interface{} {
	return MockEksForSetup
}

// MockEks is a mock Eks client
type MockEks struct {
	eksiface.EKSAPI
	mock.Mock
}

// BuildMockEksSvc builds and returns a MockEks struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEksSvc(funcs []string) (mockSvc *MockEks) {
	mockSvc = &MockEks{}
	for _, f := range funcs {
		svcEksSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockEksSvcError builds and returns a MockEks struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEksSvcError(funcs []string) (mockSvc *MockEks) {
	mockSvc = &MockEks{}
	for _, f := range funcs {
		svcEksSetupCallsError[f](mockSvc)
	}
	return
}

// BuildEksFargateProfilevcAll builds and returns a MockEks struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEksSvcAll() (mockSvc *MockEks) {
	mockSvc = &MockEks{}
	for _, f := range svcEksSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockEksSvcAllError builds and returns a MockEks struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEksSvcAllError() (mockSvc *MockEks) {
	mockSvc = &MockEks{}
	for _, f := range svcEksSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockEks) ListClustersPages(
	in *eks.ListClustersInput,
	paginationFunction func(*eks.ListClustersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleEksListClusters, true)
	return args.Error(0)
}

func (m *MockEks) ListFargateProfilesPages(
	in *eks.ListFargateProfilesInput,
	paginationFunction func(*eks.ListFargateProfilesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	if *in.ClusterName == *ExampleEksClusterNameMulti {
		paginationFunction(ExampleListFargateProfilesMulti, true)
	} else {
		paginationFunction(ExampleListFargateProfile, true)
	}
	return args.Error(0)
}

func (m *MockEks) ListNodegroupsPages(
	in *eks.ListNodegroupsInput,
	paginationFunction func(*eks.ListNodegroupsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListNodegroups, true)
	return args.Error(0)
}

func (m *MockEks) DescribeCluster(in *eks.DescribeClusterInput) (*eks.DescribeClusterOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*eks.DescribeClusterOutput), args.Error(1)
}

func (m *MockEks) DescribeFargateProfile(in *eks.DescribeFargateProfileInput) (*eks.DescribeFargateProfileOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*eks.DescribeFargateProfileOutput), args.Error(1)
}

func (m *MockEks) DescribeNodegroup(in *eks.DescribeNodegroupInput) (*eks.DescribeNodegroupOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*eks.DescribeNodegroupOutput), args.Error(1)
}
