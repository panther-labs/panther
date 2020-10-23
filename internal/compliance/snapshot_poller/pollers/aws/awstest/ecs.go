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
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/stretchr/testify/mock"
)

// Example ECS API return values
var (
	ExampleEcsClusterArn          = aws.String("arn:aws:ecs:us-west-2:123456789012:cluster/example-cluster")
	ExampleEcsClusterMultiSvcArn  = aws.String("arn:aws:ecs:us-west-2:123456789012:cluster/example-cluster-multi-service")
	ExampleEcsClusterMultiTaskArn = aws.String("arn:aws:ecs:us-west-2:123456789012:cluster/example-cluster-multi-task")
	ExampleTaskArn                = aws.String("arn:aws:ecs:us-west-2:123456789012:task/1111-2222")
	ExampleServiceArn             = aws.String("arn:aws:ecs:us-west-2:123456789012:service/example-service")

	ExampleEcsListClusters = &ecs.ListClustersOutput{
		ClusterArns: []*string{
			ExampleEcsClusterArn,
		},
	}

	ExampleEcsListClustersContinue = &ecs.ListClustersOutput{
		ClusterArns: []*string{
			ExampleEcsClusterArn,
			ExampleEcsClusterArn,
		},
		NextToken: aws.String("1"),
	}

	ExampleEcsListTasks = &ecs.ListTasksOutput{
		TaskArns: []*string{
			ExampleTaskArn,
		},
	}

	ExampleEcsListTasksMultiTasks = &ecs.ListTasksOutput{
		TaskArns: []*string{},
	}

	ExampleEcsListServices = &ecs.ListServicesOutput{
		ServiceArns: []*string{
			ExampleServiceArn,
		},
	}

	ExampleEcsListServicesMultiSvc = &ecs.ListServicesOutput{
		ServiceArns: []*string{},
	}

	ExampleEcsDescribeClustersOutput = &ecs.DescribeClustersOutput{
		Clusters: []*ecs.Cluster{
			{
				ClusterArn:                        ExampleEcsClusterArn,
				ClusterName:                       aws.String("example-cluster"),
				Status:                            aws.String("ACTIVE"),
				RegisteredContainerInstancesCount: aws.Int64(0),
				RunningTasksCount:                 aws.Int64(1),
				PendingTasksCount:                 aws.Int64(0),
				ActiveServicesCount:               aws.Int64(1),
				Statistics:                        []*ecs.KeyValuePair{},
				Tags: []*ecs.Tag{
					{
						Key:   aws.String("Key1"),
						Value: aws.String("Value1"),
					},
				},
				Settings: []*ecs.ClusterSetting{
					{
						Name:  aws.String("containerInsights"),
						Value: aws.String("disabled"),
					},
				},
				CapacityProviders:               []*string{},
				DefaultCapacityProviderStrategy: []*ecs.CapacityProviderStrategyItem{},
			},
		},
	}

	ExampleEcsDescribeTasksOutput = &ecs.DescribeTasksOutput{
		Failures: nil,
		Tasks: []*ecs.Task{
			{
				Attachments: []*ecs.Attachment{
					{
						Id:     aws.String("1111-222"),
						Type:   aws.String("ElasticNetworkInterface"),
						Status: aws.String("ATTACHED"),
						Details: []*ecs.KeyValuePair{
							{
								Name:  aws.String("subnetId"),
								Value: aws.String("subnet-111"),
							},
						},
					},
				},
				AvailabilityZone: aws.String("us-west-2b"),
				ClusterArn:       aws.String("arn:aws:ecs:us-west-2:123456789012:cluster/example-cluster"),
				Connectivity:     aws.String("CONNECTED"),
				Containers: []*ecs.Container{
					{
						ContainerArn: aws.String("arn:aws:ecs:us-west-2:123456789012:container/1111"),
						TaskArn:      aws.String("arn:aws:ecs:us-west-2:123456789012:task/2222"),
						Name:         aws.String("example"),
					},
				},
				Cpu:             aws.String("512"),
				DesiredStatus:   aws.String("RUNNING"),
				Group:           aws.String("service:example"),
				PlatformVersion: aws.String("1.3.0"),
				StartedBy:       aws.String("ecs-svc/1111"),
				Tags:            []*ecs.Tag{},
				Version:         aws.Int64(3),
			},
		},
	}

	ExampleEcsDescribeServicesOutput = &ecs.DescribeServicesOutput{
		Services: []*ecs.Service{
			{
				ServiceArn:  aws.String("arn:aws:ecs:us-west-2:123456789012:service/example"),
				ServiceName: aws.String("example"),
				ClusterArn:  aws.String("arn:aws:ecs:us-west-2:123456789012:cluster/example-cluster"),
				LoadBalancers: []*ecs.LoadBalancer{
					{
						TargetGroupArn: aws.String("arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/example/1111"),
						ContainerName:  aws.String("example"),
						ContainerPort:  aws.Int64(80),
					},
				},
				RunningCount: aws.Int64(1),
				PendingCount: aws.Int64(0),
				DeploymentConfiguration: &ecs.DeploymentConfiguration{
					MaximumPercent:        aws.Int64(200),
					MinimumHealthyPercent: aws.Int64(50),
				},
				RoleArn: aws.String("arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"),
				Events: []*ecs.ServiceEvent{
					{
						Id:        aws.String("2222"),
						CreatedAt: aws.Time(time.Unix(1581379785, 0)),
						Message:   aws.String("(service example) has reached a steady state."),
					},
					{
						Id:        aws.String("1111"),
						CreatedAt: aws.Time(time.Unix(1581379764, 0)),
						Message:   aws.String("(service example) has stopped 1 running tasks: (task 1111)."),
					},
				},
				CreatedAt: aws.Time(time.Unix(1579896067, 0)),
			},
		},
	}

	svcEcsSetupCalls = map[string]func(*MockEcs){
		"ListClustersPages": func(svc *MockEcs) {
			svc.On("ListClustersPages", mock.Anything).
				Return(nil)
		},
		"ListTasksPages": func(svc *MockEcs) {
			svc.On("ListTasksPages", mock.Anything).
				Return(nil)
		},
		"ListServicesPages": func(svc *MockEcs) {
			svc.On("ListServicesPages", mock.Anything).
				Return(nil)
		},
		"DescribeClusters": func(svc *MockEcs) {
			svc.On("DescribeClusters", mock.Anything).
				Return(ExampleEcsDescribeClustersOutput, nil)
		},
		"DescribeTasks": func(svc *MockEcs) {
			svc.On("DescribeTasks", mock.Anything).
				Return(ExampleEcsDescribeTasksOutput, nil)
		},
		"DescribeServices": func(svc *MockEcs) {
			svc.On("DescribeServices", mock.Anything).
				Return(ExampleEcsDescribeServicesOutput, nil)
		},
	}

	svcEcsSetupCallsError = map[string]func(*MockEcs){
		"ListClustersPages": func(svc *MockEcs) {
			svc.On("ListClustersPages", mock.Anything).
				Return(errors.New("ECS.ListListClustersPages error"))
		},
		"ListTasksPages": func(svc *MockEcs) {
			svc.On("ListTaskPages", mock.Anything).
				Return(errors.New("ECS.ListTaskPages error"))
		},
		"ListServicesPages": func(svc *MockEcs) {
			svc.On("ListServicesPages", mock.Anything).
				Return(errors.New("ECS.ListServicesPages error"))
		},
		"DescribeClusters": func(svc *MockEcs) {
			svc.On("DescribeClusters", mock.Anything).
				Return(&ecs.DescribeClustersOutput{},
					errors.New("ECS.DescribeClusters error"),
				)
		},
		"DescribeTasks": func(svc *MockEcs) {
			svc.On("DescribeTasks", mock.Anything).
				Return(&ecs.DescribeTasksOutput{},
					errors.New("ECS.DescribeTasks error"),
				)
		},
		"DescribeServices": func(svc *MockEcs) {
			svc.On("DescribeServices", mock.Anything).
				Return(&ecs.DescribeServicesOutput{},
					errors.New("ECS.DescribeServices error"),
				)
		},
	}

	MockEcsForSetup = &MockEcs{}
)

// initialize globals
func init() {
	for i := 0; i < 120; i++ {
		ExampleEcsListTasksMultiTasks.TaskArns = append(ExampleEcsListTasksMultiTasks.TaskArns, ExampleTaskArn)
	}
	for i := 0; i < 12; i++ {
		ExampleEcsListServicesMultiSvc.ServiceArns = append(ExampleEcsListServicesMultiSvc.ServiceArns, ExampleServiceArn)
	}
}

// ECS mock

// SetupMockEcs is used to override the ECS Client initializer
func SetupMockEcs(_ *session.Session, _ *aws.Config) interface{} {
	return MockEcsForSetup
}

// MockEcs is a mock ECS client
type MockEcs struct {
	ecsiface.ECSAPI
	mock.Mock
}

// BuildMockEcsSvc builds and returns a MockEcs struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEcsSvc(funcs []string) (mockSvc *MockEcs) {
	mockSvc = &MockEcs{}
	for _, f := range funcs {
		svcEcsSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockEcsSvcError builds and returns a MockEcs struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockEcsSvcError(funcs []string) (mockSvc *MockEcs) {
	mockSvc = &MockEcs{}
	for _, f := range funcs {
		svcEcsSetupCallsError[f](mockSvc)
	}
	return
}

// BuildMockEcsSvcAll builds and returns a MockEcs struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEcsSvcAll() (mockSvc *MockEcs) {
	mockSvc = &MockEcs{}
	for _, f := range svcEcsSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockEcsSvcAllError builds and returns a MockEcs struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockEcsSvcAllError() (mockSvc *MockEcs) {
	mockSvc = &MockEcs{}
	for _, f := range svcEcsSetupCallsError {
		f(mockSvc)
	}
	return
}

func (m *MockEcs) ListClustersPages(
	in *ecs.ListClustersInput,
	paginationFunction func(*ecs.ListClustersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleEcsListClusters, true)
	return args.Error(0)
}

func (m *MockEcs) ListServicesPages(
	in *ecs.ListServicesInput,
	paginationFunction func(*ecs.ListServicesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	// Return appropriate ListServices output based on input ClusterARN
	if in.Cluster == ExampleEcsClusterMultiSvcArn {
		paginationFunction(ExampleEcsListServicesMultiSvc, true)
		return args.Error(0)
	}
	paginationFunction(ExampleEcsListServices, true)
	return args.Error(0)
}

func (m *MockEcs) ListTasksPages(
	in *ecs.ListTasksInput,
	paginationFunction func(*ecs.ListTasksOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	// Return appropriate ListTasks output based on input ClusterARN
	if in.Cluster == ExampleEcsClusterMultiTaskArn {
		paginationFunction(ExampleEcsListTasksMultiTasks, true)
		return args.Error(0)
	}
	paginationFunction(ExampleEcsListTasks, true)
	return args.Error(0)
}

func (m *MockEcs) DescribeClusters(in *ecs.DescribeClustersInput) (*ecs.DescribeClustersOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*ecs.DescribeClustersOutput), args.Error(1)
}

func (m *MockEcs) DescribeServices(in *ecs.DescribeServicesInput) (*ecs.DescribeServicesOutput, error) {
	args := m.Called(in)
	// API only allows describing 10 services at a time.
	// Return error if input has more than 10 ServiceArns.
	if len(in.Services) > 10 {
		return nil, errors.New("ECS.DescribeServices error: Too many service ARNS passed to DescribeServices")
	}
	return args.Get(0).(*ecs.DescribeServicesOutput), args.Error(1)
}

func (m *MockEcs) DescribeTasks(in *ecs.DescribeTasksInput) (*ecs.DescribeTasksOutput, error) {
	args := m.Called(in)
	// API only allows describing 100 tasks at a time.
	// Return error if input has more than 100 TaskArns.
	if len(in.Tasks) > 100 {
		return nil, errors.New("ECS.DescribeTasks error: Too many task ARNS passed to DescribeTasks")
	}
	return args.Get(0).(*ecs.DescribeTasksOutput), args.Error(1)
}
