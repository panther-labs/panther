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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ecs/ecsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var EcsClientFunc = setupEcsClient

func setupEcsClient(sess *session.Session, cfg *aws.Config) interface{} {
	return ecs.New(sess, cfg)
}

func getEcsClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (ecsiface.ECSAPI, error) {
	client, err := getClient(pollerResourceInput, EcsClientFunc, "ecs", region)
	if err != nil {
		return nil, err
	}

	return client.(ecsiface.ECSAPI), nil
}

// PollECSCluster polls a single ECS cluster resource
func PollECSCluster(
	pollerInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getEcsClient(pollerInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildEcsClusterSnapshot(client, scanRequest.ResourceID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)

	return snapshot, nil
}

// listECSClusters returns all ECS clusters in the account
func listECSClusters(ecsSvc ecsiface.ECSAPI, nextMarker *string) (clusters []*string, marker *string, err error) {
	err = ecsSvc.ListClustersPages(&ecs.ListClustersInput{
		NextToken:  nextMarker,
		MaxResults: aws.Int64(int64(defaultBatchSize)),
	},
		func(page *ecs.ListClustersOutput, lastPage bool) bool {
			return ecsClusterIterator(page, &clusters, &marker)
		})
	if err != nil {
		return nil, nil, errors.Wrap(err, "ECS.ListClustersPages")
	}
	return
}

func ecsClusterIterator(page *ecs.ListClustersOutput, clusters *[]*string, marker **string) bool {
	*clusters = append(*clusters, page.ClusterArns...)
	*marker = page.NextToken
	return len(*clusters) < defaultBatchSize
}

// describeECSCluster provides detailed information for a given ECS cluster
func describeECSCluster(ecsSvc ecsiface.ECSAPI, arn *string) (*ecs.Cluster, error) {
	out, err := ecsSvc.DescribeClusters(&ecs.DescribeClustersInput{
		Clusters: []*string{arn},
		Include:  []*string{aws.String("TAGS")},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "ECS.DescribeClusters: %s", aws.StringValue(arn))
	}

	if len(out.Clusters) == 0 {
		zap.L().Warn(
			"tried to scan non-existent resource",
			zap.String("resourceType", awsmodels.EcsClusterSchema),
			zap.String("resourceId", *arn),
		)
		return nil, nil
	}

	if len(out.Clusters) != 1 {
		return nil, errors.WithMessagef(
			errors.New("ECS.DescribeClusters"),
			"expected exactly one ECS cluster when describing %s, but found %d clusters",
			aws.StringValue(arn),
			len(out.Clusters),
		)
	}
	return out.Clusters[0], nil
}

// getECSClusterTasks enumerates and then describes all active tasks of a cluster
func getECSClusterTasks(ecsSvc ecsiface.ECSAPI, clusterArn *string) ([]*awsmodels.EcsTask, error) {
	// Enumerate tasks
	var taskArns []*string
	err := ecsSvc.ListTasksPages(&ecs.ListTasksInput{Cluster: clusterArn},
		func(page *ecs.ListTasksOutput, lastPage bool) bool {
			taskArns = append(taskArns, page.TaskArns...)
			return true
		})

	if err != nil {
		return nil, errors.Wrapf(err, "ECS.ListTasksPages: %s", aws.StringValue(clusterArn))
	}

	// If there are no tasks stop here
	if len(taskArns) == 0 {
		return nil, nil
	}

	// Describe tasks
	//
	// The DescribeTasks API call does not have a version with builtin paging like the list
	// API call does. API set a limit of 100 tasks to describe in a single operation.
	// Loop through results 100 elements at a time and aggregate the results
	const ecsTasksBatchSize = 100
	// initialize the rawTasks variable
	var rawTasks ecs.DescribeTasksOutput
	// loop through the items in taskArns, 100 at a time
	for i := 0; i < len(taskArns); i += ecsTasksBatchSize {
		end := i + ecsTasksBatchSize
		if end > len(taskArns) {
			end = len(taskArns)
		}
		rawTasksPage, err := ecsSvc.DescribeTasks(&ecs.DescribeTasksInput{
			Cluster: clusterArn,
			// This only accepts one argument, which is the string TAGS
			// Indicates that we want to included the task tags
			Include: []*string{aws.String("TAGS")},
			Tasks:   taskArns[i:end],
		})
		if err != nil {
			return nil, errors.Wrapf(err, "ECS.DescribeTasks: %s", aws.StringValue(clusterArn))
		}
		// Append each round of rawTasksPage.Tasks results to overall rawTasks var.
		// rawTasks.Failures will only contain details of tasks removed between
		// ListTasksPages and DescribeTasks, we can safely discard those results.
		rawTasks.Tasks = append(rawTasks.Tasks, rawTasksPage.Tasks...)
	}

	tasks := make([]*awsmodels.EcsTask, 0, len(rawTasks.Tasks))
	for _, task := range rawTasks.Tasks {
		tasks = append(tasks, &awsmodels.EcsTask{
			GenericAWSResource: awsmodels.GenericAWSResource{
				ARN:  task.TaskArn,
				Tags: utils.ParseTagSlice(task.Tags),
			},
			Attachments:           task.Attachments,
			Attributes:            task.Attributes,
			AvailabilityZone:      task.AvailabilityZone,
			CapacityProviderName:  task.CapacityProviderName,
			Connectivity:          task.Connectivity,
			ConnectivityAt:        task.ConnectivityAt,
			ContainerInstanceArn:  task.ContainerInstanceArn,
			Containers:            task.Containers,
			Cpu:                   task.Cpu,
			TimeCreated:           task.CreatedAt,
			DesiredStatus:         task.DesiredStatus,
			ExecutionStoppedAt:    task.ExecutionStoppedAt,
			Group:                 task.Group,
			HealthStatus:          task.HealthStatus,
			InferenceAccelerators: task.InferenceAccelerators,
			LastStatus:            task.LastStatus,
			LaunchType:            task.LaunchType,
			Memory:                task.Memory,
			Overrides:             task.Overrides,
			PlatformVersion:       task.PlatformVersion,
			PullStartedAt:         task.PullStartedAt,
			PullStoppedAt:         task.PullStoppedAt,
			StartedAt:             task.StartedAt,
			StartedBy:             task.StartedBy,
			StopCode:              task.StopCode,
			StoppedAt:             task.StoppedAt,
			StoppedReason:         task.StoppedReason,
			StoppingAt:            task.StoppingAt,
			TaskDefinitionArn:     task.TaskDefinitionArn,
			Version:               task.Version,
		})
	}

	return tasks, nil
}

// getECSClusterServices enumerates and then describes all active services of a cluster
func getECSClusterServices(ecsSvc ecsiface.ECSAPI, clusterArn *string) ([]*awsmodels.EcsService, error) {
	// Enumerate services
	var serviceArns []*string
	err := ecsSvc.ListServicesPages(&ecs.ListServicesInput{Cluster: clusterArn},
		func(page *ecs.ListServicesOutput, lastPage bool) bool {
			serviceArns = append(serviceArns, page.ServiceArns...)
			return true
		})

	if err != nil {
		return nil, errors.Wrapf(err, "ECS.ListServicesPages: %s", aws.StringValue(clusterArn))
	}

	// If there are no services, stop here
	if len(serviceArns) == 0 {
		return nil, nil
	}

	// Describe services
	//
	// The DescribeServices API call does not have a version with builtin paging like the list
	// API call does. API set a limit of 10 services to describe in a single operation.
	// Loop through results 10 elements at a time and aggregate the results
	const ecsServiceBatchSize = 10
	// initialize the rawServices variable
	var rawServices ecs.DescribeServicesOutput
	// loop through the items in serviceArns, 10 at a time
	for i := 0; i < len(serviceArns); i += ecsServiceBatchSize {
		end := i + ecsServiceBatchSize
		if end > len(serviceArns) {
			end = len(serviceArns)
		}
		rawServicesPage, err := ecsSvc.DescribeServices(&ecs.DescribeServicesInput{
			Cluster:  clusterArn,
			Include:  []*string{aws.String("TAGS")},
			Services: serviceArns[i:end],
		})
		if err != nil {
			return nil, errors.Wrapf(err, "ECS.DescribeServices: %s", aws.StringValue(clusterArn))
		}
		// Append each round of rawServicesPage.Services results to overall rawServices var.
		// rawServices.Failures will only contain details of services deleted between
		// ListServicesPages and DescribeServices, we can safely discard those results.
		rawServices.Services = append(rawServices.Services, rawServicesPage.Services...)
	}

	services := make([]*awsmodels.EcsService, 0, len(rawServices.Services))
	for _, service := range rawServices.Services {
		services = append(services, &awsmodels.EcsService{
			GenericAWSResource: awsmodels.GenericAWSResource{
				ARN:  service.ServiceArn,
				Name: service.ServiceName,
				Tags: utils.ParseTagSlice(service.Tags),
			},
			CapacityProviderStrategy:      service.CapacityProviderStrategy,
			TimeCreated:                   service.CreatedAt,
			CreatedBy:                     service.CreatedBy,
			DeploymentConfiguration:       service.DeploymentConfiguration,
			DeploymentController:          service.DeploymentController,
			Deployments:                   service.Deployments,
			DesiredCount:                  service.DesiredCount,
			EnableECSManagedTags:          service.EnableECSManagedTags,
			Events:                        service.Events,
			HealthCheckGracePeriodSeconds: service.HealthCheckGracePeriodSeconds,
			LaunchType:                    service.LaunchType,
			LoadBalancers:                 service.LoadBalancers,
			NetworkConfiguration:          service.NetworkConfiguration,
			PendingCount:                  service.PendingCount,
			PlacementConstraints:          service.PlacementConstraints,
			PlacementStrategy:             service.PlacementStrategy,
			PlatformVersion:               service.PlatformVersion,
			PropagateTags:                 service.PropagateTags,
			RoleArn:                       service.RoleArn,
			RunningCount:                  service.RunningCount,
			SchedulingStrategy:            service.SchedulingStrategy,
			ServiceRegistries:             service.ServiceRegistries,
			Status:                        service.Status,
			TaskDefinition:                service.TaskDefinition,
			TaskSets:                      service.TaskSets,
		})
	}

	return services, nil
}

// buildEcsClusterSnapshot returns a complete snapshot of an ECS cluster
func buildEcsClusterSnapshot(ecsSvc ecsiface.ECSAPI, clusterArn *string) (*awsmodels.EcsCluster, error) {
	if clusterArn == nil {
		return nil, nil
	}

	details, err := describeECSCluster(ecsSvc, clusterArn)
	// Can details ever be nil without an error?
	if err != nil || details == nil {
		return nil, err
	}

	ecsCluster := &awsmodels.EcsCluster{
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  details.ClusterArn,
			Name: details.ClusterName,
			Tags: utils.ParseTagSlice(details.Tags),
		},
		GenericResource: awsmodels.GenericResource{
			ResourceID:   clusterArn,
			ResourceType: aws.String(awsmodels.EcsClusterSchema),
		},
		ActiveServicesCount:               details.ActiveServicesCount,
		Attachments:                       details.Attachments,
		AttachmentsStatus:                 details.AttachmentsStatus,
		CapacityProviders:                 details.CapacityProviders,
		DefaultCapacityProviderStrategy:   details.DefaultCapacityProviderStrategy,
		PendingTasksCount:                 details.PendingTasksCount,
		RegisteredContainerInstancesCount: details.RegisteredContainerInstancesCount,
		RunningTasksCount:                 details.RunningTasksCount,
		Settings:                          details.Settings,
		Statistics:                        details.Statistics,
		Status:                            details.Status,
	}

	ecsCluster.Tasks, err = getECSClusterTasks(ecsSvc, details.ClusterArn)
	if err != nil {
		return nil, err
	}

	ecsCluster.Services, err = getECSClusterServices(ecsSvc, details.ClusterArn)
	if err != nil {
		return nil, err
	}

	return ecsCluster, nil
}

// PollEcsCluster gathers information on each ECS Cluster for an AWS account.
func PollEcsClusters(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting ECS Cluster resource poller")
	ecsClusterSnapshots := make(map[string]*awsmodels.EcsCluster)

	ecsSvc, err := getEcsClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all clusters
	clusters, marker, err := listECSClusters(ecsSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	resources := make([]apimodels.AddResourceEntry, 0, len(ecsClusterSnapshots))
	for _, clusterArn := range clusters {
		ecsClusterSnapshot, err := buildEcsClusterSnapshot(ecsSvc, clusterArn)
		if err != nil {
			return nil, nil, err
		}
		ecsClusterSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		ecsClusterSnapshot.Region = pollerInput.Region

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      ecsClusterSnapshot,
			ID:              *ecsClusterSnapshot.ResourceID,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.EcsClusterSchema,
		})
	}

	return resources, marker, nil
}
