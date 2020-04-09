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
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
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
		return nil, err // error is logged in getClient()
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

	snapshot := buildEcsClusterSnapshot(client, scanRequest.ResourceID)
	if snapshot == nil {
		return nil, nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)

	return snapshot, nil
}

// listClusters returns all ECS clusters in the account
func listClusters(ecsSvc ecsiface.ECSAPI) (clusters []*string) {
	err := ecsSvc.ListClustersPages(&ecs.ListClustersInput{},
		func(page *ecs.ListClustersOutput, lastPage bool) bool {
			clusters = append(clusters, page.ClusterArns...)
			return true
		})
	if err != nil {
		utils.LogAWSError("ECS.ListClustersPages", err)
	}
	return
}

// describeCluster provides detailed information for a given ECS cluster
func describeCluster(ecsSvc ecsiface.ECSAPI, arn *string) (*ecs.Cluster, error) {
	out, err := ecsSvc.DescribeClusters(&ecs.DescribeClustersInput{
		Clusters: []*string{arn},
		Include:  []*string{aws.String("TAGS")},
	})
	if err != nil {
		utils.LogAWSError("ECS.DescribeClusters", err)
		return nil, err
	}

	if len(out.Clusters) == 0 {
		zap.L().Warn(
			"tried to scan non-existent resource",
			zap.String("resourceType", awsmodels.EcsClusterSchema),
			zap.String("resourceId", *arn),
		)
		return nil, nil
	}

	return out.Clusters[0], nil
}

// getClusterTasks enumerates and then describes all active tasks of a cluster
func getClusterTasks(ecsSvc ecsiface.ECSAPI, clusterArn *string) ([]*awsmodels.EcsTask, error) {
	// Enumerate tasks
	var taskArns []*string
	err := ecsSvc.ListTasksPages(&ecs.ListTasksInput{Cluster: clusterArn},
		func(page *ecs.ListTasksOutput, lastPage bool) bool {
			taskArns = append(taskArns, page.TaskArns...)
			return true
		})

	if err != nil {
		utils.LogAWSError("ECS.ListTasksPages", err)
		return nil, err
	}

	// If there are no tasks stop here
	if len(taskArns) == 0 {
		return nil, nil
	}

	// Describe tasks
	//
	// Oddly, the DescribeTasks API call does not have a version with builtin paging like the list
	// API call does. If we run into issues here we may need to implement paging ourselves.
	rawTasks, err := ecsSvc.DescribeTasks(&ecs.DescribeTasksInput{
		Cluster: clusterArn,
		// This only accepts one argument, which is the string TAGS
		// Indicates that we want to included the task tags
		Include: []*string{aws.String("TAGS")},
		Tasks:   taskArns,
	})
	if err != nil {
		utils.LogAWSError("ECS.DescribeTasks", err)
		return nil, err
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
			ConnectivityAt:        utils.DateTimeFormat(aws.TimeValue(task.ConnectivityAt)),
			ContainerInstanceArn:  task.ContainerInstanceArn,
			Containers:            task.Containers,
			Cpu:                   task.Cpu,
			TimeCreated:           utils.DateTimeFormat(aws.TimeValue(task.CreatedAt)),
			DesiredStatus:         task.DesiredStatus,
			ExecutionStoppedAt:    utils.DateTimeFormat(aws.TimeValue(task.ExecutionStoppedAt)),
			Group:                 task.Group,
			HealthStatus:          task.HealthStatus,
			InferenceAccelerators: task.InferenceAccelerators,
			LastStatus:            task.LastStatus,
			LaunchType:            task.LaunchType,
			Memory:                task.Memory,
			Overrides:             task.Overrides,
			PlatformVersion:       task.PlatformVersion,
			PullStartedAt:         utils.DateTimeFormat(aws.TimeValue(task.PullStartedAt)),
			PullStoppedAt:         utils.DateTimeFormat(aws.TimeValue(task.PullStoppedAt)),
			StartedAt:             utils.DateTimeFormat(aws.TimeValue(task.StartedAt)),
			StartedBy:             task.StartedBy,
			StopCode:              task.StopCode,
			StoppedAt:             utils.DateTimeFormat(aws.TimeValue(task.StoppedAt)),
			StoppedReason:         task.StoppedReason,
			StoppingAt:            utils.DateTimeFormat(aws.TimeValue(task.StoppingAt)),
			TaskDefinitionArn:     task.TaskDefinitionArn,
			Version:               task.Version,
		})
	}

	return tasks, nil
}

// getClusterServices enumerates and then describes all active services of a cluster
func getClusterServices(ecsSvc ecsiface.ECSAPI, clusterArn *string) ([]*awsmodels.EcsService, error) {
	// Enumerate services
	var serviceArns []*string
	err := ecsSvc.ListServicesPages(&ecs.ListServicesInput{Cluster: clusterArn},
		func(page *ecs.ListServicesOutput, lastPage bool) bool {
			serviceArns = append(serviceArns, page.ServiceArns...)
			return true
		})

	if err != nil {
		utils.LogAWSError("ECS.ListServicesPages", err)
		return nil, err
	}

	// If there are no services stop here
	if len(serviceArns) == 0 {
		return nil, nil
	}

	// Describe services
	//
	// Oddly, the DescribeServices API call does not have a version with builtin paging like the list
	// API call does. If we run into issues here we may need to implement paging ourselves.
	rawServices, err := ecsSvc.DescribeServices(&ecs.DescribeServicesInput{
		Cluster: clusterArn,
		// This only accepts one argument, which is the string TAGS
		// Indicates that we want to included the task tags
		Include:  []*string{aws.String("TAGS")},
		Services: serviceArns,
	})

	if err != nil {
		utils.LogAWSError("ECS.DescribeServices", err)
		return nil, err
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
			TimeCreated:                   utils.DateTimeFormat(aws.TimeValue(service.CreatedAt)),
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
func buildEcsClusterSnapshot(ecsSvc ecsiface.ECSAPI, clusterArn *string) *awsmodels.EcsCluster {
	if clusterArn == nil {
		return nil
	}

	details, err := describeCluster(ecsSvc, clusterArn)
	if err != nil || details == nil {
		return nil
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

	ecsCluster.Tasks, err = getClusterTasks(ecsSvc, details.ClusterArn)
	if err != nil {
		return nil
	}

	ecsCluster.Services, err = getClusterServices(ecsSvc, details.ClusterArn)
	if err != nil {
		return nil
	}

	return ecsCluster
}

// PollEcsCluster gathers information on each ECS Cluster for an AWS account.
func PollEcsClusters(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting ECS Cluster resource poller")
	ecsClusterSnapshots := make(map[string]*awsmodels.EcsCluster)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "ecs") {
		ecsSvc, err := getEcsClient(pollerInput, *regionID)
		if err != nil {
			return nil, err // error is logged in getClient()
		}

		// Start with generating a list of all clusters
		clusters := listClusters(ecsSvc)
		if len(clusters) == 0 {
			zap.L().Debug("no ECS clusters found", zap.String("region", *regionID))
			continue
		}

		for _, clusterArn := range clusters {
			ecsClusterSnapshot := buildEcsClusterSnapshot(ecsSvc, clusterArn)
			if ecsClusterSnapshot == nil {
				continue
			}
			ecsClusterSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			ecsClusterSnapshot.Region = regionID

			if _, ok := ecsClusterSnapshots[*ecsClusterSnapshot.ARN]; ok {
				zap.L().Info(
					"overwriting existing ECS Certificate snapshot",
					zap.String("resourceId", *ecsClusterSnapshot.ARN),
				)
			}
			ecsClusterSnapshots[*ecsClusterSnapshot.ARN] = ecsClusterSnapshot
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(ecsClusterSnapshots))
	for resourceID, ecsSnapshot := range ecsClusterSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      ecsSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.EcsClusterSchema,
		})
	}

	return resources, nil
}
