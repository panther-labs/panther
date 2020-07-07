---
description: Amazon Elastic Container Service Cluster
---

# ECS Cluster

#### Resource Type

`AWS.ECS.Cluster`

#### Resource ID Format

The resource ID is the cluster ARN.

`arn:aws:ecs:us-east-1:123456789012:cluster/panther-web-cluster`

#### Background

An Amazon ECS cluster is a logical grouping of tasks or services.

#### Fields

| Field             | Type     | Description                                                                                                                           |
| :---------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| `RunningTasksCount` | `Int` |  The number of runnning tasks                                                                          |
| `Tasks`         | `Map` | The ECS tasks running in the cluster owner.                                                                                                |

#### Example

```json
{
	"CapacityProviders": null,
	"Tasks": [
		{
			"AvailabilityZone": "us-east-1b",
			"Version": 3,
			"StoppedReason": null,
			"Overrides": {
				"ContainerOverrides": [
					{
						"EnvironmentFiles": null,
						"Name": "panther-web",
						"MemoryReservation": null,
						"Command": null,
						"Memory": null,
						"Cpu": null,
						"Environment": null,
						"ResourceRequirements": null
					}
				],
				"Memory": null,
				"Cpu": null,
				"ExecutionRoleArn": null,
				"InferenceAcceleratorOverrides": null,
				"TaskRoleArn": null
			},
			"Tags": null,
			"Region": null,
			"ConnectivityAt": "2020-06-05T20:59:03.000Z",
			"StoppedAt": "0001-01-01T00:00:00.000Z",
			"InferenceAccelerators": null,
			"Attributes": null,
			"StopCode": null,
			"PullStoppedAt": "2020-06-05T20:59:53.000Z",
			"LaunchType": "FARGATE",
			"Attachments": [
				{
					"Status": "ATTACHED",
					"Type": "ElasticNetworkInterface",
					"Details": [
						{
							"Name": "subnetId",
							"Value": "subnet-001113333fff77777"
						},
						{
							"Value": "eni-001113333fff77777",
							"Name": "networkInterfaceId"
						},
						{
							"Value": "02:ad:9c:22:93:a9",
							"Name": "macAddress"
						},
						{
							"Value": "10.0.0.103",
							"Name": "privateIPv4Address"
						}
					],
					"Id": "9c7e-8d8a7ea3bd6b"
				}
			],
			"StoppingAt": "0001-01-01T00:00:00.000Z",
			"ContainerInstanceArn": null,
			"PlatformVersion": "1.3.0",
			"CapacityProviderName": null,
			"DesiredStatus": "RUNNING",
			"Memory": "1024",
			"TimeCreated": "2020-06-05T20:58:58.000Z",
			"Group": "service:panther-web",
			"StartedAt": "2020-06-05T20:59:54.000Z",
			"Connectivity": "CONNECTED",
			"Containers": [
				{
					"MemoryReservation": "1024",
					"ImageDigest": "sha256:6c79fb3782ad6b42dc08e4c88a12d2e5b097a9dd2338a44fd8ae2e1c8e13c20e",
					"Image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/panther-web:12e2171dc4408d5fbd2b011dad43496925f2c88da51dfd4f0632ff6b07cfea51",
					"RuntimeId": "ee28d181f47249a77c11fffc1feadd",
					"Cpu": "512",
					"TaskArn": "arn:aws:ecs:us-east-1:123456789012:task/a5e41fe0-0056-4140-a6fd-c7738959ccc4",
					"Memory": "1024",
					"ContainerArn": "arn:aws:ecs:us-east-1:123456789012:container/f41c2745-86b1-43bf-855c-59d4655cc4f6",
					"GpuIds": null,
					"Reason": null,
					"NetworkBindings": null,
					"ExitCode": null,
					"Name": "panther-web",
					"NetworkInterfaces": [
						{
							"AttachmentId": "8b043f1e-ee7d-400c-9c7e-8d8a7ea3bd6b",
							"Ipv6Address": null,
							"PrivateIpv4Address": "10.0.0.103"
						}
					],
					"LastStatus": "RUNNING",
					"HealthStatus": "UNKNOWN"
				}
			],
			"Cpu": "512",
			"Arn": "arn:aws:ecs:us-east-1:123456789012:task/a5e41fe0-0056-4140-a6fd-c7738959ccc4",
			"StartedBy": "ecs-svc/6871675624579221172",
			"ExecutionStoppedAt": "0001-01-01T00:00:00.000Z",
			"AccountId": null,
			"HealthStatus": "UNKNOWN",
			"PullStartedAt": "2020-06-05T20:59:10.000Z",
			"LastStatus": "RUNNING",
			"TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/panther-web:11"
		}
	],
	"PendingTasksCount": 0,
	"Region": "us-east-1",
	"Statistics": null,
	"Status": "ACTIVE",
	"ResourceType": "AWS.ECS.Cluster",
	"RunningTasksCount": 1,
	"AttachmentsStatus": null,
	"ActiveServicesCount": 1,
	"Arn": "arn:aws:ecs:us-east-1:123456789012:cluster/panther-web-cluster",
	"Name": "panther-web-cluster",
	"TimeCreated": null,
	"Attachments": null,
	"RegisteredContainerInstancesCount": 0,
	"AccountId": "123456789012",
	"Settings": [
		{
			"Name": "containerInsights",
			"Value": "disabled"
		}
	],
	"ResourceId": "arn:aws:ecs:us-east-1:123456789012:cluster/panther-web-cluster",
	"Services": [
		{
			"NetworkConfiguration": {
				"AwsvpcConfiguration": {
					"AssignPublicIp": "ENABLED",
					"SecurityGroups": [
						"sg-000fff8888889cb03"
					],
					"Subnets": [
						"subnet-039f9387",
						"subnet-039f9388"
					]
				}
			},
			"TaskSets": null,
			"TimeCreated": "2020-06-03T21:06:21.000Z",
			"TaskDefinition": "arn:aws:ecs:us-east-1:123456789012:task-definition/panther-web:11",
			"ServiceRegistries": null,
			"DesiredCount": 1,
			"PlacementStrategy": null,
			"Status": "ACTIVE",
			"RoleArn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
			"PropagateTags": "NONE",
			"Deployments": [
				{
					"Status": "PRIMARY",
					"CreatedAt": "2020-06-05T20:58:55Z",
					"RunningCount": 1,
					"Id": "ecs-svc/6871675624579221172",
					"PendingCount": 0,
					"NetworkConfiguration": {
						"AwsvpcConfiguration": {
							"Subnets": [
								"subnet-039f9387",
								"subnet-039f9388"
							],
							"AssignPublicIp": "ENABLED",
							"SecurityGroups": [
								"sg-000fff8888889cb03"
							]
						}
					},
					"CapacityProviderStrategy": null,
					"DesiredCount": 1,
					"UpdatedAt": "2020-06-05T21:00:17Z",
					"PlatformVersion": "1.3.0",
					"TaskDefinition": "arn:aws:ecs:us-east-1:123456789012:task-definition/panther-web:11",
					"LaunchType": "FARGATE"
				}
			],
			"SchedulingStrategy": "REPLICA",
			"PlacementConstraints": null,
			"EnableECSManagedTags": false,
			"CreatedBy": null,
			"RunningCount": 1,
			"Tags": null,
			"Events": [				
				{
					"Message": "(service panther-web) has started 1 tasks: (task ad06758c-9c2b-42ca-9ddb-9aaab7e50b09).",
					"CreatedAt": "2020-06-03T21:06:26Z",
					"Id": "b3d231c8-9609-49f4-93f5-3d4c31b8940a"
				}
			],
			"PendingCount": 0,
			"Arn": "arn:aws:ecs:us-east-1:123456789012:service/panther-web",
			"PlatformVersion": "LATEST",
			"Region": null,
			"CapacityProviderStrategy": null,
			"LaunchType": "FARGATE",
			"Name": "panther-web",
			"DeploymentConfiguration": {
				"MaximumPercent": 200,
				"MinimumHealthyPercent": 50
			},
			"LoadBalancers": [
				{
					"LoadBalancerName": null,
					"ContainerName": "panther-web",
					"ContainerPort": 80,
					"TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/panther-web/49c89eed5dfd4dc0"
				}
			],
			"HealthCheckGracePeriodSeconds": 60,
			"DeploymentController": null,
			"AccountId": null
		}
	],
	"Tags": {
		"Application": "Panther",
		"PantherEdition": "Enterprise",
		"Stack": "panther-web",
		"PantherVersion": "v1.4.0"
	},
	"DefaultCapacityProviderStrategy": null
}
```
