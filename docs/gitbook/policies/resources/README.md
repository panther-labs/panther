---
description: >-
  This page will walk you through the most common attributes that can be
  referenced in any policy.
---

# Resource Types

## Background

A **Resource** is an entity within your AWS account, such as an EC2 Instance, S3 Bucket, IAM User, and more.

A **Meta Resource** provides context on a given service for an entire account, which is useful in understanding whether or not it is configured. For example, the CloudTrail Meta resource allows you to ensure at least one CloudTrail is setup in an account.

When you first connect your account to Panther, all resources are scanned and evaluated against the defined policies. The schema for each resource is defined in the nested sections which include all attributes with their descriptions.

## Common Fields

The following Attributes are common across all resources and can be referenced in any Policy:

| Field Name     | Description                                                                                                                                                                                                     |
| :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AccountId`    | The ID of the AWS Account the resource resides in                                                                                                                                                               |
| `Arn`          | The fully qualified Amazon Resource Name, if one exists                                                                                                                                                         |
| `Id`           | The AWS unique identifier, if one exists                                                                                                                                                                        |
| `Name`         | The AWS name, if one exists                                                                                                                                                                                     |
| `Region`       | The region the resource exists in, with a value of `GLOBAL_REGION` if the resource is not regional                                                                                                              |
| `ResourceId`   | The Panther unique identifier                                                                                                                                                                                   |
| `ResourceType` | The categorization of the resource, such as `AWS.EC2.Instance`                                                                                                                                                  |
| `Tags`         | A map of key/value pair labels that may be assigned to an AWS resource, when any exist                                                                                                                          |
| `TimeCreated`  | An [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp of when the resource was created. This is not set if the information is not provided by the AWS API or if not applicable, such as in Meta resources |
