/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { SeverityEnum } from 'Generated/schema';
import { BadgeProps } from 'pouncejs';

export const AWS_ACCOUNT_ID_REGEX = new RegExp('^\\d{12}$');

export const INCLUDE_DIGITS_REGEX = new RegExp('(?=.*[0-9])');

export const INCLUDE_LOWERCASE_REGEX = new RegExp('(?=.*[a-z])');

export const INCLUDE_UPPERCASE_REGEX = new RegExp('(?=.*[A-Z])');

export const INCLUDE_SPECIAL_CHAR_REGEX = new RegExp('(?=.*[!@#\\$%\\^&\\*;:,.<>?/])');

export const DEFAULT_POLICY_FUNCTION =
  'def policy(resource):\n\t# Write your code here.\n\treturn True';

export const DEFAULT_RULE_FUNCTION = 'def rule(event):\n\t# Write your code here.\n\treturn False';

export const RESOURCE_TYPES = [
  'AWS.ACM.Certificate',
  'AWS.CloudFormation.Stack',
  'AWS.CloudTrail',
  'AWS.CloudTrail.Meta',
  'AWS.CloudWatch.LogGroup',
  'AWS.Config.Recorder',
  'AWS.Config.Recorder.Meta',
  'AWS.DynamoDB.Table',
  'AWS.EC2.AMI',
  'AWS.EC2.Instance',
  'AWS.EC2.NetworkACL',
  'AWS.EC2.SecurityGroup',
  'AWS.EC2.Volume',
  'AWS.EC2.VPC',
  'AWS.ECS.Cluster',
  'AWS.ELBV2.ApplicationLoadBalancer',
  'AWS.GuardDuty.Detector',
  'AWS.IAM.Group',
  'AWS.IAM.Policy',
  'AWS.IAM.Role',
  'AWS.IAM.RootUser',
  'AWS.IAM.User',
  'AWS.KMS.Key',
  'AWS.Lambda.Function',
  'AWS.PasswordPolicy',
  'AWS.RDS.Instance',
  'AWS.Redshift.Cluster',
  'AWS.S3.Bucket',
  'AWS.WAF.Regional.WebACL',
  'AWS.WAF.WebACL',
] as const;

export const LOG_TYPES = [
  'AWS.ALB',
  'AWS.AuroraMySQLAudit',
  'AWS.CloudTrail',
  'AWS.GuardDuty',
  'AWS.S3ServerAccess',
  'AWS.VPCFlow',
  'Nginx.Access',
  'Osquery.Batch',
  'Osquery.Differential',
  'Osquery.Snapshot',
  'Osquery.Status',
  'OSSEC.EventInfo',
] as const;

export const SEVERITY_COLOR_MAP: { [key in SeverityEnum]: BadgeProps['color'] } = {
  [SeverityEnum.Critical]: 'red' as const,
  [SeverityEnum.High]: 'pink' as const,
  [SeverityEnum.Medium]: 'blue' as const,
  [SeverityEnum.Low]: 'grey' as const,
  [SeverityEnum.Info]: 'neutral' as const,
};

export const PANTHER_SCHEMA_DOCS_LINK = 'https://docs.runpanther.io';

export const DEFAULT_SMALL_PAGE_SIZE = 10;
export const DEFAULT_LARGE_PAGE_SIZE = 25;

// The key under which User-related data will be stored in the storage
export const USER_INFO_STORAGE_KEY = 'panther.user.info';
export const ERROR_REPORTING_CONSENT_STORAGE_KEY = 'panther.generalSettings.errorReportingConsent';

export enum INTEGRATION_TYPES {
  AWS_LOGS = 'aws-s3',
  AWS_INFRA = 'aws-scan',
}
