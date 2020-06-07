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

import { SeverityEnum } from 'Generated/schema';
import { BadgeProps } from 'pouncejs';
import { generateDocUrl } from 'Helpers/utils';
import { pantherConfig } from 'Source/config';

export enum LogIntegrationsEnum {
  's3' = 'aws-s3',
}

export const AWS_ACCOUNT_ID_REGEX = new RegExp('^\\d{12}$');

export const S3_BUCKET_NAME_REGEX = new RegExp(
  '(?=^.{3,63}$)(^(([a-z0-9]|[a-z0-9][a-z0-9\\-]*[a-z0-9])\\.)*([a-z0-9]|[a-z0-9][a-z0-9\\-]*[a-z0-9])$)'
);

export const INCLUDE_DIGITS_REGEX = new RegExp('(?=.*[0-9])');

export const INCLUDE_LOWERCASE_REGEX = new RegExp('(?=.*[a-z])');

export const SOURCE_LABEL_REGEX = new RegExp('^[a-zA-Z0-9- ]+$');

export const INCLUDE_UPPERCASE_REGEX = new RegExp('(?=.*[A-Z])');

export const INCLUDE_SPECIAL_CHAR_REGEX = new RegExp('[^\\d\\sA-Za-z]');

export const CHECK_IF_HASH_REGEX = new RegExp('[a-f0-9]{32}');

export const DEFAULT_POLICY_FUNCTION =
  'def policy(resource):\n\t# Return False if the resource is non-compliant, which will trigger alerts/remediation.\n\treturn True';

export const DEFAULT_RULE_FUNCTION =
  'def rule(event):\n\t# Return True to match the log event and trigger an alert.\n\treturn False';

export const DEFAULT_TITLE_FUNCTION =
  "def title(event):\n\t# (Optional) Return a string which will be shown as the alert title.\n\treturn ''";

export const DEFAULT_DEDUP_FUNCTION =
  "def dedup(event):\n\t# (Optional) Return a string which will de-duplicate similar alerts.\n\treturn ''";

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
  'Apache.AccessCombined',
  'Apache.AccessCommon',
  'AWS.ALB',
  'AWS.AuroraMySQLAudit',
  'AWS.CloudTrail',
  'AWS.CloudTrailDigest',
  'AWS.CloudTrailInsight',
  'AWS.GuardDuty',
  'AWS.S3ServerAccess',
  'AWS.VPCFlow',
  'Fluentd.Syslog3164',
  'Fluentd.Syslog5424',
  'GitLab.API',
  'GitLab.Audit',
  'GitLab.Exceptions',
  'GitLab.Git',
  'GitLab.Integrations',
  'GitLab.Production',
  'Nginx.Access',
  'Osquery.Batch',
  'Osquery.Differential',
  'Osquery.Snapshot',
  'Osquery.Status',
  'OSSEC.EventInfo',
  'Suricata.Anomaly',
  'Suricata.DNS',
  'Syslog.RFC3164',
  'Syslog.RFC5424',
] as const;

export const SEVERITY_COLOR_MAP: { [key in SeverityEnum]: BadgeProps['color'] } = {
  [SeverityEnum.Critical]: 'red' as const,
  [SeverityEnum.High]: 'pink' as const,
  [SeverityEnum.Medium]: 'blue' as const,
  [SeverityEnum.Low]: 'grey' as const,
  [SeverityEnum.Info]: 'neutral' as const,
};

export const PANTHER_SCHEMA_DOCS_MASTER_LINK = 'https://docs.runpanther.io';

export const PANTHER_SCHEMA_DOCS_LINK = generateDocUrl(
  PANTHER_SCHEMA_DOCS_MASTER_LINK,
  pantherConfig.PANTHER_VERSION
);

export const DEFAULT_SMALL_PAGE_SIZE = 10;
export const DEFAULT_LARGE_PAGE_SIZE = 25;

// The key under which User-related data will be stored in the storage
export const USER_INFO_STORAGE_KEY = 'panther.user.info';
export const ERROR_REPORTING_CONSENT_STORAGE_KEY = 'panther.generalSettings.errorReportingConsent';

// The default panther system user id
export const PANTHER_USER_ID = '00000000-0000-4000-8000-000000000000';
// Docs URL we use to prompt users for explanations
export const LOG_ONBOARDING_DOC_URL = `https://docs.runpanther.io/log-processing#sns-notification-setup`;
