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

import { pantherConfig } from 'Source/config';
import slackLogo from 'Assets/slack-minimal-logo.svg';
import { DestinationTypeEnum, DetectionTypeEnum, SeverityEnum } from 'Generated/schema';
import msTeamsLogo from 'Assets/ms-teams-minimal-logo.svg';
import opsgenieLogo from 'Assets/opsgenie-minimal-logo.svg';
import jiraLogo from 'Assets/jira-minimal-logo.svg';
import githubLogo from 'Assets/github-minimal-logo.svg';
import pagerDutyLogo from 'Assets/pagerduty-minimal-logo.svg';
import snsLogo from 'Assets/aws-sns-minimal-logo.svg';
import sqsLogo from 'Assets/aws-sqs-minimal-logo.svg';
import asanaLogo from 'Assets/asana-minimal-logo.svg';
import customWebhook from 'Assets/custom-webhook-minimal-logo.svg';
import { Theme } from 'pouncejs';

export enum LogIntegrationsEnum {
  's3' = 'aws-s3',
  'sqs' = 'aws-sqs',
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
  "def title(event):\n\t# (Optional) Return a string which will be shown as the alert title.\n\t# If no 'dedup' function is defined, the return value of this method will act as deduplication string.\n\treturn ''";

export const DEFAULT_DEDUP_FUNCTION =
  "# def dedup(event):\n\t#  (Optional) Return a string which will be used to deduplicate similar alerts.\n\t# return ''";

export const DEFAULT_ALERT_CONTEXT_FUNCTION =
  "# def alert_context(event):\n\t#  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination\n\t# return {'key':'value'}";

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
  'AWS.EKS.Cluster',
  'AWS.ELBV2.ApplicationLoadBalancer',
  'AWS.GuardDuty.Detector',
  'AWS.GuardDuty.Detector.Meta',
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

export const AWS_REGIONS = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'af-south-1',
  'ap-east-1',
  'ap-south-1',
  'ap-northeast-1',
  'ap-northeast-2',
  'ap-northeast-3',
  'ap-southeast-1',
  'ap-southeast-2',
  'ca-central-1',
  'cn-north-1',
  'cn-northwest-1',
  'eu-central-1',
  'eu-west-1',
  'eu-west-2',
  'eu-west-3',
  'eu-south-1',
  'eu-north-1',
  'me-south-1',
  'sa-east-1',
  'us-gov-east-1',
  'us-gov-west-1',
] as const;

const VERSION_PARTS = pantherConfig.PANTHER_VERSION.split('.'); // ["1", "7", "1]
export const PANTHER_DOCS_LINK = `https://docs.runpanther.io/v/release-${VERSION_PARTS[0]}.${VERSION_PARTS[1]}`;

export const ANALYSIS_UPLOAD_DOC_URL = `${PANTHER_DOCS_LINK}/user-guide/analysis/panther-analysis-tool#uploading-to-panther`;
export const CLOUD_SECURITY_REAL_TIME_DOC_URL = `${PANTHER_DOCS_LINK}/cloud-security/setup#configure-real-time-monitoring`;
export const LOG_ONBOARDING_SNS_DOC_URL = `${PANTHER_DOCS_LINK}/log-analysis/setup#setup-notifications-of-new-data`;
export const PRIVACY_DOC_URL = `${PANTHER_DOCS_LINK}/user-guide/help/security-privacy#privacy`;
export const CUSTOM_LOG_TYPES_DOC_URL = `${PANTHER_DOCS_LINK}/enterprise/custom-log-types`;
export const REMEDIATION_DOC_URL = `${PANTHER_DOCS_LINK}/cloud-security/automatic-remediation#overview`;
// End of doc URLs section

export const DEFAULT_SMALL_PAGE_SIZE = 10;
export const DEFAULT_LARGE_PAGE_SIZE = 25;

// The key under which User-related data will be stored in the storage
export const USER_INFO_STORAGE_KEY = 'panther.user.info';
export const ERROR_REPORTING_CONSENT_STORAGE_KEY = 'panther.generalSettings.errorReportingConsent';
export const ANALYTICS_CONSENT_STORAGE_KEY = 'panther.generalSettings.analyticsConsent';

// The default panther system user id
export const PANTHER_USER_ID = '00000000-0000-4000-8000-000000000000';

export const DEFAULT_SENSITIVE_VALUE = '*******************';

export const DESTINATIONS: Record<
  DestinationTypeEnum,
  { logo: string; title: string; type: DestinationTypeEnum }
> = {
  [DestinationTypeEnum.Slack]: {
    logo: slackLogo,
    title: 'Slack',
    type: DestinationTypeEnum.Slack,
  },
  [DestinationTypeEnum.Msteams]: {
    logo: msTeamsLogo,
    title: 'Microsoft Teams',
    type: DestinationTypeEnum.Msteams,
  },
  [DestinationTypeEnum.Opsgenie]: {
    logo: opsgenieLogo,
    title: 'Opsgenie',
    type: DestinationTypeEnum.Opsgenie,
  },
  [DestinationTypeEnum.Jira]: {
    logo: jiraLogo,
    title: 'Jira',
    type: DestinationTypeEnum.Jira,
  },
  [DestinationTypeEnum.Github]: {
    logo: githubLogo,
    title: 'Github',
    type: DestinationTypeEnum.Github,
  },
  [DestinationTypeEnum.Pagerduty]: {
    logo: pagerDutyLogo,
    title: 'PagerDuty',
    type: DestinationTypeEnum.Pagerduty,
  },
  [DestinationTypeEnum.Sns]: {
    logo: snsLogo,
    title: 'AWS SNS',
    type: DestinationTypeEnum.Sns,
  },
  [DestinationTypeEnum.Sqs]: {
    logo: sqsLogo,
    title: 'AWS SQS',
    type: DestinationTypeEnum.Sqs,
  },
  [DestinationTypeEnum.Asana]: {
    logo: asanaLogo,
    title: 'Asana',
    type: DestinationTypeEnum.Asana,
  },
  [DestinationTypeEnum.Customwebhook]: {
    logo: customWebhook,
    title: 'Custom Webhook',
    type: DestinationTypeEnum.Customwebhook,
  },
};

export const SEVERITY_COLOR_MAP: { [key in SeverityEnum]: keyof Theme['colors'] } = {
  [SeverityEnum.Critical]: 'red-400' as const,
  [SeverityEnum.High]: 'orange-500' as const,
  [SeverityEnum.Medium]: 'yellow-500' as const,
  [SeverityEnum.Low]: 'blue-300' as const,
  [SeverityEnum.Info]: 'gray-300' as const,
};

export const DETECTION_TYPE_COLOR_MAP: {
  [key in DetectionTypeEnum | 'GLOBAL']: keyof Theme['colors'];
} = {
  [DetectionTypeEnum.Policy]: 'indigo-300' as const,
  [DetectionTypeEnum.Rule]: 'cyan-500' as const,
  GLOBAL: 'green-200' as const,
};
