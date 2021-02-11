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

import { GraphQLResolveInfo, GraphQLScalarType, GraphQLScalarTypeConfig } from 'graphql';
export type Maybe<T> = T | null;
export type Omit<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>>;
export type RequireFields<T, K extends keyof T> = { [X in Exclude<keyof T, K>]?: T[X] } &
  { [P in K]-?: NonNullable<T[P]> };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: string;
  String: string;
  Boolean: boolean;
  Int: number;
  Float: number;
  AWSDateTime: string;
  AWSJSON: string;
  Long: number;
  AWSEmail: string;
  AWSTimestamp: number;
};

export enum AccountTypeEnum {
  Aws = 'aws',
}

export type ActiveSuppressCount = {
  __typename?: 'ActiveSuppressCount';
  active?: Maybe<ComplianceStatusCounts>;
  suppressed?: Maybe<ComplianceStatusCounts>;
};

export type AddComplianceIntegrationInput = {
  awsAccountId: Scalars['String'];
  integrationLabel: Scalars['String'];
  remediationEnabled?: Maybe<Scalars['Boolean']>;
  cweEnabled?: Maybe<Scalars['Boolean']>;
  regionIgnoreList?: Maybe<Array<Scalars['String']>>;
  resourceTypeIgnoreList?: Maybe<Array<Scalars['String']>>;
};

export type AddGlobalPythonModuleInput = {
  id: Scalars['ID'];
  description: Scalars['String'];
  body: Scalars['String'];
};

export type AddOrUpdateCustomLogInput = {
  revision?: Maybe<Scalars['Int']>;
  logType: Scalars['String'];
  description: Scalars['String'];
  referenceURL: Scalars['String'];
  logSpec: Scalars['String'];
};

export type AddOrUpdateDataModelInput = {
  displayName: Scalars['String'];
  id: Scalars['ID'];
  enabled: Scalars['Boolean'];
  logTypes: Array<Scalars['String']>;
  mappings: Array<DataModelMappingInput>;
  body?: Maybe<Scalars['String']>;
};

export type AddPolicyInput = {
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  body: Scalars['String'];
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  outputIds?: Maybe<Array<Scalars['ID']>>;
  reference?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  suppressions?: Maybe<Array<Maybe<Scalars['String']>>>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<DetectionTestDefinitionInput>>>;
};

export type AddRuleInput = {
  body: Scalars['String'];
  dedupPeriodMinutes: Scalars['Int'];
  threshold: Scalars['Int'];
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  logTypes?: Maybe<Array<Scalars['String']>>;
  outputIds?: Maybe<Array<Scalars['ID']>>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  tags?: Maybe<Array<Scalars['String']>>;
  tests?: Maybe<Array<DetectionTestDefinitionInput>>;
};

export type AddS3LogIntegrationInput = {
  awsAccountId: Scalars['String'];
  integrationLabel: Scalars['String'];
  s3Bucket: Scalars['String'];
  kmsKey?: Maybe<Scalars['String']>;
  s3PrefixLogTypes: Array<S3PrefixLogTypesInput>;
  managedBucketNotifications: Scalars['Boolean'];
};

export type AddSqsLogIntegrationInput = {
  integrationLabel: Scalars['String'];
  sqsConfig: SqsLogConfigInput;
};

export type Alert = {
  alertId: Scalars['ID'];
  creationTime: Scalars['AWSDateTime'];
  deliveryResponses: Array<Maybe<DeliveryResponse>>;
  severity: SeverityEnum;
  status: AlertStatusesEnum;
  title: Scalars['String'];
  type: AlertTypesEnum;
  lastUpdatedBy?: Maybe<Scalars['ID']>;
  lastUpdatedByTime?: Maybe<Scalars['AWSDateTime']>;
  updateTime: Scalars['AWSDateTime'];
};

export type AlertDetails = Alert & {
  __typename?: 'AlertDetails';
  alertId: Scalars['ID'];
  creationTime: Scalars['AWSDateTime'];
  deliveryResponses: Array<Maybe<DeliveryResponse>>;
  severity: SeverityEnum;
  status: AlertStatusesEnum;
  title: Scalars['String'];
  type: AlertTypesEnum;
  lastUpdatedBy?: Maybe<Scalars['ID']>;
  lastUpdatedByTime?: Maybe<Scalars['AWSDateTime']>;
  updateTime: Scalars['AWSDateTime'];
  detection: AlertDetailsDetectionInfo;
  description?: Maybe<Scalars['String']>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
};

export type AlertDetailsDetectionInfo = AlertDetailsRuleInfo | AlertSummaryPolicyInfo;

export type AlertDetailsRuleInfo = {
  __typename?: 'AlertDetailsRuleInfo';
  ruleId?: Maybe<Scalars['ID']>;
  logTypes: Array<Scalars['String']>;
  eventsMatched: Scalars['Int'];
  dedupString: Scalars['String'];
  events: Array<Scalars['AWSJSON']>;
  eventsLastEvaluatedKey?: Maybe<Scalars['String']>;
};

export enum AlertStatusesEnum {
  Open = 'OPEN',
  Triaged = 'TRIAGED',
  Closed = 'CLOSED',
  Resolved = 'RESOLVED',
}

export type AlertSummary = Alert & {
  __typename?: 'AlertSummary';
  alertId: Scalars['ID'];
  creationTime: Scalars['AWSDateTime'];
  deliveryResponses: Array<Maybe<DeliveryResponse>>;
  type: AlertTypesEnum;
  severity: SeverityEnum;
  status: AlertStatusesEnum;
  title: Scalars['String'];
  lastUpdatedBy?: Maybe<Scalars['ID']>;
  lastUpdatedByTime?: Maybe<Scalars['AWSDateTime']>;
  updateTime: Scalars['AWSDateTime'];
  detection: AlertSummaryDetectionInfo;
};

export type AlertSummaryDetectionInfo = AlertSummaryRuleInfo | AlertSummaryPolicyInfo;

export type AlertSummaryPolicyInfo = {
  __typename?: 'AlertSummaryPolicyInfo';
  policyId?: Maybe<Scalars['ID']>;
  resourceId?: Maybe<Scalars['String']>;
  policySourceId: Scalars['String'];
  resourceTypes: Array<Scalars['String']>;
};

export type AlertSummaryRuleInfo = {
  __typename?: 'AlertSummaryRuleInfo';
  ruleId?: Maybe<Scalars['ID']>;
  logTypes: Array<Scalars['String']>;
  eventsMatched: Scalars['Int'];
};

export enum AlertTypesEnum {
  Rule = 'RULE',
  RuleError = 'RULE_ERROR',
  Policy = 'POLICY',
}

export type AsanaConfig = {
  __typename?: 'AsanaConfig';
  personalAccessToken: Scalars['String'];
  projectGids: Array<Scalars['String']>;
};

export type AsanaConfigInput = {
  personalAccessToken: Scalars['String'];
  projectGids: Array<Scalars['String']>;
};

export type ComplianceIntegration = {
  __typename?: 'ComplianceIntegration';
  awsAccountId: Scalars['String'];
  createdAtTime: Scalars['AWSDateTime'];
  createdBy: Scalars['ID'];
  integrationId: Scalars['ID'];
  integrationLabel: Scalars['String'];
  cweEnabled?: Maybe<Scalars['Boolean']>;
  remediationEnabled?: Maybe<Scalars['Boolean']>;
  regionIgnoreList?: Maybe<Array<Scalars['String']>>;
  resourceTypeIgnoreList?: Maybe<Array<Scalars['String']>>;
  health: ComplianceIntegrationHealth;
  stackName: Scalars['String'];
};

export type ComplianceIntegrationHealth = {
  __typename?: 'ComplianceIntegrationHealth';
  auditRoleStatus: IntegrationItemHealthStatus;
  cweRoleStatus: IntegrationItemHealthStatus;
  remediationRoleStatus: IntegrationItemHealthStatus;
};

export type ComplianceItem = {
  __typename?: 'ComplianceItem';
  errorMessage?: Maybe<Scalars['String']>;
  lastUpdated?: Maybe<Scalars['AWSDateTime']>;
  policyId?: Maybe<Scalars['ID']>;
  policySeverity?: Maybe<SeverityEnum>;
  resourceId?: Maybe<Scalars['ID']>;
  resourceType?: Maybe<Scalars['String']>;
  status?: Maybe<ComplianceStatusEnum>;
  suppressed?: Maybe<Scalars['Boolean']>;
  integrationId?: Maybe<Scalars['ID']>;
};

export type ComplianceStatusCounts = {
  __typename?: 'ComplianceStatusCounts';
  error?: Maybe<Scalars['Int']>;
  fail?: Maybe<Scalars['Int']>;
  pass?: Maybe<Scalars['Int']>;
};

export enum ComplianceStatusEnum {
  Error = 'ERROR',
  Fail = 'FAIL',
  Pass = 'PASS',
}

export type CustomLogOutput = {
  __typename?: 'CustomLogOutput';
  error?: Maybe<Error>;
  record?: Maybe<CustomLogRecord>;
};

export type CustomLogRecord = {
  __typename?: 'CustomLogRecord';
  logType: Scalars['String'];
  revision: Scalars['Int'];
  updatedAt: Scalars['String'];
  description: Scalars['String'];
  referenceURL: Scalars['String'];
  logSpec: Scalars['String'];
};

export type CustomWebhookConfig = {
  __typename?: 'CustomWebhookConfig';
  webhookURL: Scalars['String'];
};

export type CustomWebhookConfigInput = {
  webhookURL: Scalars['String'];
};

export type DataModel = {
  __typename?: 'DataModel';
  displayName: Scalars['String'];
  id: Scalars['ID'];
  enabled: Scalars['Boolean'];
  logTypes: Array<Scalars['String']>;
  mappings: Array<DataModelMapping>;
  body?: Maybe<Scalars['String']>;
  createdAt: Scalars['AWSDateTime'];
  lastModified: Scalars['AWSDateTime'];
};

export type DataModelMapping = {
  __typename?: 'DataModelMapping';
  name: Scalars['String'];
  path?: Maybe<Scalars['String']>;
  method?: Maybe<Scalars['String']>;
};

export type DataModelMappingInput = {
  name: Scalars['String'];
  path?: Maybe<Scalars['String']>;
  method?: Maybe<Scalars['String']>;
};

export type DeleteCustomLogInput = {
  logType: Scalars['String'];
  revision: Scalars['Int'];
};

export type DeleteCustomLogOutput = {
  __typename?: 'DeleteCustomLogOutput';
  error?: Maybe<Error>;
};

export type DeleteDataModelInput = {
  dataModels: Array<DeleteEntry>;
};

export type DeleteDetectionInput = {
  detections: Array<DeleteEntry>;
};

export type DeleteEntry = {
  id: Scalars['ID'];
};

export type DeleteGlobalPythonModuleInput = {
  globals: Array<DeleteEntry>;
};

export type DeliverAlertInput = {
  alertId: Scalars['ID'];
  outputIds: Array<Scalars['ID']>;
};

export type DeliveryResponse = {
  __typename?: 'DeliveryResponse';
  outputId: Scalars['ID'];
  message: Scalars['String'];
  statusCode: Scalars['Int'];
  success: Scalars['Boolean'];
  dispatchedAt: Scalars['AWSDateTime'];
};

export type Destination = {
  __typename?: 'Destination';
  createdBy: Scalars['String'];
  creationTime: Scalars['AWSDateTime'];
  displayName: Scalars['String'];
  lastModifiedBy: Scalars['String'];
  lastModifiedTime: Scalars['AWSDateTime'];
  outputId: Scalars['ID'];
  outputType: DestinationTypeEnum;
  outputConfig: DestinationConfig;
  verificationStatus?: Maybe<Scalars['String']>;
  defaultForSeverity: Array<Maybe<SeverityEnum>>;
  alertTypes: Array<AlertTypesEnum>;
};

export type DestinationConfig = {
  __typename?: 'DestinationConfig';
  slack?: Maybe<SlackConfig>;
  sns?: Maybe<SnsConfig>;
  sqs?: Maybe<SqsDestinationConfig>;
  pagerDuty?: Maybe<PagerDutyConfig>;
  github?: Maybe<GithubConfig>;
  jira?: Maybe<JiraConfig>;
  opsgenie?: Maybe<OpsgenieConfig>;
  msTeams?: Maybe<MsTeamsConfig>;
  asana?: Maybe<AsanaConfig>;
  customWebhook?: Maybe<CustomWebhookConfig>;
};

export type DestinationConfigInput = {
  slack?: Maybe<SlackConfigInput>;
  sns?: Maybe<SnsConfigInput>;
  sqs?: Maybe<SqsConfigInput>;
  pagerDuty?: Maybe<PagerDutyConfigInput>;
  github?: Maybe<GithubConfigInput>;
  jira?: Maybe<JiraConfigInput>;
  opsgenie?: Maybe<OpsgenieConfigInput>;
  msTeams?: Maybe<MsTeamsConfigInput>;
  asana?: Maybe<AsanaConfigInput>;
  customWebhook?: Maybe<CustomWebhookConfigInput>;
};

export type DestinationInput = {
  outputId?: Maybe<Scalars['ID']>;
  displayName: Scalars['String'];
  outputConfig: DestinationConfigInput;
  outputType: Scalars['String'];
  defaultForSeverity: Array<Maybe<SeverityEnum>>;
  alertTypes: Array<Maybe<AlertTypesEnum>>;
};

export enum DestinationTypeEnum {
  Slack = 'slack',
  Pagerduty = 'pagerduty',
  Github = 'github',
  Jira = 'jira',
  Opsgenie = 'opsgenie',
  Msteams = 'msteams',
  Sns = 'sns',
  Sqs = 'sqs',
  Asana = 'asana',
  Customwebhook = 'customwebhook',
}

export type Detection = {
  body: Scalars['String'];
  createdAt: Scalars['AWSDateTime'];
  createdBy?: Maybe<Scalars['ID']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  lastModifiedBy?: Maybe<Scalars['ID']>;
  outputIds: Array<Scalars['ID']>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  tags: Array<Scalars['String']>;
  tests: Array<DetectionTestDefinition>;
  versionId?: Maybe<Scalars['ID']>;
  analysisType: DetectionTypeEnum;
};

export type DetectionTestDefinition = {
  __typename?: 'DetectionTestDefinition';
  expectedResult?: Maybe<Scalars['Boolean']>;
  name?: Maybe<Scalars['String']>;
  resource?: Maybe<Scalars['String']>;
};

export type DetectionTestDefinitionInput = {
  expectedResult?: Maybe<Scalars['Boolean']>;
  name?: Maybe<Scalars['String']>;
  resource?: Maybe<Scalars['String']>;
};

export enum DetectionTypeEnum {
  Rule = 'RULE',
  Policy = 'POLICY',
}

export type DetectionTypes = {
  __typename?: 'DetectionTypes';
  GLOBAL: Scalars['Int'];
  RULE: Scalars['Int'];
  POLICY: Scalars['Int'];
};

export type Error = {
  __typename?: 'Error';
  code?: Maybe<Scalars['String']>;
  message: Scalars['String'];
};

export enum ErrorCodeEnum {
  NotFound = 'NotFound',
}

export type FloatSeries = {
  __typename?: 'FloatSeries';
  label: Scalars['String'];
  values: Array<Scalars['Float']>;
};

export type FloatSeriesData = {
  __typename?: 'FloatSeriesData';
  timestamps: Array<Scalars['AWSDateTime']>;
  series: Array<FloatSeries>;
};

export type GeneralSettings = {
  __typename?: 'GeneralSettings';
  displayName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['String']>;
  errorReportingConsent?: Maybe<Scalars['Boolean']>;
  analyticsConsent?: Maybe<Scalars['Boolean']>;
};

export type GetAlertInput = {
  alertId: Scalars['ID'];
  eventsPageSize?: Maybe<Scalars['Int']>;
  eventsExclusiveStartKey?: Maybe<Scalars['String']>;
};

export type GetComplianceIntegrationTemplateInput = {
  awsAccountId: Scalars['String'];
  integrationLabel: Scalars['String'];
  remediationEnabled?: Maybe<Scalars['Boolean']>;
  cweEnabled?: Maybe<Scalars['Boolean']>;
};

export type GetCustomLogInput = {
  logType: Scalars['String'];
  revision?: Maybe<Scalars['Int']>;
};

export type GetCustomLogOutput = {
  __typename?: 'GetCustomLogOutput';
  error?: Maybe<Error>;
  record?: Maybe<CustomLogRecord>;
};

export type GetGlobalPythonModuleInput = {
  id: Scalars['ID'];
  versionId?: Maybe<Scalars['ID']>;
};

export type GetPolicyInput = {
  id: Scalars['ID'];
  versionId?: Maybe<Scalars['ID']>;
};

export type GetResourceInput = {
  resourceId: Scalars['ID'];
};

export type GetRuleInput = {
  id: Scalars['ID'];
  versionId?: Maybe<Scalars['ID']>;
};

export type GetS3LogIntegrationTemplateInput = {
  awsAccountId: Scalars['String'];
  integrationLabel: Scalars['String'];
  s3Bucket: Scalars['String'];
  kmsKey?: Maybe<Scalars['String']>;
  managedBucketNotifications: Scalars['Boolean'];
};

export type GithubConfig = {
  __typename?: 'GithubConfig';
  repoName: Scalars['String'];
  token: Scalars['String'];
};

export type GithubConfigInput = {
  repoName: Scalars['String'];
  token: Scalars['String'];
};

export type GlobalPythonModule = {
  __typename?: 'GlobalPythonModule';
  body: Scalars['String'];
  description: Scalars['String'];
  id: Scalars['ID'];
  createdAt: Scalars['AWSDateTime'];
  lastModified: Scalars['AWSDateTime'];
};

export type IntegrationItemHealthStatus = {
  __typename?: 'IntegrationItemHealthStatus';
  healthy: Scalars['Boolean'];
  message: Scalars['String'];
  rawErrorMessage?: Maybe<Scalars['String']>;
};

export type IntegrationTemplate = {
  __typename?: 'IntegrationTemplate';
  body: Scalars['String'];
  stackName: Scalars['String'];
};

export type InviteUserInput = {
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['AWSEmail']>;
  messageAction?: Maybe<MessageActionEnum>;
};

export type JiraConfig = {
  __typename?: 'JiraConfig';
  orgDomain: Scalars['String'];
  projectKey: Scalars['String'];
  userName: Scalars['String'];
  apiKey: Scalars['String'];
  assigneeId?: Maybe<Scalars['String']>;
  issueType: Scalars['String'];
  labels: Array<Scalars['String']>;
};

export type JiraConfigInput = {
  orgDomain: Scalars['String'];
  projectKey: Scalars['String'];
  userName: Scalars['String'];
  apiKey: Scalars['String'];
  assigneeId?: Maybe<Scalars['String']>;
  issueType: Scalars['String'];
  labels?: Maybe<Array<Scalars['String']>>;
};

export type ListAlertsInput = {
  ruleId?: Maybe<Scalars['ID']>;
  pageSize?: Maybe<Scalars['Int']>;
  exclusiveStartKey?: Maybe<Scalars['String']>;
  severity?: Maybe<Array<Maybe<SeverityEnum>>>;
  logTypes?: Maybe<Array<Scalars['String']>>;
  resourceTypes?: Maybe<Array<Scalars['String']>>;
  types?: Maybe<Array<AlertTypesEnum>>;
  nameContains?: Maybe<Scalars['String']>;
  createdAtBefore?: Maybe<Scalars['AWSDateTime']>;
  createdAtAfter?: Maybe<Scalars['AWSDateTime']>;
  status?: Maybe<Array<Maybe<AlertStatusesEnum>>>;
  eventCountMin?: Maybe<Scalars['Int']>;
  eventCountMax?: Maybe<Scalars['Int']>;
  sortBy?: Maybe<ListAlertsSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
};

export type ListAlertsResponse = {
  __typename?: 'ListAlertsResponse';
  alertSummaries: Array<Maybe<AlertSummary>>;
  lastEvaluatedKey?: Maybe<Scalars['String']>;
};

export enum ListAlertsSortFieldsEnum {
  CreatedAt = 'createdAt',
}

export type ListAvailableLogTypesResponse = {
  __typename?: 'ListAvailableLogTypesResponse';
  logTypes: Array<Scalars['String']>;
};

export type ListComplianceItemsResponse = {
  __typename?: 'ListComplianceItemsResponse';
  items?: Maybe<Array<Maybe<ComplianceItem>>>;
  paging?: Maybe<PagingData>;
  status?: Maybe<ComplianceStatusEnum>;
  totals?: Maybe<ActiveSuppressCount>;
};

export type ListDataModelsInput = {
  enabled?: Maybe<Scalars['Boolean']>;
  nameContains?: Maybe<Scalars['String']>;
  logTypes?: Maybe<Array<Scalars['String']>>;
  sortBy?: Maybe<ListDataModelsSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  page?: Maybe<Scalars['Int']>;
  pageSize?: Maybe<Scalars['Int']>;
};

export type ListDataModelsResponse = {
  __typename?: 'ListDataModelsResponse';
  models: Array<DataModel>;
  paging: PagingData;
};

export enum ListDataModelsSortFieldsEnum {
  Enabled = 'enabled',
  Id = 'id',
  LastModified = 'lastModified',
  LogTypes = 'logTypes',
}

export type ListDetectionsInput = {
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  hasRemediation?: Maybe<Scalars['Boolean']>;
  resourceTypes?: Maybe<Array<Scalars['String']>>;
  logTypes?: Maybe<Array<Scalars['String']>>;
  analysisTypes?: Maybe<Array<DetectionTypeEnum>>;
  nameContains?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  severity?: Maybe<Array<SeverityEnum>>;
  createdBy?: Maybe<Scalars['String']>;
  lastModifiedBy?: Maybe<Scalars['String']>;
  initialSet?: Maybe<Scalars['Boolean']>;
  tags?: Maybe<Array<Scalars['String']>>;
  sortBy?: Maybe<ListDetectionsSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListDetectionsResponse = {
  __typename?: 'ListDetectionsResponse';
  detections: Array<Detection>;
  paging: PagingData;
};

export enum ListDetectionsSortFieldsEnum {
  DisplayName = 'displayName',
  Id = 'id',
  LastModified = 'lastModified',
  Enabled = 'enabled',
  Severity = 'severity',
}

export type ListGlobalPythonModuleInput = {
  nameContains?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  sortDir?: Maybe<SortDirEnum>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListGlobalPythonModulesResponse = {
  __typename?: 'ListGlobalPythonModulesResponse';
  paging?: Maybe<PagingData>;
  globals?: Maybe<Array<Maybe<GlobalPythonModule>>>;
};

export type ListPacksInput = {
  ids?: Maybe<Array<Scalars['ID']>>;
  exclusiveStartKey?: Maybe<Scalars['String']>;
  contains?: Maybe<Scalars['String']>;
  createdBefore?: Maybe<Scalars['AWSDateTime']>;
  createdAfter?: Maybe<Scalars['AWSDateTime']>;
  userId?: Maybe<Scalars['ID']>;
  sortDir?: Maybe<SortDirEnum>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListPacksResponse = {
  __typename?: 'ListPacksResponse';
  packs: Array<Pack>;
  paging: PagingData;
};

export enum ListPoliciesSortFieldsEnum {
  ComplianceStatus = 'complianceStatus',
  Enabled = 'enabled',
  Id = 'id',
  LastModified = 'lastModified',
  Severity = 'severity',
  ResourceTypes = 'resourceTypes',
}

export type ListResourcesInput = {
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  deleted?: Maybe<Scalars['Boolean']>;
  idContains?: Maybe<Scalars['String']>;
  integrationId?: Maybe<Scalars['ID']>;
  types?: Maybe<Array<Scalars['String']>>;
  sortBy?: Maybe<ListResourcesSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListResourcesResponse = {
  __typename?: 'ListResourcesResponse';
  paging?: Maybe<PagingData>;
  resources?: Maybe<Array<Maybe<ResourceSummary>>>;
};

export enum ListResourcesSortFieldsEnum {
  ComplianceStatus = 'complianceStatus',
  Id = 'id',
  LastModified = 'lastModified',
  Type = 'type',
}

export enum ListRulesSortFieldsEnum {
  DisplayName = 'displayName',
  Id = 'id',
  LastModified = 'lastModified',
  LogTypes = 'logTypes',
  Severity = 'severity',
}

export type LogAnalysisMetricsInput = {
  intervalMinutes: Scalars['Int'];
  fromDate: Scalars['AWSDateTime'];
  toDate: Scalars['AWSDateTime'];
  metricNames: Array<Scalars['String']>;
};

export type LogAnalysisMetricsResponse = {
  __typename?: 'LogAnalysisMetricsResponse';
  eventsProcessed: LongSeriesData;
  alertsBySeverity: LongSeriesData;
  /**
   * TODO: uncomment when event latency data are fixed (PR #2509, Ticket #2492)
   * eventsLatency: FloatSeriesData!
   */
  totalAlertsDelta: Array<SingleValue>;
  alertsByRuleID: Array<SingleValue>;
  fromDate: Scalars['AWSDateTime'];
  toDate: Scalars['AWSDateTime'];
  intervalMinutes: Scalars['Int'];
};

export type LogIntegration = S3LogIntegration | SqsLogSourceIntegration;

export type LongSeries = {
  __typename?: 'LongSeries';
  label: Scalars['String'];
  values: Array<Scalars['Long']>;
};

export type LongSeriesData = {
  __typename?: 'LongSeriesData';
  timestamps: Array<Scalars['AWSDateTime']>;
  series: Array<LongSeries>;
};

export enum MessageActionEnum {
  Resend = 'RESEND',
  Suppress = 'SUPPRESS',
}

export type ModifyGlobalPythonModuleInput = {
  description: Scalars['String'];
  id: Scalars['ID'];
  body: Scalars['String'];
};

export type MsTeamsConfig = {
  __typename?: 'MsTeamsConfig';
  webhookURL: Scalars['String'];
};

export type MsTeamsConfigInput = {
  webhookURL: Scalars['String'];
};

export type Mutation = {
  __typename?: 'Mutation';
  addCustomLog: GetCustomLogOutput;
  addDataModel: DataModel;
  addDestination?: Maybe<Destination>;
  addComplianceIntegration: ComplianceIntegration;
  addS3LogIntegration: S3LogIntegration;
  addSqsLogIntegration: SqsLogSourceIntegration;
  addPolicy: Policy;
  addRule: Rule;
  addGlobalPythonModule: GlobalPythonModule;
  deleteDataModel?: Maybe<Scalars['Boolean']>;
  deleteDetections?: Maybe<Scalars['Boolean']>;
  deleteDestination?: Maybe<Scalars['Boolean']>;
  deleteComplianceIntegration?: Maybe<Scalars['Boolean']>;
  deleteCustomLog: DeleteCustomLogOutput;
  deleteLogIntegration?: Maybe<Scalars['Boolean']>;
  deleteGlobalPythonModule?: Maybe<Scalars['Boolean']>;
  deleteUser?: Maybe<Scalars['Boolean']>;
  inviteUser: User;
  remediateResource?: Maybe<Scalars['Boolean']>;
  deliverAlert: AlertSummary;
  resetUserPassword: User;
  suppressPolicies?: Maybe<Scalars['Boolean']>;
  testPolicy: TestPolicyResponse;
  testRule: TestRuleResponse;
  updateAlertStatus: Array<AlertSummary>;
  updateDataModel: DataModel;
  updateCustomLog: GetCustomLogOutput;
  updateDestination?: Maybe<Destination>;
  updateComplianceIntegration: ComplianceIntegration;
  updateS3LogIntegration: S3LogIntegration;
  updateSqsLogIntegration: SqsLogSourceIntegration;
  updateGeneralSettings: GeneralSettings;
  updatePolicy: Policy;
  updateRule: Rule;
  updateUser: User;
  uploadDetections?: Maybe<UploadDetectionsResponse>;
  updateGlobalPythonlModule: GlobalPythonModule;
  updatePack: Pack;
};

export type MutationAddCustomLogArgs = {
  input: AddOrUpdateCustomLogInput;
};

export type MutationAddDataModelArgs = {
  input: AddOrUpdateDataModelInput;
};

export type MutationAddDestinationArgs = {
  input: DestinationInput;
};

export type MutationAddComplianceIntegrationArgs = {
  input: AddComplianceIntegrationInput;
};

export type MutationAddS3LogIntegrationArgs = {
  input: AddS3LogIntegrationInput;
};

export type MutationAddSqsLogIntegrationArgs = {
  input: AddSqsLogIntegrationInput;
};

export type MutationAddPolicyArgs = {
  input: AddPolicyInput;
};

export type MutationAddRuleArgs = {
  input: AddRuleInput;
};

export type MutationAddGlobalPythonModuleArgs = {
  input: AddGlobalPythonModuleInput;
};

export type MutationDeleteDataModelArgs = {
  input: DeleteDataModelInput;
};

export type MutationDeleteDetectionsArgs = {
  input: DeleteDetectionInput;
};

export type MutationDeleteDestinationArgs = {
  id: Scalars['ID'];
};

export type MutationDeleteComplianceIntegrationArgs = {
  id: Scalars['ID'];
};

export type MutationDeleteCustomLogArgs = {
  input?: Maybe<DeleteCustomLogInput>;
};

export type MutationDeleteLogIntegrationArgs = {
  id: Scalars['ID'];
};

export type MutationDeleteGlobalPythonModuleArgs = {
  input: DeleteGlobalPythonModuleInput;
};

export type MutationDeleteUserArgs = {
  id: Scalars['ID'];
};

export type MutationInviteUserArgs = {
  input?: Maybe<InviteUserInput>;
};

export type MutationRemediateResourceArgs = {
  input: RemediateResourceInput;
};

export type MutationDeliverAlertArgs = {
  input: DeliverAlertInput;
};

export type MutationResetUserPasswordArgs = {
  id: Scalars['ID'];
};

export type MutationSuppressPoliciesArgs = {
  input: SuppressPoliciesInput;
};

export type MutationTestPolicyArgs = {
  input: TestPolicyInput;
};

export type MutationTestRuleArgs = {
  input: TestRuleInput;
};

export type MutationUpdateAlertStatusArgs = {
  input: UpdateAlertStatusInput;
};

export type MutationUpdateDataModelArgs = {
  input: AddOrUpdateDataModelInput;
};

export type MutationUpdateCustomLogArgs = {
  input: AddOrUpdateCustomLogInput;
};

export type MutationUpdateDestinationArgs = {
  input: DestinationInput;
};

export type MutationUpdateComplianceIntegrationArgs = {
  input: UpdateComplianceIntegrationInput;
};

export type MutationUpdateS3LogIntegrationArgs = {
  input: UpdateS3LogIntegrationInput;
};

export type MutationUpdateSqsLogIntegrationArgs = {
  input: UpdateSqsLogIntegrationInput;
};

export type MutationUpdateGeneralSettingsArgs = {
  input: UpdateGeneralSettingsInput;
};

export type MutationUpdatePolicyArgs = {
  input: UpdatePolicyInput;
};

export type MutationUpdateRuleArgs = {
  input: UpdateRuleInput;
};

export type MutationUpdateUserArgs = {
  input: UpdateUserInput;
};

export type MutationUploadDetectionsArgs = {
  input: UploadDetectionsInput;
};

export type MutationUpdateGlobalPythonlModuleArgs = {
  input: ModifyGlobalPythonModuleInput;
};

export type MutationUpdatePackArgs = {
  input: UpdatePackInput;
};

export type OpsgenieConfig = {
  __typename?: 'OpsgenieConfig';
  apiKey: Scalars['String'];
  serviceRegion: OpsgenieServiceRegionEnum;
};

export type OpsgenieConfigInput = {
  apiKey: Scalars['String'];
  serviceRegion: OpsgenieServiceRegionEnum;
};

export enum OpsgenieServiceRegionEnum {
  Eu = 'EU',
  Us = 'US',
}

export type OrganizationReportBySeverity = {
  __typename?: 'OrganizationReportBySeverity';
  info?: Maybe<ComplianceStatusCounts>;
  low?: Maybe<ComplianceStatusCounts>;
  medium?: Maybe<ComplianceStatusCounts>;
  high?: Maybe<ComplianceStatusCounts>;
  critical?: Maybe<ComplianceStatusCounts>;
};

export type OrganizationStatsInput = {
  limitTopFailing?: Maybe<Scalars['Int']>;
};

export type OrganizationStatsResponse = {
  __typename?: 'OrganizationStatsResponse';
  appliedPolicies?: Maybe<OrganizationReportBySeverity>;
  scannedResources?: Maybe<ScannedResources>;
  topFailingPolicies: Array<Policy>;
  topFailingResources: Array<ResourceSummary>;
};

export type Pack = {
  __typename?: 'Pack';
  id: Scalars['ID'];
  enabled: Scalars['Boolean'];
  updateAvailable: Scalars['Boolean'];
  description: Scalars['String'];
  displayName: Scalars['String'];
  packVersion: PackVersion;
  availableVersions: Array<PackVersion>;
  createdBy: Scalars['ID'];
  lastModifiedBy: Scalars['ID'];
  createdAt: Scalars['AWSDateTime'];
  lastModified: Scalars['AWSDateTime'];
  detectionsPatterns: PackDetectionsPatterns;
  detectionTypes: DetectionTypes;
};

export type PackDetectionsPatterns = {
  __typename?: 'PackDetectionsPatterns';
  IDs?: Maybe<Array<Scalars['ID']>>;
};

export type PackVersion = {
  __typename?: 'PackVersion';
  id: Scalars['String'];
  name: Scalars['String'];
};

export type PackVersionInput = {
  id: Scalars['String'];
  name: Scalars['String'];
};

export type PagerDutyConfig = {
  __typename?: 'PagerDutyConfig';
  integrationKey: Scalars['String'];
};

export type PagerDutyConfigInput = {
  integrationKey: Scalars['String'];
};

export type PagingData = {
  __typename?: 'PagingData';
  thisPage?: Maybe<Scalars['Int']>;
  totalPages?: Maybe<Scalars['Int']>;
  totalItems?: Maybe<Scalars['Int']>;
};

export type PoliciesForResourceInput = {
  resourceId?: Maybe<Scalars['ID']>;
  severity?: Maybe<SeverityEnum>;
  status?: Maybe<ComplianceStatusEnum>;
  suppressed?: Maybe<Scalars['Boolean']>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type Policy = Detection & {
  __typename?: 'Policy';
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  body: Scalars['String'];
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  createdAt: Scalars['AWSDateTime'];
  createdBy?: Maybe<Scalars['ID']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  lastModifiedBy?: Maybe<Scalars['ID']>;
  outputIds: Array<Scalars['ID']>;
  reference?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Scalars['String']>>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  suppressions?: Maybe<Array<Scalars['String']>>;
  tags: Array<Scalars['String']>;
  tests: Array<DetectionTestDefinition>;
  versionId?: Maybe<Scalars['ID']>;
  analysisType: DetectionTypeEnum;
};

export type Query = {
  __typename?: 'Query';
  alert?: Maybe<AlertDetails>;
  alerts?: Maybe<ListAlertsResponse>;
  detections: ListDetectionsResponse;
  sendTestAlert: Array<Maybe<DeliveryResponse>>;
  destination?: Maybe<Destination>;
  destinations?: Maybe<Array<Maybe<Destination>>>;
  generalSettings: GeneralSettings;
  getComplianceIntegration: ComplianceIntegration;
  getComplianceIntegrationTemplate: IntegrationTemplate;
  getDataModel?: Maybe<DataModel>;
  getS3LogIntegration: S3LogIntegration;
  getS3LogIntegrationTemplate: IntegrationTemplate;
  getSqsLogIntegration: SqsLogSourceIntegration;
  remediations?: Maybe<Scalars['AWSJSON']>;
  resource?: Maybe<ResourceDetails>;
  resources?: Maybe<ListResourcesResponse>;
  resourcesForPolicy?: Maybe<ListComplianceItemsResponse>;
  getGlobalPythonModule: GlobalPythonModule;
  policy?: Maybe<Policy>;
  policiesForResource?: Maybe<ListComplianceItemsResponse>;
  listAvailableLogTypes: ListAvailableLogTypesResponse;
  listComplianceIntegrations: Array<ComplianceIntegration>;
  listDataModels: ListDataModelsResponse;
  listLogIntegrations: Array<LogIntegration>;
  listPacks: ListPacksResponse;
  organizationStats?: Maybe<OrganizationStatsResponse>;
  getLogAnalysisMetrics: LogAnalysisMetricsResponse;
  rule?: Maybe<Rule>;
  listGlobalPythonModules: ListGlobalPythonModulesResponse;
  users: Array<User>;
  getCustomLog: GetCustomLogOutput;
  listCustomLogs: Array<CustomLogRecord>;
};

export type QueryAlertArgs = {
  input: GetAlertInput;
};

export type QueryAlertsArgs = {
  input?: Maybe<ListAlertsInput>;
};

export type QueryDetectionsArgs = {
  input?: Maybe<ListDetectionsInput>;
};

export type QuerySendTestAlertArgs = {
  input: SendTestAlertInput;
};

export type QueryDestinationArgs = {
  id: Scalars['ID'];
};

export type QueryGetComplianceIntegrationArgs = {
  id: Scalars['ID'];
};

export type QueryGetComplianceIntegrationTemplateArgs = {
  input: GetComplianceIntegrationTemplateInput;
};

export type QueryGetDataModelArgs = {
  id: Scalars['ID'];
};

export type QueryGetS3LogIntegrationArgs = {
  id: Scalars['ID'];
};

export type QueryGetS3LogIntegrationTemplateArgs = {
  input: GetS3LogIntegrationTemplateInput;
};

export type QueryGetSqsLogIntegrationArgs = {
  id: Scalars['ID'];
};

export type QueryResourceArgs = {
  input: GetResourceInput;
};

export type QueryResourcesArgs = {
  input?: Maybe<ListResourcesInput>;
};

export type QueryResourcesForPolicyArgs = {
  input: ResourcesForPolicyInput;
};

export type QueryGetGlobalPythonModuleArgs = {
  input: GetGlobalPythonModuleInput;
};

export type QueryPolicyArgs = {
  input: GetPolicyInput;
};

export type QueryPoliciesForResourceArgs = {
  input?: Maybe<PoliciesForResourceInput>;
};

export type QueryListDataModelsArgs = {
  input: ListDataModelsInput;
};

export type QueryListPacksArgs = {
  input?: Maybe<ListPacksInput>;
};

export type QueryOrganizationStatsArgs = {
  input?: Maybe<OrganizationStatsInput>;
};

export type QueryGetLogAnalysisMetricsArgs = {
  input: LogAnalysisMetricsInput;
};

export type QueryRuleArgs = {
  input: GetRuleInput;
};

export type QueryListGlobalPythonModulesArgs = {
  input: ListGlobalPythonModuleInput;
};

export type QueryGetCustomLogArgs = {
  input: GetCustomLogInput;
};

export type RemediateResourceInput = {
  policyId: Scalars['ID'];
  resourceId: Scalars['ID'];
};

export type ResourceDetails = {
  __typename?: 'ResourceDetails';
  attributes?: Maybe<Scalars['AWSJSON']>;
  deleted?: Maybe<Scalars['Boolean']>;
  expiresAt?: Maybe<Scalars['Int']>;
  id?: Maybe<Scalars['ID']>;
  integrationId?: Maybe<Scalars['ID']>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  type?: Maybe<Scalars['String']>;
};

export type ResourcesForPolicyInput = {
  policyId?: Maybe<Scalars['ID']>;
  status?: Maybe<ComplianceStatusEnum>;
  suppressed?: Maybe<Scalars['Boolean']>;
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ResourceSummary = {
  __typename?: 'ResourceSummary';
  id?: Maybe<Scalars['ID']>;
  integrationId?: Maybe<Scalars['ID']>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  deleted?: Maybe<Scalars['Boolean']>;
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  type?: Maybe<Scalars['String']>;
};

export type Rule = Detection & {
  __typename?: 'Rule';
  body: Scalars['String'];
  createdAt: Scalars['AWSDateTime'];
  createdBy?: Maybe<Scalars['ID']>;
  dedupPeriodMinutes: Scalars['Int'];
  threshold: Scalars['Int'];
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  lastModifiedBy?: Maybe<Scalars['ID']>;
  logTypes?: Maybe<Array<Scalars['String']>>;
  outputIds: Array<Scalars['ID']>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  tags: Array<Scalars['String']>;
  tests: Array<DetectionTestDefinition>;
  versionId?: Maybe<Scalars['ID']>;
  analysisType: DetectionTypeEnum;
};

export type S3LogIntegration = {
  __typename?: 'S3LogIntegration';
  awsAccountId: Scalars['String'];
  createdAtTime: Scalars['AWSDateTime'];
  createdBy: Scalars['ID'];
  integrationId: Scalars['ID'];
  integrationType: Scalars['String'];
  integrationLabel: Scalars['String'];
  lastEventReceived?: Maybe<Scalars['AWSDateTime']>;
  s3Bucket: Scalars['String'];
  s3Prefix?: Maybe<Scalars['String']>;
  kmsKey?: Maybe<Scalars['String']>;
  s3PrefixLogTypes: Array<S3PrefixLogTypes>;
  managedBucketNotifications: Scalars['Boolean'];
  notificationsConfigurationSucceeded: Scalars['Boolean'];
  health: S3LogIntegrationHealth;
  stackName: Scalars['String'];
};

export type S3LogIntegrationHealth = {
  __typename?: 'S3LogIntegrationHealth';
  processingRoleStatus: IntegrationItemHealthStatus;
  s3BucketStatus: IntegrationItemHealthStatus;
  kmsKeyStatus: IntegrationItemHealthStatus;
};

export type S3PrefixLogTypes = {
  __typename?: 'S3PrefixLogTypes';
  prefix: Scalars['String'];
  logTypes: Array<Scalars['String']>;
};

export type S3PrefixLogTypesInput = {
  prefix: Scalars['String'];
  logTypes: Array<Scalars['String']>;
};

export type ScannedResources = {
  __typename?: 'ScannedResources';
  byType?: Maybe<Array<Maybe<ScannedResourceStats>>>;
};

export type ScannedResourceStats = {
  __typename?: 'ScannedResourceStats';
  count?: Maybe<ComplianceStatusCounts>;
  type?: Maybe<Scalars['String']>;
};

export type SendTestAlertInput = {
  outputIds: Array<Scalars['ID']>;
};

export enum SeverityEnum {
  Info = 'INFO',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
}

export type SingleValue = {
  __typename?: 'SingleValue';
  label: Scalars['String'];
  value: Scalars['Int'];
};

export type SlackConfig = {
  __typename?: 'SlackConfig';
  webhookURL: Scalars['String'];
};

export type SlackConfigInput = {
  webhookURL: Scalars['String'];
};

export type SnsConfig = {
  __typename?: 'SnsConfig';
  topicArn: Scalars['String'];
};

export type SnsConfigInput = {
  topicArn: Scalars['String'];
};

export enum SortDirEnum {
  Ascending = 'ascending',
  Descending = 'descending',
}

export type SqsConfig = {
  __typename?: 'SqsConfig';
  logTypes: Array<Scalars['String']>;
  allowedPrincipalArns?: Maybe<Array<Maybe<Scalars['String']>>>;
  allowedSourceArns?: Maybe<Array<Maybe<Scalars['String']>>>;
  queueUrl: Scalars['String'];
};

export type SqsConfigInput = {
  queueUrl: Scalars['String'];
};

export type SqsDestinationConfig = {
  __typename?: 'SqsDestinationConfig';
  queueUrl: Scalars['String'];
};

export type SqsLogConfigInput = {
  logTypes: Array<Scalars['String']>;
  allowedPrincipalArns: Array<Maybe<Scalars['String']>>;
  allowedSourceArns: Array<Maybe<Scalars['String']>>;
};

export type SqsLogIntegrationHealth = {
  __typename?: 'SqsLogIntegrationHealth';
  sqsStatus?: Maybe<IntegrationItemHealthStatus>;
};

export type SqsLogSourceIntegration = {
  __typename?: 'SqsLogSourceIntegration';
  createdAtTime: Scalars['AWSDateTime'];
  createdBy: Scalars['ID'];
  integrationId: Scalars['ID'];
  integrationLabel: Scalars['String'];
  integrationType: Scalars['String'];
  lastEventReceived?: Maybe<Scalars['AWSDateTime']>;
  sqsConfig: SqsConfig;
  health: SqsLogIntegrationHealth;
};

export type SuppressPoliciesInput = {
  policyIds: Array<Maybe<Scalars['ID']>>;
  resourcePatterns: Array<Maybe<Scalars['String']>>;
};

export type TestDetectionSubRecord = {
  __typename?: 'TestDetectionSubRecord';
  output?: Maybe<Scalars['String']>;
  error?: Maybe<Error>;
};

export type TestPolicyInput = {
  body: Scalars['String'];
  resourceTypes: Array<Scalars['String']>;
  tests: Array<DetectionTestDefinitionInput>;
};

export type TestPolicyRecord = TestRecord & {
  __typename?: 'TestPolicyRecord';
  id: Scalars['String'];
  name: Scalars['String'];
  passed: Scalars['Boolean'];
  functions: TestPolicyRecordFunctions;
  error?: Maybe<Error>;
};

export type TestPolicyRecordFunctions = {
  __typename?: 'TestPolicyRecordFunctions';
  policyFunction: TestDetectionSubRecord;
};

export type TestPolicyResponse = {
  __typename?: 'TestPolicyResponse';
  results: Array<TestPolicyRecord>;
};

export type TestRecord = {
  id: Scalars['String'];
  name: Scalars['String'];
  passed: Scalars['Boolean'];
  error?: Maybe<Error>;
};

export type TestRuleInput = {
  body: Scalars['String'];
  logTypes: Array<Scalars['String']>;
  tests: Array<DetectionTestDefinitionInput>;
};

export type TestRuleRecord = TestRecord & {
  __typename?: 'TestRuleRecord';
  id: Scalars['String'];
  name: Scalars['String'];
  passed: Scalars['Boolean'];
  functions: TestRuleRecordFunctions;
  error?: Maybe<Error>;
};

export type TestRuleRecordFunctions = {
  __typename?: 'TestRuleRecordFunctions';
  ruleFunction: TestDetectionSubRecord;
  titleFunction?: Maybe<TestDetectionSubRecord>;
  dedupFunction?: Maybe<TestDetectionSubRecord>;
  alertContextFunction?: Maybe<TestDetectionSubRecord>;
  descriptionFunction?: Maybe<TestDetectionSubRecord>;
  destinationsFunction?: Maybe<TestDetectionSubRecord>;
  referenceFunction?: Maybe<TestDetectionSubRecord>;
  runbookFunction?: Maybe<TestDetectionSubRecord>;
  severityFunction?: Maybe<TestDetectionSubRecord>;
};

export type TestRuleResponse = {
  __typename?: 'TestRuleResponse';
  results: Array<TestRuleRecord>;
};

export type UpdateAlertStatusInput = {
  alertIds: Array<Scalars['ID']>;
  status: AlertStatusesEnum;
};

export type UpdateComplianceIntegrationInput = {
  integrationId: Scalars['String'];
  integrationLabel?: Maybe<Scalars['String']>;
  cweEnabled?: Maybe<Scalars['Boolean']>;
  remediationEnabled?: Maybe<Scalars['Boolean']>;
  regionIgnoreList?: Maybe<Array<Scalars['String']>>;
  resourceTypeIgnoreList?: Maybe<Array<Scalars['String']>>;
};

export type UpdateGeneralSettingsInput = {
  displayName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['String']>;
  errorReportingConsent?: Maybe<Scalars['Boolean']>;
  analyticsConsent?: Maybe<Scalars['Boolean']>;
};

export type UpdatePackInput = {
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['ID'];
  packVersion?: Maybe<PackVersionInput>;
};

export type UpdatePolicyInput = {
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  body?: Maybe<Scalars['String']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['ID'];
  outputIds?: Maybe<Array<Scalars['ID']>>;
  reference?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  runbook?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  suppressions?: Maybe<Array<Maybe<Scalars['String']>>>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<DetectionTestDefinitionInput>>>;
};

export type UpdateRuleInput = {
  body?: Maybe<Scalars['String']>;
  dedupPeriodMinutes?: Maybe<Scalars['Int']>;
  threshold?: Maybe<Scalars['Int']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['ID'];
  logTypes?: Maybe<Array<Scalars['String']>>;
  outputIds?: Maybe<Array<Scalars['ID']>>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Array<Scalars['String']>>;
  tests?: Maybe<Array<DetectionTestDefinitionInput>>;
};

export type UpdateS3LogIntegrationInput = {
  integrationId: Scalars['String'];
  integrationLabel?: Maybe<Scalars['String']>;
  s3Bucket?: Maybe<Scalars['String']>;
  kmsKey?: Maybe<Scalars['String']>;
  s3PrefixLogTypes?: Maybe<Array<S3PrefixLogTypesInput>>;
};

export type UpdateSqsLogIntegrationInput = {
  integrationId: Scalars['String'];
  integrationLabel: Scalars['String'];
  sqsConfig: SqsLogConfigInput;
};

export type UpdateUserInput = {
  id: Scalars['ID'];
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['AWSEmail']>;
};

export type UploadDetectionsInput = {
  data: Scalars['String'];
};

export type UploadDetectionsResponse = {
  __typename?: 'UploadDetectionsResponse';
  totalPolicies: Scalars['Int'];
  newPolicies: Scalars['Int'];
  modifiedPolicies: Scalars['Int'];
  totalRules: Scalars['Int'];
  newRules: Scalars['Int'];
  modifiedRules: Scalars['Int'];
  totalGlobals: Scalars['Int'];
  newGlobals: Scalars['Int'];
  modifiedGlobals: Scalars['Int'];
  totalDataModels: Scalars['Int'];
  newDataModels: Scalars['Int'];
  modifiedDataModels: Scalars['Int'];
};

export type User = {
  __typename?: 'User';
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  id: Scalars['ID'];
  email: Scalars['AWSEmail'];
  createdAt: Scalars['AWSTimestamp'];
  status: Scalars['String'];
};

export type ResolverTypeWrapper<T> = Promise<T> | T;

export type LegacyStitchingResolver<TResult, TParent, TContext, TArgs> = {
  fragment: string;
  resolve: ResolverFn<TResult, TParent, TContext, TArgs>;
};

export type NewStitchingResolver<TResult, TParent, TContext, TArgs> = {
  selectionSet: string;
  resolve: ResolverFn<TResult, TParent, TContext, TArgs>;
};
export type StitchingResolver<TResult, TParent, TContext, TArgs> =
  | LegacyStitchingResolver<TResult, TParent, TContext, TArgs>
  | NewStitchingResolver<TResult, TParent, TContext, TArgs>;
export type Resolver<TResult, TParent = {}, TContext = {}, TArgs = {}> =
  | ResolverFn<TResult, TParent, TContext, TArgs>
  | StitchingResolver<TResult, TParent, TContext, TArgs>;

export type ResolverFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => Promise<TResult> | TResult;

export type SubscriptionSubscribeFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => AsyncIterator<TResult> | Promise<AsyncIterator<TResult>>;

export type SubscriptionResolveFn<TResult, TParent, TContext, TArgs> = (
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => TResult | Promise<TResult>;

export interface SubscriptionSubscriberObject<
  TResult,
  TKey extends string,
  TParent,
  TContext,
  TArgs
> {
  subscribe: SubscriptionSubscribeFn<{ [key in TKey]: TResult }, TParent, TContext, TArgs>;
  resolve?: SubscriptionResolveFn<TResult, { [key in TKey]: TResult }, TContext, TArgs>;
}

export interface SubscriptionResolverObject<TResult, TParent, TContext, TArgs> {
  subscribe: SubscriptionSubscribeFn<any, TParent, TContext, TArgs>;
  resolve: SubscriptionResolveFn<TResult, any, TContext, TArgs>;
}

export type SubscriptionObject<TResult, TKey extends string, TParent, TContext, TArgs> =
  | SubscriptionSubscriberObject<TResult, TKey, TParent, TContext, TArgs>
  | SubscriptionResolverObject<TResult, TParent, TContext, TArgs>;

export type SubscriptionResolver<
  TResult,
  TKey extends string,
  TParent = {},
  TContext = {},
  TArgs = {}
> =
  | ((...args: any[]) => SubscriptionObject<TResult, TKey, TParent, TContext, TArgs>)
  | SubscriptionObject<TResult, TKey, TParent, TContext, TArgs>;

export type TypeResolveFn<TTypes, TParent = {}, TContext = {}> = (
  parent: TParent,
  context: TContext,
  info: GraphQLResolveInfo
) => Maybe<TTypes> | Promise<Maybe<TTypes>>;

export type IsTypeOfResolverFn<T = {}> = (
  obj: T,
  info: GraphQLResolveInfo
) => boolean | Promise<boolean>;

export type NextResolverFn<T> = () => Promise<T>;

export type DirectiveResolverFn<TResult = {}, TParent = {}, TContext = {}, TArgs = {}> = (
  next: NextResolverFn<TResult>,
  parent: TParent,
  args: TArgs,
  context: TContext,
  info: GraphQLResolveInfo
) => TResult | Promise<TResult>;

/** Mapping between all available schema types and the resolvers types */
export type ResolversTypes = {
  Query: ResolverTypeWrapper<{}>;
  GetAlertInput: GetAlertInput;
  ID: ResolverTypeWrapper<Scalars['ID']>;
  Int: ResolverTypeWrapper<Scalars['Int']>;
  String: ResolverTypeWrapper<Scalars['String']>;
  AlertDetails: ResolverTypeWrapper<
    Omit<AlertDetails, 'detection'> & { detection: ResolversTypes['AlertDetailsDetectionInfo'] }
  >;
  Alert: ResolversTypes['AlertDetails'] | ResolversTypes['AlertSummary'];
  AWSDateTime: ResolverTypeWrapper<Scalars['AWSDateTime']>;
  DeliveryResponse: ResolverTypeWrapper<DeliveryResponse>;
  Boolean: ResolverTypeWrapper<Scalars['Boolean']>;
  SeverityEnum: SeverityEnum;
  AlertStatusesEnum: AlertStatusesEnum;
  AlertTypesEnum: AlertTypesEnum;
  AlertDetailsDetectionInfo:
    | ResolversTypes['AlertDetailsRuleInfo']
    | ResolversTypes['AlertSummaryPolicyInfo'];
  AlertDetailsRuleInfo: ResolverTypeWrapper<AlertDetailsRuleInfo>;
  AWSJSON: ResolverTypeWrapper<Scalars['AWSJSON']>;
  AlertSummaryPolicyInfo: ResolverTypeWrapper<AlertSummaryPolicyInfo>;
  ListAlertsInput: ListAlertsInput;
  ListAlertsSortFieldsEnum: ListAlertsSortFieldsEnum;
  SortDirEnum: SortDirEnum;
  ListAlertsResponse: ResolverTypeWrapper<ListAlertsResponse>;
  AlertSummary: ResolverTypeWrapper<
    Omit<AlertSummary, 'detection'> & { detection: ResolversTypes['AlertSummaryDetectionInfo'] }
  >;
  AlertSummaryDetectionInfo:
    | ResolversTypes['AlertSummaryRuleInfo']
    | ResolversTypes['AlertSummaryPolicyInfo'];
  AlertSummaryRuleInfo: ResolverTypeWrapper<AlertSummaryRuleInfo>;
  ListDetectionsInput: ListDetectionsInput;
  ComplianceStatusEnum: ComplianceStatusEnum;
  DetectionTypeEnum: DetectionTypeEnum;
  ListDetectionsSortFieldsEnum: ListDetectionsSortFieldsEnum;
  ListDetectionsResponse: ResolverTypeWrapper<ListDetectionsResponse>;
  Detection: ResolversTypes['Policy'] | ResolversTypes['Rule'];
  DetectionTestDefinition: ResolverTypeWrapper<DetectionTestDefinition>;
  PagingData: ResolverTypeWrapper<PagingData>;
  SendTestAlertInput: SendTestAlertInput;
  Destination: ResolverTypeWrapper<Destination>;
  DestinationTypeEnum: DestinationTypeEnum;
  DestinationConfig: ResolverTypeWrapper<DestinationConfig>;
  SlackConfig: ResolverTypeWrapper<SlackConfig>;
  SnsConfig: ResolverTypeWrapper<SnsConfig>;
  SqsDestinationConfig: ResolverTypeWrapper<SqsDestinationConfig>;
  PagerDutyConfig: ResolverTypeWrapper<PagerDutyConfig>;
  GithubConfig: ResolverTypeWrapper<GithubConfig>;
  JiraConfig: ResolverTypeWrapper<JiraConfig>;
  OpsgenieConfig: ResolverTypeWrapper<OpsgenieConfig>;
  OpsgenieServiceRegionEnum: OpsgenieServiceRegionEnum;
  MsTeamsConfig: ResolverTypeWrapper<MsTeamsConfig>;
  AsanaConfig: ResolverTypeWrapper<AsanaConfig>;
  CustomWebhookConfig: ResolverTypeWrapper<CustomWebhookConfig>;
  GeneralSettings: ResolverTypeWrapper<GeneralSettings>;
  ComplianceIntegration: ResolverTypeWrapper<ComplianceIntegration>;
  ComplianceIntegrationHealth: ResolverTypeWrapper<ComplianceIntegrationHealth>;
  IntegrationItemHealthStatus: ResolverTypeWrapper<IntegrationItemHealthStatus>;
  GetComplianceIntegrationTemplateInput: GetComplianceIntegrationTemplateInput;
  IntegrationTemplate: ResolverTypeWrapper<IntegrationTemplate>;
  DataModel: ResolverTypeWrapper<DataModel>;
  DataModelMapping: ResolverTypeWrapper<DataModelMapping>;
  S3LogIntegration: ResolverTypeWrapper<S3LogIntegration>;
  S3PrefixLogTypes: ResolverTypeWrapper<S3PrefixLogTypes>;
  S3LogIntegrationHealth: ResolverTypeWrapper<S3LogIntegrationHealth>;
  GetS3LogIntegrationTemplateInput: GetS3LogIntegrationTemplateInput;
  SqsLogSourceIntegration: ResolverTypeWrapper<SqsLogSourceIntegration>;
  SqsConfig: ResolverTypeWrapper<SqsConfig>;
  SqsLogIntegrationHealth: ResolverTypeWrapper<SqsLogIntegrationHealth>;
  GetResourceInput: GetResourceInput;
  ResourceDetails: ResolverTypeWrapper<ResourceDetails>;
  ListResourcesInput: ListResourcesInput;
  ListResourcesSortFieldsEnum: ListResourcesSortFieldsEnum;
  ListResourcesResponse: ResolverTypeWrapper<ListResourcesResponse>;
  ResourceSummary: ResolverTypeWrapper<ResourceSummary>;
  ResourcesForPolicyInput: ResourcesForPolicyInput;
  ListComplianceItemsResponse: ResolverTypeWrapper<ListComplianceItemsResponse>;
  ComplianceItem: ResolverTypeWrapper<ComplianceItem>;
  ActiveSuppressCount: ResolverTypeWrapper<ActiveSuppressCount>;
  ComplianceStatusCounts: ResolverTypeWrapper<ComplianceStatusCounts>;
  GetGlobalPythonModuleInput: GetGlobalPythonModuleInput;
  GlobalPythonModule: ResolverTypeWrapper<GlobalPythonModule>;
  GetPolicyInput: GetPolicyInput;
  Policy: ResolverTypeWrapper<Policy>;
  PoliciesForResourceInput: PoliciesForResourceInput;
  ListAvailableLogTypesResponse: ResolverTypeWrapper<ListAvailableLogTypesResponse>;
  ListDataModelsInput: ListDataModelsInput;
  ListDataModelsSortFieldsEnum: ListDataModelsSortFieldsEnum;
  ListDataModelsResponse: ResolverTypeWrapper<ListDataModelsResponse>;
  LogIntegration: ResolversTypes['S3LogIntegration'] | ResolversTypes['SqsLogSourceIntegration'];
  ListPacksInput: ListPacksInput;
  ListPacksResponse: ResolverTypeWrapper<ListPacksResponse>;
  Pack: ResolverTypeWrapper<Pack>;
  PackVersion: ResolverTypeWrapper<PackVersion>;
  PackDetectionsPatterns: ResolverTypeWrapper<PackDetectionsPatterns>;
  DetectionTypes: ResolverTypeWrapper<DetectionTypes>;
  OrganizationStatsInput: OrganizationStatsInput;
  OrganizationStatsResponse: ResolverTypeWrapper<OrganizationStatsResponse>;
  OrganizationReportBySeverity: ResolverTypeWrapper<OrganizationReportBySeverity>;
  ScannedResources: ResolverTypeWrapper<ScannedResources>;
  ScannedResourceStats: ResolverTypeWrapper<ScannedResourceStats>;
  LogAnalysisMetricsInput: LogAnalysisMetricsInput;
  LogAnalysisMetricsResponse: ResolverTypeWrapper<LogAnalysisMetricsResponse>;
  LongSeriesData: ResolverTypeWrapper<LongSeriesData>;
  LongSeries: ResolverTypeWrapper<LongSeries>;
  Long: ResolverTypeWrapper<Scalars['Long']>;
  SingleValue: ResolverTypeWrapper<SingleValue>;
  GetRuleInput: GetRuleInput;
  Rule: ResolverTypeWrapper<Rule>;
  ListGlobalPythonModuleInput: ListGlobalPythonModuleInput;
  ListGlobalPythonModulesResponse: ResolverTypeWrapper<ListGlobalPythonModulesResponse>;
  User: ResolverTypeWrapper<User>;
  AWSEmail: ResolverTypeWrapper<Scalars['AWSEmail']>;
  AWSTimestamp: ResolverTypeWrapper<Scalars['AWSTimestamp']>;
  GetCustomLogInput: GetCustomLogInput;
  GetCustomLogOutput: ResolverTypeWrapper<GetCustomLogOutput>;
  Error: ResolverTypeWrapper<Error>;
  CustomLogRecord: ResolverTypeWrapper<CustomLogRecord>;
  Mutation: ResolverTypeWrapper<{}>;
  AddOrUpdateCustomLogInput: AddOrUpdateCustomLogInput;
  AddOrUpdateDataModelInput: AddOrUpdateDataModelInput;
  DataModelMappingInput: DataModelMappingInput;
  DestinationInput: DestinationInput;
  DestinationConfigInput: DestinationConfigInput;
  SlackConfigInput: SlackConfigInput;
  SnsConfigInput: SnsConfigInput;
  SqsConfigInput: SqsConfigInput;
  PagerDutyConfigInput: PagerDutyConfigInput;
  GithubConfigInput: GithubConfigInput;
  JiraConfigInput: JiraConfigInput;
  OpsgenieConfigInput: OpsgenieConfigInput;
  MsTeamsConfigInput: MsTeamsConfigInput;
  AsanaConfigInput: AsanaConfigInput;
  CustomWebhookConfigInput: CustomWebhookConfigInput;
  AddComplianceIntegrationInput: AddComplianceIntegrationInput;
  AddS3LogIntegrationInput: AddS3LogIntegrationInput;
  S3PrefixLogTypesInput: S3PrefixLogTypesInput;
  AddSqsLogIntegrationInput: AddSqsLogIntegrationInput;
  SqsLogConfigInput: SqsLogConfigInput;
  AddPolicyInput: AddPolicyInput;
  DetectionTestDefinitionInput: DetectionTestDefinitionInput;
  AddRuleInput: AddRuleInput;
  AddGlobalPythonModuleInput: AddGlobalPythonModuleInput;
  DeleteDataModelInput: DeleteDataModelInput;
  DeleteEntry: DeleteEntry;
  DeleteDetectionInput: DeleteDetectionInput;
  DeleteCustomLogInput: DeleteCustomLogInput;
  DeleteCustomLogOutput: ResolverTypeWrapper<DeleteCustomLogOutput>;
  DeleteGlobalPythonModuleInput: DeleteGlobalPythonModuleInput;
  InviteUserInput: InviteUserInput;
  MessageActionEnum: MessageActionEnum;
  RemediateResourceInput: RemediateResourceInput;
  DeliverAlertInput: DeliverAlertInput;
  SuppressPoliciesInput: SuppressPoliciesInput;
  TestPolicyInput: TestPolicyInput;
  TestPolicyResponse: ResolverTypeWrapper<TestPolicyResponse>;
  TestPolicyRecord: ResolverTypeWrapper<TestPolicyRecord>;
  TestRecord: ResolversTypes['TestPolicyRecord'] | ResolversTypes['TestRuleRecord'];
  TestPolicyRecordFunctions: ResolverTypeWrapper<TestPolicyRecordFunctions>;
  TestDetectionSubRecord: ResolverTypeWrapper<TestDetectionSubRecord>;
  TestRuleInput: TestRuleInput;
  TestRuleResponse: ResolverTypeWrapper<TestRuleResponse>;
  TestRuleRecord: ResolverTypeWrapper<TestRuleRecord>;
  TestRuleRecordFunctions: ResolverTypeWrapper<TestRuleRecordFunctions>;
  UpdateAlertStatusInput: UpdateAlertStatusInput;
  UpdateComplianceIntegrationInput: UpdateComplianceIntegrationInput;
  UpdateS3LogIntegrationInput: UpdateS3LogIntegrationInput;
  UpdateSqsLogIntegrationInput: UpdateSqsLogIntegrationInput;
  UpdateGeneralSettingsInput: UpdateGeneralSettingsInput;
  UpdatePolicyInput: UpdatePolicyInput;
  UpdateRuleInput: UpdateRuleInput;
  UpdateUserInput: UpdateUserInput;
  UploadDetectionsInput: UploadDetectionsInput;
  UploadDetectionsResponse: ResolverTypeWrapper<UploadDetectionsResponse>;
  ModifyGlobalPythonModuleInput: ModifyGlobalPythonModuleInput;
  UpdatePackInput: UpdatePackInput;
  PackVersionInput: PackVersionInput;
  CustomLogOutput: ResolverTypeWrapper<CustomLogOutput>;
  FloatSeries: ResolverTypeWrapper<FloatSeries>;
  Float: ResolverTypeWrapper<Scalars['Float']>;
  FloatSeriesData: ResolverTypeWrapper<FloatSeriesData>;
  ListPoliciesSortFieldsEnum: ListPoliciesSortFieldsEnum;
  ListRulesSortFieldsEnum: ListRulesSortFieldsEnum;
  AccountTypeEnum: AccountTypeEnum;
  ErrorCodeEnum: ErrorCodeEnum;
};

/** Mapping between all available schema types and the resolvers parents */
export type ResolversParentTypes = {
  Query: {};
  GetAlertInput: GetAlertInput;
  ID: Scalars['ID'];
  Int: Scalars['Int'];
  String: Scalars['String'];
  AlertDetails: Omit<AlertDetails, 'detection'> & {
    detection: ResolversParentTypes['AlertDetailsDetectionInfo'];
  };
  Alert: ResolversParentTypes['AlertDetails'] | ResolversParentTypes['AlertSummary'];
  AWSDateTime: Scalars['AWSDateTime'];
  DeliveryResponse: DeliveryResponse;
  Boolean: Scalars['Boolean'];
  SeverityEnum: SeverityEnum;
  AlertStatusesEnum: AlertStatusesEnum;
  AlertTypesEnum: AlertTypesEnum;
  AlertDetailsDetectionInfo:
    | ResolversParentTypes['AlertDetailsRuleInfo']
    | ResolversParentTypes['AlertSummaryPolicyInfo'];
  AlertDetailsRuleInfo: AlertDetailsRuleInfo;
  AWSJSON: Scalars['AWSJSON'];
  AlertSummaryPolicyInfo: AlertSummaryPolicyInfo;
  ListAlertsInput: ListAlertsInput;
  ListAlertsSortFieldsEnum: ListAlertsSortFieldsEnum;
  SortDirEnum: SortDirEnum;
  ListAlertsResponse: ListAlertsResponse;
  AlertSummary: Omit<AlertSummary, 'detection'> & {
    detection: ResolversParentTypes['AlertSummaryDetectionInfo'];
  };
  AlertSummaryDetectionInfo:
    | ResolversParentTypes['AlertSummaryRuleInfo']
    | ResolversParentTypes['AlertSummaryPolicyInfo'];
  AlertSummaryRuleInfo: AlertSummaryRuleInfo;
  ListDetectionsInput: ListDetectionsInput;
  ComplianceStatusEnum: ComplianceStatusEnum;
  DetectionTypeEnum: DetectionTypeEnum;
  ListDetectionsSortFieldsEnum: ListDetectionsSortFieldsEnum;
  ListDetectionsResponse: ListDetectionsResponse;
  Detection: ResolversParentTypes['Policy'] | ResolversParentTypes['Rule'];
  DetectionTestDefinition: DetectionTestDefinition;
  PagingData: PagingData;
  SendTestAlertInput: SendTestAlertInput;
  Destination: Destination;
  DestinationTypeEnum: DestinationTypeEnum;
  DestinationConfig: DestinationConfig;
  SlackConfig: SlackConfig;
  SnsConfig: SnsConfig;
  SqsDestinationConfig: SqsDestinationConfig;
  PagerDutyConfig: PagerDutyConfig;
  GithubConfig: GithubConfig;
  JiraConfig: JiraConfig;
  OpsgenieConfig: OpsgenieConfig;
  OpsgenieServiceRegionEnum: OpsgenieServiceRegionEnum;
  MsTeamsConfig: MsTeamsConfig;
  AsanaConfig: AsanaConfig;
  CustomWebhookConfig: CustomWebhookConfig;
  GeneralSettings: GeneralSettings;
  ComplianceIntegration: ComplianceIntegration;
  ComplianceIntegrationHealth: ComplianceIntegrationHealth;
  IntegrationItemHealthStatus: IntegrationItemHealthStatus;
  GetComplianceIntegrationTemplateInput: GetComplianceIntegrationTemplateInput;
  IntegrationTemplate: IntegrationTemplate;
  DataModel: DataModel;
  DataModelMapping: DataModelMapping;
  S3LogIntegration: S3LogIntegration;
  S3PrefixLogTypes: S3PrefixLogTypes;
  S3LogIntegrationHealth: S3LogIntegrationHealth;
  GetS3LogIntegrationTemplateInput: GetS3LogIntegrationTemplateInput;
  SqsLogSourceIntegration: SqsLogSourceIntegration;
  SqsConfig: SqsConfig;
  SqsLogIntegrationHealth: SqsLogIntegrationHealth;
  GetResourceInput: GetResourceInput;
  ResourceDetails: ResourceDetails;
  ListResourcesInput: ListResourcesInput;
  ListResourcesSortFieldsEnum: ListResourcesSortFieldsEnum;
  ListResourcesResponse: ListResourcesResponse;
  ResourceSummary: ResourceSummary;
  ResourcesForPolicyInput: ResourcesForPolicyInput;
  ListComplianceItemsResponse: ListComplianceItemsResponse;
  ComplianceItem: ComplianceItem;
  ActiveSuppressCount: ActiveSuppressCount;
  ComplianceStatusCounts: ComplianceStatusCounts;
  GetGlobalPythonModuleInput: GetGlobalPythonModuleInput;
  GlobalPythonModule: GlobalPythonModule;
  GetPolicyInput: GetPolicyInput;
  Policy: Policy;
  PoliciesForResourceInput: PoliciesForResourceInput;
  ListAvailableLogTypesResponse: ListAvailableLogTypesResponse;
  ListDataModelsInput: ListDataModelsInput;
  ListDataModelsSortFieldsEnum: ListDataModelsSortFieldsEnum;
  ListDataModelsResponse: ListDataModelsResponse;
  LogIntegration:
    | ResolversParentTypes['S3LogIntegration']
    | ResolversParentTypes['SqsLogSourceIntegration'];
  ListPacksInput: ListPacksInput;
  ListPacksResponse: ListPacksResponse;
  Pack: Pack;
  PackVersion: PackVersion;
  PackDetectionsPatterns: PackDetectionsPatterns;
  DetectionTypes: DetectionTypes;
  OrganizationStatsInput: OrganizationStatsInput;
  OrganizationStatsResponse: OrganizationStatsResponse;
  OrganizationReportBySeverity: OrganizationReportBySeverity;
  ScannedResources: ScannedResources;
  ScannedResourceStats: ScannedResourceStats;
  LogAnalysisMetricsInput: LogAnalysisMetricsInput;
  LogAnalysisMetricsResponse: LogAnalysisMetricsResponse;
  LongSeriesData: LongSeriesData;
  LongSeries: LongSeries;
  Long: Scalars['Long'];
  SingleValue: SingleValue;
  GetRuleInput: GetRuleInput;
  Rule: Rule;
  ListGlobalPythonModuleInput: ListGlobalPythonModuleInput;
  ListGlobalPythonModulesResponse: ListGlobalPythonModulesResponse;
  User: User;
  AWSEmail: Scalars['AWSEmail'];
  AWSTimestamp: Scalars['AWSTimestamp'];
  GetCustomLogInput: GetCustomLogInput;
  GetCustomLogOutput: GetCustomLogOutput;
  Error: Error;
  CustomLogRecord: CustomLogRecord;
  Mutation: {};
  AddOrUpdateCustomLogInput: AddOrUpdateCustomLogInput;
  AddOrUpdateDataModelInput: AddOrUpdateDataModelInput;
  DataModelMappingInput: DataModelMappingInput;
  DestinationInput: DestinationInput;
  DestinationConfigInput: DestinationConfigInput;
  SlackConfigInput: SlackConfigInput;
  SnsConfigInput: SnsConfigInput;
  SqsConfigInput: SqsConfigInput;
  PagerDutyConfigInput: PagerDutyConfigInput;
  GithubConfigInput: GithubConfigInput;
  JiraConfigInput: JiraConfigInput;
  OpsgenieConfigInput: OpsgenieConfigInput;
  MsTeamsConfigInput: MsTeamsConfigInput;
  AsanaConfigInput: AsanaConfigInput;
  CustomWebhookConfigInput: CustomWebhookConfigInput;
  AddComplianceIntegrationInput: AddComplianceIntegrationInput;
  AddS3LogIntegrationInput: AddS3LogIntegrationInput;
  S3PrefixLogTypesInput: S3PrefixLogTypesInput;
  AddSqsLogIntegrationInput: AddSqsLogIntegrationInput;
  SqsLogConfigInput: SqsLogConfigInput;
  AddPolicyInput: AddPolicyInput;
  DetectionTestDefinitionInput: DetectionTestDefinitionInput;
  AddRuleInput: AddRuleInput;
  AddGlobalPythonModuleInput: AddGlobalPythonModuleInput;
  DeleteDataModelInput: DeleteDataModelInput;
  DeleteEntry: DeleteEntry;
  DeleteDetectionInput: DeleteDetectionInput;
  DeleteCustomLogInput: DeleteCustomLogInput;
  DeleteCustomLogOutput: DeleteCustomLogOutput;
  DeleteGlobalPythonModuleInput: DeleteGlobalPythonModuleInput;
  InviteUserInput: InviteUserInput;
  MessageActionEnum: MessageActionEnum;
  RemediateResourceInput: RemediateResourceInput;
  DeliverAlertInput: DeliverAlertInput;
  SuppressPoliciesInput: SuppressPoliciesInput;
  TestPolicyInput: TestPolicyInput;
  TestPolicyResponse: TestPolicyResponse;
  TestPolicyRecord: TestPolicyRecord;
  TestRecord: ResolversParentTypes['TestPolicyRecord'] | ResolversParentTypes['TestRuleRecord'];
  TestPolicyRecordFunctions: TestPolicyRecordFunctions;
  TestDetectionSubRecord: TestDetectionSubRecord;
  TestRuleInput: TestRuleInput;
  TestRuleResponse: TestRuleResponse;
  TestRuleRecord: TestRuleRecord;
  TestRuleRecordFunctions: TestRuleRecordFunctions;
  UpdateAlertStatusInput: UpdateAlertStatusInput;
  UpdateComplianceIntegrationInput: UpdateComplianceIntegrationInput;
  UpdateS3LogIntegrationInput: UpdateS3LogIntegrationInput;
  UpdateSqsLogIntegrationInput: UpdateSqsLogIntegrationInput;
  UpdateGeneralSettingsInput: UpdateGeneralSettingsInput;
  UpdatePolicyInput: UpdatePolicyInput;
  UpdateRuleInput: UpdateRuleInput;
  UpdateUserInput: UpdateUserInput;
  UploadDetectionsInput: UploadDetectionsInput;
  UploadDetectionsResponse: UploadDetectionsResponse;
  ModifyGlobalPythonModuleInput: ModifyGlobalPythonModuleInput;
  UpdatePackInput: UpdatePackInput;
  PackVersionInput: PackVersionInput;
  CustomLogOutput: CustomLogOutput;
  FloatSeries: FloatSeries;
  Float: Scalars['Float'];
  FloatSeriesData: FloatSeriesData;
  ListPoliciesSortFieldsEnum: ListPoliciesSortFieldsEnum;
  ListRulesSortFieldsEnum: ListRulesSortFieldsEnum;
  AccountTypeEnum: AccountTypeEnum;
  ErrorCodeEnum: ErrorCodeEnum;
};

export type ActiveSuppressCountResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ActiveSuppressCount'] = ResolversParentTypes['ActiveSuppressCount']
> = {
  active?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  suppressed?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AlertResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Alert'] = ResolversParentTypes['Alert']
> = {
  __resolveType: TypeResolveFn<'AlertDetails' | 'AlertSummary', ParentType, ContextType>;
  alertId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  deliveryResponses?: Resolver<
    Array<Maybe<ResolversTypes['DeliveryResponse']>>,
    ParentType,
    ContextType
  >;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  status?: Resolver<ResolversTypes['AlertStatusesEnum'], ParentType, ContextType>;
  title?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  type?: Resolver<ResolversTypes['AlertTypesEnum'], ParentType, ContextType>;
  lastUpdatedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  lastUpdatedByTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  updateTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
};

export type AlertDetailsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertDetails'] = ResolversParentTypes['AlertDetails']
> = {
  alertId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  deliveryResponses?: Resolver<
    Array<Maybe<ResolversTypes['DeliveryResponse']>>,
    ParentType,
    ContextType
  >;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  status?: Resolver<ResolversTypes['AlertStatusesEnum'], ParentType, ContextType>;
  title?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  type?: Resolver<ResolversTypes['AlertTypesEnum'], ParentType, ContextType>;
  lastUpdatedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  lastUpdatedByTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  updateTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  detection?: Resolver<ResolversTypes['AlertDetailsDetectionInfo'], ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AlertDetailsDetectionInfoResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertDetailsDetectionInfo'] = ResolversParentTypes['AlertDetailsDetectionInfo']
> = {
  __resolveType: TypeResolveFn<
    'AlertDetailsRuleInfo' | 'AlertSummaryPolicyInfo',
    ParentType,
    ContextType
  >;
};

export type AlertDetailsRuleInfoResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertDetailsRuleInfo'] = ResolversParentTypes['AlertDetailsRuleInfo']
> = {
  ruleId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  eventsMatched?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  dedupString?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  events?: Resolver<Array<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  eventsLastEvaluatedKey?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AlertSummaryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertSummary'] = ResolversParentTypes['AlertSummary']
> = {
  alertId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  deliveryResponses?: Resolver<
    Array<Maybe<ResolversTypes['DeliveryResponse']>>,
    ParentType,
    ContextType
  >;
  type?: Resolver<ResolversTypes['AlertTypesEnum'], ParentType, ContextType>;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  status?: Resolver<ResolversTypes['AlertStatusesEnum'], ParentType, ContextType>;
  title?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastUpdatedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  lastUpdatedByTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  updateTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  detection?: Resolver<ResolversTypes['AlertSummaryDetectionInfo'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AlertSummaryDetectionInfoResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertSummaryDetectionInfo'] = ResolversParentTypes['AlertSummaryDetectionInfo']
> = {
  __resolveType: TypeResolveFn<
    'AlertSummaryRuleInfo' | 'AlertSummaryPolicyInfo',
    ParentType,
    ContextType
  >;
};

export type AlertSummaryPolicyInfoResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertSummaryPolicyInfo'] = ResolversParentTypes['AlertSummaryPolicyInfo']
> = {
  policyId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  resourceId?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  policySourceId?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  resourceTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AlertSummaryRuleInfoResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertSummaryRuleInfo'] = ResolversParentTypes['AlertSummaryRuleInfo']
> = {
  ruleId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  eventsMatched?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type AsanaConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AsanaConfig'] = ResolversParentTypes['AsanaConfig']
> = {
  personalAccessToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  projectGids?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export interface AwsDateTimeScalarConfig
  extends GraphQLScalarTypeConfig<ResolversTypes['AWSDateTime'], any> {
  name: 'AWSDateTime';
}

export interface AwsEmailScalarConfig
  extends GraphQLScalarTypeConfig<ResolversTypes['AWSEmail'], any> {
  name: 'AWSEmail';
}

export interface AwsjsonScalarConfig
  extends GraphQLScalarTypeConfig<ResolversTypes['AWSJSON'], any> {
  name: 'AWSJSON';
}

export interface AwsTimestampScalarConfig
  extends GraphQLScalarTypeConfig<ResolversTypes['AWSTimestamp'], any> {
  name: 'AWSTimestamp';
}

export type ComplianceIntegrationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ComplianceIntegration'] = ResolversParentTypes['ComplianceIntegration']
> = {
  awsAccountId?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  createdAtTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationLabel?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  cweEnabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  remediationEnabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  regionIgnoreList?: Resolver<Maybe<Array<ResolversTypes['String']>>, ParentType, ContextType>;
  resourceTypeIgnoreList?: Resolver<
    Maybe<Array<ResolversTypes['String']>>,
    ParentType,
    ContextType
  >;
  health?: Resolver<ResolversTypes['ComplianceIntegrationHealth'], ParentType, ContextType>;
  stackName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ComplianceIntegrationHealthResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ComplianceIntegrationHealth'] = ResolversParentTypes['ComplianceIntegrationHealth']
> = {
  auditRoleStatus?: Resolver<
    ResolversTypes['IntegrationItemHealthStatus'],
    ParentType,
    ContextType
  >;
  cweRoleStatus?: Resolver<ResolversTypes['IntegrationItemHealthStatus'], ParentType, ContextType>;
  remediationRoleStatus?: Resolver<
    ResolversTypes['IntegrationItemHealthStatus'],
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ComplianceItemResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ComplianceItem'] = ResolversParentTypes['ComplianceItem']
> = {
  errorMessage?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  lastUpdated?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  policyId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  policySeverity?: Resolver<Maybe<ResolversTypes['SeverityEnum']>, ParentType, ContextType>;
  resourceId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  resourceType?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  status?: Resolver<Maybe<ResolversTypes['ComplianceStatusEnum']>, ParentType, ContextType>;
  suppressed?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  integrationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ComplianceStatusCountsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ComplianceStatusCounts'] = ResolversParentTypes['ComplianceStatusCounts']
> = {
  error?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  fail?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  pass?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type CustomLogOutputResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['CustomLogOutput'] = ResolversParentTypes['CustomLogOutput']
> = {
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  record?: Resolver<Maybe<ResolversTypes['CustomLogRecord']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type CustomLogRecordResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['CustomLogRecord'] = ResolversParentTypes['CustomLogRecord']
> = {
  logType?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  revision?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  updatedAt?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  description?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  referenceURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  logSpec?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type CustomWebhookConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['CustomWebhookConfig'] = ResolversParentTypes['CustomWebhookConfig']
> = {
  webhookURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DataModelResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DataModel'] = ResolversParentTypes['DataModel']
> = {
  displayName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  enabled?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  mappings?: Resolver<Array<ResolversTypes['DataModelMapping']>, ParentType, ContextType>;
  body?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  lastModified?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DataModelMappingResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DataModelMapping'] = ResolversParentTypes['DataModelMapping']
> = {
  name?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  path?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  method?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DeleteCustomLogOutputResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DeleteCustomLogOutput'] = ResolversParentTypes['DeleteCustomLogOutput']
> = {
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DeliveryResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DeliveryResponse'] = ResolversParentTypes['DeliveryResponse']
> = {
  outputId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  statusCode?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  success?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  dispatchedAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DestinationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Destination'] = ResolversParentTypes['Destination']
> = {
  createdBy?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  displayName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastModifiedBy?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastModifiedTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  outputId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  outputType?: Resolver<ResolversTypes['DestinationTypeEnum'], ParentType, ContextType>;
  outputConfig?: Resolver<ResolversTypes['DestinationConfig'], ParentType, ContextType>;
  verificationStatus?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  defaultForSeverity?: Resolver<
    Array<Maybe<ResolversTypes['SeverityEnum']>>,
    ParentType,
    ContextType
  >;
  alertTypes?: Resolver<Array<ResolversTypes['AlertTypesEnum']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DestinationConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DestinationConfig'] = ResolversParentTypes['DestinationConfig']
> = {
  slack?: Resolver<Maybe<ResolversTypes['SlackConfig']>, ParentType, ContextType>;
  sns?: Resolver<Maybe<ResolversTypes['SnsConfig']>, ParentType, ContextType>;
  sqs?: Resolver<Maybe<ResolversTypes['SqsDestinationConfig']>, ParentType, ContextType>;
  pagerDuty?: Resolver<Maybe<ResolversTypes['PagerDutyConfig']>, ParentType, ContextType>;
  github?: Resolver<Maybe<ResolversTypes['GithubConfig']>, ParentType, ContextType>;
  jira?: Resolver<Maybe<ResolversTypes['JiraConfig']>, ParentType, ContextType>;
  opsgenie?: Resolver<Maybe<ResolversTypes['OpsgenieConfig']>, ParentType, ContextType>;
  msTeams?: Resolver<Maybe<ResolversTypes['MsTeamsConfig']>, ParentType, ContextType>;
  asana?: Resolver<Maybe<ResolversTypes['AsanaConfig']>, ParentType, ContextType>;
  customWebhook?: Resolver<Maybe<ResolversTypes['CustomWebhookConfig']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DetectionResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Detection'] = ResolversParentTypes['Detection']
> = {
  __resolveType: TypeResolveFn<'Policy' | 'Rule', ParentType, ContextType>;
  body?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastModifiedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  outputIds?: Resolver<Array<ResolversTypes['ID']>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  tags?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  tests?: Resolver<Array<ResolversTypes['DetectionTestDefinition']>, ParentType, ContextType>;
  versionId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  analysisType?: Resolver<ResolversTypes['DetectionTypeEnum'], ParentType, ContextType>;
};

export type DetectionTestDefinitionResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DetectionTestDefinition'] = ResolversParentTypes['DetectionTestDefinition']
> = {
  expectedResult?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  name?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  resource?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type DetectionTypesResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DetectionTypes'] = ResolversParentTypes['DetectionTypes']
> = {
  GLOBAL?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  RULE?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  POLICY?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ErrorResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Error'] = ResolversParentTypes['Error']
> = {
  code?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type FloatSeriesResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['FloatSeries'] = ResolversParentTypes['FloatSeries']
> = {
  label?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  values?: Resolver<Array<ResolversTypes['Float']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type FloatSeriesDataResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['FloatSeriesData'] = ResolversParentTypes['FloatSeriesData']
> = {
  timestamps?: Resolver<Array<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  series?: Resolver<Array<ResolversTypes['FloatSeries']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type GeneralSettingsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GeneralSettings'] = ResolversParentTypes['GeneralSettings']
> = {
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  email?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  errorReportingConsent?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  analyticsConsent?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type GetCustomLogOutputResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GetCustomLogOutput'] = ResolversParentTypes['GetCustomLogOutput']
> = {
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  record?: Resolver<Maybe<ResolversTypes['CustomLogRecord']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type GithubConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GithubConfig'] = ResolversParentTypes['GithubConfig']
> = {
  repoName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  token?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type GlobalPythonModuleResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GlobalPythonModule'] = ResolversParentTypes['GlobalPythonModule']
> = {
  body?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  description?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  lastModified?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type IntegrationItemHealthStatusResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['IntegrationItemHealthStatus'] = ResolversParentTypes['IntegrationItemHealthStatus']
> = {
  healthy?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  message?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  rawErrorMessage?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type IntegrationTemplateResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['IntegrationTemplate'] = ResolversParentTypes['IntegrationTemplate']
> = {
  body?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  stackName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type JiraConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['JiraConfig'] = ResolversParentTypes['JiraConfig']
> = {
  orgDomain?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  projectKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  userName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  apiKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  assigneeId?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  issueType?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  labels?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListAlertsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListAlertsResponse'] = ResolversParentTypes['ListAlertsResponse']
> = {
  alertSummaries?: Resolver<Array<Maybe<ResolversTypes['AlertSummary']>>, ParentType, ContextType>;
  lastEvaluatedKey?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListAvailableLogTypesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListAvailableLogTypesResponse'] = ResolversParentTypes['ListAvailableLogTypesResponse']
> = {
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListComplianceItemsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListComplianceItemsResponse'] = ResolversParentTypes['ListComplianceItemsResponse']
> = {
  items?: Resolver<Maybe<Array<Maybe<ResolversTypes['ComplianceItem']>>>, ParentType, ContextType>;
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  status?: Resolver<Maybe<ResolversTypes['ComplianceStatusEnum']>, ParentType, ContextType>;
  totals?: Resolver<Maybe<ResolversTypes['ActiveSuppressCount']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListDataModelsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListDataModelsResponse'] = ResolversParentTypes['ListDataModelsResponse']
> = {
  models?: Resolver<Array<ResolversTypes['DataModel']>, ParentType, ContextType>;
  paging?: Resolver<ResolversTypes['PagingData'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListDetectionsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListDetectionsResponse'] = ResolversParentTypes['ListDetectionsResponse']
> = {
  detections?: Resolver<Array<ResolversTypes['Detection']>, ParentType, ContextType>;
  paging?: Resolver<ResolversTypes['PagingData'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListGlobalPythonModulesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListGlobalPythonModulesResponse'] = ResolversParentTypes['ListGlobalPythonModulesResponse']
> = {
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  globals?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['GlobalPythonModule']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListPacksResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListPacksResponse'] = ResolversParentTypes['ListPacksResponse']
> = {
  packs?: Resolver<Array<ResolversTypes['Pack']>, ParentType, ContextType>;
  paging?: Resolver<ResolversTypes['PagingData'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ListResourcesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListResourcesResponse'] = ResolversParentTypes['ListResourcesResponse']
> = {
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  resources?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['ResourceSummary']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type LogAnalysisMetricsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['LogAnalysisMetricsResponse'] = ResolversParentTypes['LogAnalysisMetricsResponse']
> = {
  eventsProcessed?: Resolver<ResolversTypes['LongSeriesData'], ParentType, ContextType>;
  alertsBySeverity?: Resolver<ResolversTypes['LongSeriesData'], ParentType, ContextType>;
  totalAlertsDelta?: Resolver<Array<ResolversTypes['SingleValue']>, ParentType, ContextType>;
  alertsByRuleID?: Resolver<Array<ResolversTypes['SingleValue']>, ParentType, ContextType>;
  fromDate?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  toDate?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  intervalMinutes?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type LogIntegrationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['LogIntegration'] = ResolversParentTypes['LogIntegration']
> = {
  __resolveType: TypeResolveFn<
    'S3LogIntegration' | 'SqsLogSourceIntegration',
    ParentType,
    ContextType
  >;
};

export interface LongScalarConfig extends GraphQLScalarTypeConfig<ResolversTypes['Long'], any> {
  name: 'Long';
}

export type LongSeriesResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['LongSeries'] = ResolversParentTypes['LongSeries']
> = {
  label?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  values?: Resolver<Array<ResolversTypes['Long']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type LongSeriesDataResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['LongSeriesData'] = ResolversParentTypes['LongSeriesData']
> = {
  timestamps?: Resolver<Array<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  series?: Resolver<Array<ResolversTypes['LongSeries']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type MsTeamsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['MsTeamsConfig'] = ResolversParentTypes['MsTeamsConfig']
> = {
  webhookURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type MutationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Mutation'] = ResolversParentTypes['Mutation']
> = {
  addCustomLog?: Resolver<
    ResolversTypes['GetCustomLogOutput'],
    ParentType,
    ContextType,
    RequireFields<MutationAddCustomLogArgs, 'input'>
  >;
  addDataModel?: Resolver<
    ResolversTypes['DataModel'],
    ParentType,
    ContextType,
    RequireFields<MutationAddDataModelArgs, 'input'>
  >;
  addDestination?: Resolver<
    Maybe<ResolversTypes['Destination']>,
    ParentType,
    ContextType,
    RequireFields<MutationAddDestinationArgs, 'input'>
  >;
  addComplianceIntegration?: Resolver<
    ResolversTypes['ComplianceIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationAddComplianceIntegrationArgs, 'input'>
  >;
  addS3LogIntegration?: Resolver<
    ResolversTypes['S3LogIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationAddS3LogIntegrationArgs, 'input'>
  >;
  addSqsLogIntegration?: Resolver<
    ResolversTypes['SqsLogSourceIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationAddSqsLogIntegrationArgs, 'input'>
  >;
  addPolicy?: Resolver<
    ResolversTypes['Policy'],
    ParentType,
    ContextType,
    RequireFields<MutationAddPolicyArgs, 'input'>
  >;
  addRule?: Resolver<
    ResolversTypes['Rule'],
    ParentType,
    ContextType,
    RequireFields<MutationAddRuleArgs, 'input'>
  >;
  addGlobalPythonModule?: Resolver<
    ResolversTypes['GlobalPythonModule'],
    ParentType,
    ContextType,
    RequireFields<MutationAddGlobalPythonModuleArgs, 'input'>
  >;
  deleteDataModel?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteDataModelArgs, 'input'>
  >;
  deleteDetections?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteDetectionsArgs, 'input'>
  >;
  deleteDestination?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteDestinationArgs, 'id'>
  >;
  deleteComplianceIntegration?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteComplianceIntegrationArgs, 'id'>
  >;
  deleteCustomLog?: Resolver<
    ResolversTypes['DeleteCustomLogOutput'],
    ParentType,
    ContextType,
    RequireFields<MutationDeleteCustomLogArgs, never>
  >;
  deleteLogIntegration?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteLogIntegrationArgs, 'id'>
  >;
  deleteGlobalPythonModule?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteGlobalPythonModuleArgs, 'input'>
  >;
  deleteUser?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteUserArgs, 'id'>
  >;
  inviteUser?: Resolver<
    ResolversTypes['User'],
    ParentType,
    ContextType,
    RequireFields<MutationInviteUserArgs, never>
  >;
  remediateResource?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationRemediateResourceArgs, 'input'>
  >;
  deliverAlert?: Resolver<
    ResolversTypes['AlertSummary'],
    ParentType,
    ContextType,
    RequireFields<MutationDeliverAlertArgs, 'input'>
  >;
  resetUserPassword?: Resolver<
    ResolversTypes['User'],
    ParentType,
    ContextType,
    RequireFields<MutationResetUserPasswordArgs, 'id'>
  >;
  suppressPolicies?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationSuppressPoliciesArgs, 'input'>
  >;
  testPolicy?: Resolver<
    ResolversTypes['TestPolicyResponse'],
    ParentType,
    ContextType,
    RequireFields<MutationTestPolicyArgs, 'input'>
  >;
  testRule?: Resolver<
    ResolversTypes['TestRuleResponse'],
    ParentType,
    ContextType,
    RequireFields<MutationTestRuleArgs, 'input'>
  >;
  updateAlertStatus?: Resolver<
    Array<ResolversTypes['AlertSummary']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateAlertStatusArgs, 'input'>
  >;
  updateDataModel?: Resolver<
    ResolversTypes['DataModel'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateDataModelArgs, 'input'>
  >;
  updateCustomLog?: Resolver<
    ResolversTypes['GetCustomLogOutput'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateCustomLogArgs, 'input'>
  >;
  updateDestination?: Resolver<
    Maybe<ResolversTypes['Destination']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateDestinationArgs, 'input'>
  >;
  updateComplianceIntegration?: Resolver<
    ResolversTypes['ComplianceIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateComplianceIntegrationArgs, 'input'>
  >;
  updateS3LogIntegration?: Resolver<
    ResolversTypes['S3LogIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateS3LogIntegrationArgs, 'input'>
  >;
  updateSqsLogIntegration?: Resolver<
    ResolversTypes['SqsLogSourceIntegration'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateSqsLogIntegrationArgs, 'input'>
  >;
  updateGeneralSettings?: Resolver<
    ResolversTypes['GeneralSettings'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateGeneralSettingsArgs, 'input'>
  >;
  updatePolicy?: Resolver<
    ResolversTypes['Policy'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdatePolicyArgs, 'input'>
  >;
  updateRule?: Resolver<
    ResolversTypes['Rule'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateRuleArgs, 'input'>
  >;
  updateUser?: Resolver<
    ResolversTypes['User'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateUserArgs, 'input'>
  >;
  uploadDetections?: Resolver<
    Maybe<ResolversTypes['UploadDetectionsResponse']>,
    ParentType,
    ContextType,
    RequireFields<MutationUploadDetectionsArgs, 'input'>
  >;
  updateGlobalPythonlModule?: Resolver<
    ResolversTypes['GlobalPythonModule'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateGlobalPythonlModuleArgs, 'input'>
  >;
  updatePack?: Resolver<
    ResolversTypes['Pack'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdatePackArgs, 'input'>
  >;
};

export type OpsgenieConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['OpsgenieConfig'] = ResolversParentTypes['OpsgenieConfig']
> = {
  apiKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  serviceRegion?: Resolver<ResolversTypes['OpsgenieServiceRegionEnum'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type OrganizationReportBySeverityResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['OrganizationReportBySeverity'] = ResolversParentTypes['OrganizationReportBySeverity']
> = {
  info?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  low?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  medium?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  high?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  critical?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type OrganizationStatsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['OrganizationStatsResponse'] = ResolversParentTypes['OrganizationStatsResponse']
> = {
  appliedPolicies?: Resolver<
    Maybe<ResolversTypes['OrganizationReportBySeverity']>,
    ParentType,
    ContextType
  >;
  scannedResources?: Resolver<Maybe<ResolversTypes['ScannedResources']>, ParentType, ContextType>;
  topFailingPolicies?: Resolver<Array<ResolversTypes['Policy']>, ParentType, ContextType>;
  topFailingResources?: Resolver<Array<ResolversTypes['ResourceSummary']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PackResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Pack'] = ResolversParentTypes['Pack']
> = {
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  enabled?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  updateAvailable?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  description?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  displayName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  packVersion?: Resolver<ResolversTypes['PackVersion'], ParentType, ContextType>;
  availableVersions?: Resolver<Array<ResolversTypes['PackVersion']>, ParentType, ContextType>;
  createdBy?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModifiedBy?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  lastModified?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  detectionsPatterns?: Resolver<ResolversTypes['PackDetectionsPatterns'], ParentType, ContextType>;
  detectionTypes?: Resolver<ResolversTypes['DetectionTypes'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PackDetectionsPatternsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PackDetectionsPatterns'] = ResolversParentTypes['PackDetectionsPatterns']
> = {
  IDs?: Resolver<Maybe<Array<ResolversTypes['ID']>>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PackVersionResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PackVersion'] = ResolversParentTypes['PackVersion']
> = {
  id?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  name?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PagerDutyConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PagerDutyConfig'] = ResolversParentTypes['PagerDutyConfig']
> = {
  integrationKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PagingDataResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PagingData'] = ResolversParentTypes['PagingData']
> = {
  thisPage?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  totalPages?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  totalItems?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type PolicyResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Policy'] = ResolversParentTypes['Policy']
> = {
  autoRemediationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  autoRemediationParameters?: Resolver<Maybe<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  body?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastModifiedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  outputIds?: Resolver<Array<ResolversTypes['ID']>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  resourceTypes?: Resolver<Maybe<Array<ResolversTypes['String']>>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  suppressions?: Resolver<Maybe<Array<ResolversTypes['String']>>, ParentType, ContextType>;
  tags?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  tests?: Resolver<Array<ResolversTypes['DetectionTestDefinition']>, ParentType, ContextType>;
  versionId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  analysisType?: Resolver<ResolversTypes['DetectionTypeEnum'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type QueryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Query'] = ResolversParentTypes['Query']
> = {
  alert?: Resolver<
    Maybe<ResolversTypes['AlertDetails']>,
    ParentType,
    ContextType,
    RequireFields<QueryAlertArgs, 'input'>
  >;
  alerts?: Resolver<
    Maybe<ResolversTypes['ListAlertsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryAlertsArgs, never>
  >;
  detections?: Resolver<
    ResolversTypes['ListDetectionsResponse'],
    ParentType,
    ContextType,
    RequireFields<QueryDetectionsArgs, never>
  >;
  sendTestAlert?: Resolver<
    Array<Maybe<ResolversTypes['DeliveryResponse']>>,
    ParentType,
    ContextType,
    RequireFields<QuerySendTestAlertArgs, 'input'>
  >;
  destination?: Resolver<
    Maybe<ResolversTypes['Destination']>,
    ParentType,
    ContextType,
    RequireFields<QueryDestinationArgs, 'id'>
  >;
  destinations?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['Destination']>>>,
    ParentType,
    ContextType
  >;
  generalSettings?: Resolver<ResolversTypes['GeneralSettings'], ParentType, ContextType>;
  getComplianceIntegration?: Resolver<
    ResolversTypes['ComplianceIntegration'],
    ParentType,
    ContextType,
    RequireFields<QueryGetComplianceIntegrationArgs, 'id'>
  >;
  getComplianceIntegrationTemplate?: Resolver<
    ResolversTypes['IntegrationTemplate'],
    ParentType,
    ContextType,
    RequireFields<QueryGetComplianceIntegrationTemplateArgs, 'input'>
  >;
  getDataModel?: Resolver<
    Maybe<ResolversTypes['DataModel']>,
    ParentType,
    ContextType,
    RequireFields<QueryGetDataModelArgs, 'id'>
  >;
  getS3LogIntegration?: Resolver<
    ResolversTypes['S3LogIntegration'],
    ParentType,
    ContextType,
    RequireFields<QueryGetS3LogIntegrationArgs, 'id'>
  >;
  getS3LogIntegrationTemplate?: Resolver<
    ResolversTypes['IntegrationTemplate'],
    ParentType,
    ContextType,
    RequireFields<QueryGetS3LogIntegrationTemplateArgs, 'input'>
  >;
  getSqsLogIntegration?: Resolver<
    ResolversTypes['SqsLogSourceIntegration'],
    ParentType,
    ContextType,
    RequireFields<QueryGetSqsLogIntegrationArgs, 'id'>
  >;
  remediations?: Resolver<Maybe<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  resource?: Resolver<
    Maybe<ResolversTypes['ResourceDetails']>,
    ParentType,
    ContextType,
    RequireFields<QueryResourceArgs, 'input'>
  >;
  resources?: Resolver<
    Maybe<ResolversTypes['ListResourcesResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryResourcesArgs, never>
  >;
  resourcesForPolicy?: Resolver<
    Maybe<ResolversTypes['ListComplianceItemsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryResourcesForPolicyArgs, 'input'>
  >;
  getGlobalPythonModule?: Resolver<
    ResolversTypes['GlobalPythonModule'],
    ParentType,
    ContextType,
    RequireFields<QueryGetGlobalPythonModuleArgs, 'input'>
  >;
  policy?: Resolver<
    Maybe<ResolversTypes['Policy']>,
    ParentType,
    ContextType,
    RequireFields<QueryPolicyArgs, 'input'>
  >;
  policiesForResource?: Resolver<
    Maybe<ResolversTypes['ListComplianceItemsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryPoliciesForResourceArgs, never>
  >;
  listAvailableLogTypes?: Resolver<
    ResolversTypes['ListAvailableLogTypesResponse'],
    ParentType,
    ContextType
  >;
  listComplianceIntegrations?: Resolver<
    Array<ResolversTypes['ComplianceIntegration']>,
    ParentType,
    ContextType
  >;
  listDataModels?: Resolver<
    ResolversTypes['ListDataModelsResponse'],
    ParentType,
    ContextType,
    RequireFields<QueryListDataModelsArgs, 'input'>
  >;
  listLogIntegrations?: Resolver<Array<ResolversTypes['LogIntegration']>, ParentType, ContextType>;
  listPacks?: Resolver<
    ResolversTypes['ListPacksResponse'],
    ParentType,
    ContextType,
    RequireFields<QueryListPacksArgs, never>
  >;
  organizationStats?: Resolver<
    Maybe<ResolversTypes['OrganizationStatsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryOrganizationStatsArgs, never>
  >;
  getLogAnalysisMetrics?: Resolver<
    ResolversTypes['LogAnalysisMetricsResponse'],
    ParentType,
    ContextType,
    RequireFields<QueryGetLogAnalysisMetricsArgs, 'input'>
  >;
  rule?: Resolver<
    Maybe<ResolversTypes['Rule']>,
    ParentType,
    ContextType,
    RequireFields<QueryRuleArgs, 'input'>
  >;
  listGlobalPythonModules?: Resolver<
    ResolversTypes['ListGlobalPythonModulesResponse'],
    ParentType,
    ContextType,
    RequireFields<QueryListGlobalPythonModulesArgs, 'input'>
  >;
  users?: Resolver<Array<ResolversTypes['User']>, ParentType, ContextType>;
  getCustomLog?: Resolver<
    ResolversTypes['GetCustomLogOutput'],
    ParentType,
    ContextType,
    RequireFields<QueryGetCustomLogArgs, 'input'>
  >;
  listCustomLogs?: Resolver<Array<ResolversTypes['CustomLogRecord']>, ParentType, ContextType>;
};

export type ResourceDetailsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ResourceDetails'] = ResolversParentTypes['ResourceDetails']
> = {
  attributes?: Resolver<Maybe<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  deleted?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  expiresAt?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  id?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  integrationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ResourceSummaryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ResourceSummary'] = ResolversParentTypes['ResourceSummary']
> = {
  id?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  integrationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  deleted?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type RuleResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Rule'] = ResolversParentTypes['Rule']
> = {
  body?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  dedupPeriodMinutes?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  threshold?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastModifiedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  logTypes?: Resolver<Maybe<Array<ResolversTypes['String']>>, ParentType, ContextType>;
  outputIds?: Resolver<Array<ResolversTypes['ID']>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<ResolversTypes['SeverityEnum'], ParentType, ContextType>;
  tags?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  tests?: Resolver<Array<ResolversTypes['DetectionTestDefinition']>, ParentType, ContextType>;
  versionId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  analysisType?: Resolver<ResolversTypes['DetectionTypeEnum'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type S3LogIntegrationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['S3LogIntegration'] = ResolversParentTypes['S3LogIntegration']
> = {
  awsAccountId?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  createdAtTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationType?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  integrationLabel?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastEventReceived?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  s3Bucket?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  s3Prefix?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  kmsKey?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  s3PrefixLogTypes?: Resolver<Array<ResolversTypes['S3PrefixLogTypes']>, ParentType, ContextType>;
  managedBucketNotifications?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  notificationsConfigurationSucceeded?: Resolver<
    ResolversTypes['Boolean'],
    ParentType,
    ContextType
  >;
  health?: Resolver<ResolversTypes['S3LogIntegrationHealth'], ParentType, ContextType>;
  stackName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type S3LogIntegrationHealthResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['S3LogIntegrationHealth'] = ResolversParentTypes['S3LogIntegrationHealth']
> = {
  processingRoleStatus?: Resolver<
    ResolversTypes['IntegrationItemHealthStatus'],
    ParentType,
    ContextType
  >;
  s3BucketStatus?: Resolver<ResolversTypes['IntegrationItemHealthStatus'], ParentType, ContextType>;
  kmsKeyStatus?: Resolver<ResolversTypes['IntegrationItemHealthStatus'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type S3PrefixLogTypesResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['S3PrefixLogTypes'] = ResolversParentTypes['S3PrefixLogTypes']
> = {
  prefix?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ScannedResourcesResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ScannedResources'] = ResolversParentTypes['ScannedResources']
> = {
  byType?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['ScannedResourceStats']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type ScannedResourceStatsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ScannedResourceStats'] = ResolversParentTypes['ScannedResourceStats']
> = {
  count?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SingleValueResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SingleValue'] = ResolversParentTypes['SingleValue']
> = {
  label?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  value?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SlackConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SlackConfig'] = ResolversParentTypes['SlackConfig']
> = {
  webhookURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SnsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SnsConfig'] = ResolversParentTypes['SnsConfig']
> = {
  topicArn?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SqsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SqsConfig'] = ResolversParentTypes['SqsConfig']
> = {
  logTypes?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  allowedPrincipalArns?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['String']>>>,
    ParentType,
    ContextType
  >;
  allowedSourceArns?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['String']>>>,
    ParentType,
    ContextType
  >;
  queueUrl?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SqsDestinationConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SqsDestinationConfig'] = ResolversParentTypes['SqsDestinationConfig']
> = {
  queueUrl?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SqsLogIntegrationHealthResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SqsLogIntegrationHealth'] = ResolversParentTypes['SqsLogIntegrationHealth']
> = {
  sqsStatus?: Resolver<
    Maybe<ResolversTypes['IntegrationItemHealthStatus']>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type SqsLogSourceIntegrationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SqsLogSourceIntegration'] = ResolversParentTypes['SqsLogSourceIntegration']
> = {
  createdAtTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  createdBy?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  integrationLabel?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  integrationType?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastEventReceived?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  sqsConfig?: Resolver<ResolversTypes['SqsConfig'], ParentType, ContextType>;
  health?: Resolver<ResolversTypes['SqsLogIntegrationHealth'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestDetectionSubRecordResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestDetectionSubRecord'] = ResolversParentTypes['TestDetectionSubRecord']
> = {
  output?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestPolicyRecordResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestPolicyRecord'] = ResolversParentTypes['TestPolicyRecord']
> = {
  id?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  name?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  passed?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  functions?: Resolver<ResolversTypes['TestPolicyRecordFunctions'], ParentType, ContextType>;
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestPolicyRecordFunctionsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestPolicyRecordFunctions'] = ResolversParentTypes['TestPolicyRecordFunctions']
> = {
  policyFunction?: Resolver<ResolversTypes['TestDetectionSubRecord'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestPolicyResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestPolicyResponse'] = ResolversParentTypes['TestPolicyResponse']
> = {
  results?: Resolver<Array<ResolversTypes['TestPolicyRecord']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestRecordResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestRecord'] = ResolversParentTypes['TestRecord']
> = {
  __resolveType: TypeResolveFn<'TestPolicyRecord' | 'TestRuleRecord', ParentType, ContextType>;
  id?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  name?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  passed?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
};

export type TestRuleRecordResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestRuleRecord'] = ResolversParentTypes['TestRuleRecord']
> = {
  id?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  name?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  passed?: Resolver<ResolversTypes['Boolean'], ParentType, ContextType>;
  functions?: Resolver<ResolversTypes['TestRuleRecordFunctions'], ParentType, ContextType>;
  error?: Resolver<Maybe<ResolversTypes['Error']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestRuleRecordFunctionsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestRuleRecordFunctions'] = ResolversParentTypes['TestRuleRecordFunctions']
> = {
  ruleFunction?: Resolver<ResolversTypes['TestDetectionSubRecord'], ParentType, ContextType>;
  titleFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  dedupFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  alertContextFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  descriptionFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  destinationsFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  referenceFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  runbookFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  severityFunction?: Resolver<
    Maybe<ResolversTypes['TestDetectionSubRecord']>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type TestRuleResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestRuleResponse'] = ResolversParentTypes['TestRuleResponse']
> = {
  results?: Resolver<Array<ResolversTypes['TestRuleRecord']>, ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type UploadDetectionsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['UploadDetectionsResponse'] = ResolversParentTypes['UploadDetectionsResponse']
> = {
  totalPolicies?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  newPolicies?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  modifiedPolicies?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  totalRules?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  newRules?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  modifiedRules?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  totalGlobals?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  newGlobals?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  modifiedGlobals?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  totalDataModels?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  newDataModels?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  modifiedDataModels?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type UserResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['User'] = ResolversParentTypes['User']
> = {
  givenName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  familyName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  email?: Resolver<ResolversTypes['AWSEmail'], ParentType, ContextType>;
  createdAt?: Resolver<ResolversTypes['AWSTimestamp'], ParentType, ContextType>;
  status?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: IsTypeOfResolverFn<ParentType>;
};

export type Resolvers<ContextType = any> = {
  ActiveSuppressCount?: ActiveSuppressCountResolvers<ContextType>;
  Alert?: AlertResolvers;
  AlertDetails?: AlertDetailsResolvers<ContextType>;
  AlertDetailsDetectionInfo?: AlertDetailsDetectionInfoResolvers;
  AlertDetailsRuleInfo?: AlertDetailsRuleInfoResolvers<ContextType>;
  AlertSummary?: AlertSummaryResolvers<ContextType>;
  AlertSummaryDetectionInfo?: AlertSummaryDetectionInfoResolvers;
  AlertSummaryPolicyInfo?: AlertSummaryPolicyInfoResolvers<ContextType>;
  AlertSummaryRuleInfo?: AlertSummaryRuleInfoResolvers<ContextType>;
  AsanaConfig?: AsanaConfigResolvers<ContextType>;
  AWSDateTime?: GraphQLScalarType;
  AWSEmail?: GraphQLScalarType;
  AWSJSON?: GraphQLScalarType;
  AWSTimestamp?: GraphQLScalarType;
  ComplianceIntegration?: ComplianceIntegrationResolvers<ContextType>;
  ComplianceIntegrationHealth?: ComplianceIntegrationHealthResolvers<ContextType>;
  ComplianceItem?: ComplianceItemResolvers<ContextType>;
  ComplianceStatusCounts?: ComplianceStatusCountsResolvers<ContextType>;
  CustomLogOutput?: CustomLogOutputResolvers<ContextType>;
  CustomLogRecord?: CustomLogRecordResolvers<ContextType>;
  CustomWebhookConfig?: CustomWebhookConfigResolvers<ContextType>;
  DataModel?: DataModelResolvers<ContextType>;
  DataModelMapping?: DataModelMappingResolvers<ContextType>;
  DeleteCustomLogOutput?: DeleteCustomLogOutputResolvers<ContextType>;
  DeliveryResponse?: DeliveryResponseResolvers<ContextType>;
  Destination?: DestinationResolvers<ContextType>;
  DestinationConfig?: DestinationConfigResolvers<ContextType>;
  Detection?: DetectionResolvers;
  DetectionTestDefinition?: DetectionTestDefinitionResolvers<ContextType>;
  DetectionTypes?: DetectionTypesResolvers<ContextType>;
  Error?: ErrorResolvers<ContextType>;
  FloatSeries?: FloatSeriesResolvers<ContextType>;
  FloatSeriesData?: FloatSeriesDataResolvers<ContextType>;
  GeneralSettings?: GeneralSettingsResolvers<ContextType>;
  GetCustomLogOutput?: GetCustomLogOutputResolvers<ContextType>;
  GithubConfig?: GithubConfigResolvers<ContextType>;
  GlobalPythonModule?: GlobalPythonModuleResolvers<ContextType>;
  IntegrationItemHealthStatus?: IntegrationItemHealthStatusResolvers<ContextType>;
  IntegrationTemplate?: IntegrationTemplateResolvers<ContextType>;
  JiraConfig?: JiraConfigResolvers<ContextType>;
  ListAlertsResponse?: ListAlertsResponseResolvers<ContextType>;
  ListAvailableLogTypesResponse?: ListAvailableLogTypesResponseResolvers<ContextType>;
  ListComplianceItemsResponse?: ListComplianceItemsResponseResolvers<ContextType>;
  ListDataModelsResponse?: ListDataModelsResponseResolvers<ContextType>;
  ListDetectionsResponse?: ListDetectionsResponseResolvers<ContextType>;
  ListGlobalPythonModulesResponse?: ListGlobalPythonModulesResponseResolvers<ContextType>;
  ListPacksResponse?: ListPacksResponseResolvers<ContextType>;
  ListResourcesResponse?: ListResourcesResponseResolvers<ContextType>;
  LogAnalysisMetricsResponse?: LogAnalysisMetricsResponseResolvers<ContextType>;
  LogIntegration?: LogIntegrationResolvers;
  Long?: GraphQLScalarType;
  LongSeries?: LongSeriesResolvers<ContextType>;
  LongSeriesData?: LongSeriesDataResolvers<ContextType>;
  MsTeamsConfig?: MsTeamsConfigResolvers<ContextType>;
  Mutation?: MutationResolvers<ContextType>;
  OpsgenieConfig?: OpsgenieConfigResolvers<ContextType>;
  OrganizationReportBySeverity?: OrganizationReportBySeverityResolvers<ContextType>;
  OrganizationStatsResponse?: OrganizationStatsResponseResolvers<ContextType>;
  Pack?: PackResolvers<ContextType>;
  PackDetectionsPatterns?: PackDetectionsPatternsResolvers<ContextType>;
  PackVersion?: PackVersionResolvers<ContextType>;
  PagerDutyConfig?: PagerDutyConfigResolvers<ContextType>;
  PagingData?: PagingDataResolvers<ContextType>;
  Policy?: PolicyResolvers<ContextType>;
  Query?: QueryResolvers<ContextType>;
  ResourceDetails?: ResourceDetailsResolvers<ContextType>;
  ResourceSummary?: ResourceSummaryResolvers<ContextType>;
  Rule?: RuleResolvers<ContextType>;
  S3LogIntegration?: S3LogIntegrationResolvers<ContextType>;
  S3LogIntegrationHealth?: S3LogIntegrationHealthResolvers<ContextType>;
  S3PrefixLogTypes?: S3PrefixLogTypesResolvers<ContextType>;
  ScannedResources?: ScannedResourcesResolvers<ContextType>;
  ScannedResourceStats?: ScannedResourceStatsResolvers<ContextType>;
  SingleValue?: SingleValueResolvers<ContextType>;
  SlackConfig?: SlackConfigResolvers<ContextType>;
  SnsConfig?: SnsConfigResolvers<ContextType>;
  SqsConfig?: SqsConfigResolvers<ContextType>;
  SqsDestinationConfig?: SqsDestinationConfigResolvers<ContextType>;
  SqsLogIntegrationHealth?: SqsLogIntegrationHealthResolvers<ContextType>;
  SqsLogSourceIntegration?: SqsLogSourceIntegrationResolvers<ContextType>;
  TestDetectionSubRecord?: TestDetectionSubRecordResolvers<ContextType>;
  TestPolicyRecord?: TestPolicyRecordResolvers<ContextType>;
  TestPolicyRecordFunctions?: TestPolicyRecordFunctionsResolvers<ContextType>;
  TestPolicyResponse?: TestPolicyResponseResolvers<ContextType>;
  TestRecord?: TestRecordResolvers;
  TestRuleRecord?: TestRuleRecordResolvers<ContextType>;
  TestRuleRecordFunctions?: TestRuleRecordFunctionsResolvers<ContextType>;
  TestRuleResponse?: TestRuleResponseResolvers<ContextType>;
  UploadDetectionsResponse?: UploadDetectionsResponseResolvers<ContextType>;
  User?: UserResolvers<ContextType>;
};

/**
 * @deprecated
 * Use "Resolvers" root object instead. If you wish to get "IResolvers", add "typesPrefix: I" to your config.
 */
export type IResolvers<ContextType = any> = Resolvers<ContextType>;
