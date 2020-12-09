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

import {
  ActiveSuppressCount,
  AddComplianceIntegrationInput,
  AddGlobalPythonModuleInput,
  AddPolicyInput,
  AddRuleInput,
  AddS3LogIntegrationInput,
  AddSqsLogIntegrationInput,
  AlertDetails,
  AlertDetailsRuleInfo,
  AlertSummary,
  AlertSummaryPolicyInfo,
  AlertSummaryRuleInfo,
  AsanaConfig,
  AsanaConfigInput,
  ComplianceIntegration,
  ComplianceIntegrationHealth,
  ComplianceItem,
  ComplianceStatusCounts,
  CustomWebhookConfig,
  CustomWebhookConfigInput,
  DeleteGlobalPythonInputItem,
  DeleteGlobalPythonModuleInput,
  DeletePolicyInput,
  DeletePolicyInputItem,
  DeleteRuleInput,
  DeleteRuleInputItem,
  DeliverAlertInput,
  DeliveryResponse,
  Destination,
  DestinationConfig,
  DestinationConfigInput,
  DestinationInput,
  DetectionTestDefinition,
  DetectionTestDefinitionInput,
  Error,
  FloatSeries,
  FloatSeriesData,
  GeneralSettings,
  GetAlertInput,
  GetComplianceIntegrationTemplateInput,
  GetGlobalPythonModuleInput,
  GetPolicyInput,
  GetResourceInput,
  GetRuleInput,
  GetS3LogIntegrationTemplateInput,
  GithubConfig,
  GithubConfigInput,
  GlobalPythonModule,
  IntegrationItemHealthStatus,
  IntegrationTemplate,
  InviteUserInput,
  JiraConfig,
  JiraConfigInput,
  ListAlertsInput,
  ListAlertsResponse,
  ListAvailableLogTypesResponse,
  ListComplianceItemsResponse,
  ListGlobalPythonModuleInput,
  ListGlobalPythonModulesResponse,
  ListPoliciesInput,
  ListPoliciesResponse,
  ListResourcesInput,
  ListResourcesResponse,
  ListRulesInput,
  ListRulesResponse,
  LogAnalysisMetricsInput,
  LogAnalysisMetricsResponse,
  LongSeries,
  LongSeriesData,
  ModifyGlobalPythonModuleInput,
  MsTeamsConfig,
  MsTeamsConfigInput,
  OpsgenieConfig,
  OpsgenieConfigInput,
  OrganizationReportBySeverity,
  OrganizationStatsInput,
  OrganizationStatsResponse,
  PagerDutyConfig,
  PagerDutyConfigInput,
  PagingData,
  PoliciesForResourceInput,
  PolicyDetails,
  PolicySummary,
  RemediateResourceInput,
  ResourceDetails,
  ResourcesForPolicyInput,
  ResourceSummary,
  RuleDetails,
  RuleSummary,
  S3LogIntegration,
  S3LogIntegrationHealth,
  S3PrefixLogTypes,
  S3PrefixLogTypesInput,
  ScannedResources,
  ScannedResourceStats,
  SendTestAlertInput,
  SingleValue,
  SlackConfig,
  SlackConfigInput,
  SnsConfig,
  SnsConfigInput,
  SqsConfig,
  SqsConfigInput,
  SqsDestinationConfig,
  SqsLogConfigInput,
  SqsLogIntegrationHealth,
  SqsLogSourceIntegration,
  SuppressPoliciesInput,
  TestDetectionSubRecord,
  TestPolicyInput,
  TestPolicyRecord,
  TestPolicyRecordFunctions,
  TestPolicyResponse,
  TestRuleInput,
  TestRuleRecord,
  TestRuleRecordFunctions,
  TestRuleResponse,
  UpdateAlertStatusInput,
  UpdateComplianceIntegrationInput,
  UpdateGeneralSettingsInput,
  UpdatePolicyInput,
  UpdateRuleInput,
  UpdateS3LogIntegrationInput,
  UpdateSqsLogIntegrationInput,
  UpdateUserInput,
  UploadPoliciesInput,
  UploadPoliciesResponse,
  User,
  AccountTypeEnum,
  AlertDetailsDetectionInfo,
  AlertStatusesEnum,
  AlertSummaryDetectionInfo,
  AlertTypesEnum,
  ComplianceStatusEnum,
  DestinationTypeEnum,
  ListAlertsSortFieldsEnum,
  ListPoliciesSortFieldsEnum,
  ListResourcesSortFieldsEnum,
  ListRulesSortFieldsEnum,
  LogIntegration,
  OpsgenieServiceRegionEnum,
  SeverityEnum,
  SortDirEnum,
} from '../../__generated__/schema';
import { generateRandomArray, faker } from 'test-utils';

export const buildActiveSuppressCount = (
  overrides: Partial<ActiveSuppressCount> = {}
): ActiveSuppressCount => {
  return {
    __typename: 'ActiveSuppressCount',
    active: 'active' in overrides ? overrides.active : buildComplianceStatusCounts(),
    suppressed: 'suppressed' in overrides ? overrides.suppressed : buildComplianceStatusCounts(),
  };
};

export const buildAddComplianceIntegrationInput = (
  overrides: Partial<AddComplianceIntegrationInput> = {}
): AddComplianceIntegrationInput => {
  return {
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'protocol',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'withdrawal',
    remediationEnabled: 'remediationEnabled' in overrides ? overrides.remediationEnabled : false,
    cweEnabled: 'cweEnabled' in overrides ? overrides.cweEnabled : false,
  };
};

export const buildAddGlobalPythonModuleInput = (
  overrides: Partial<AddGlobalPythonModuleInput> = {}
): AddGlobalPythonModuleInput => {
  return {
    id: 'id' in overrides ? overrides.id : '6b0f1c64-e650-48e8-abcf-37c23c6cf854',
    description: 'description' in overrides ? overrides.description : 'Dynamic',
    body: 'body' in overrides ? overrides.body : 'methodologies',
  };
};

export const buildAddPolicyInput = (overrides: Partial<AddPolicyInput> = {}): AddPolicyInput => {
  return {
    autoRemediationId:
      'autoRemediationId' in overrides
        ? overrides.autoRemediationId
        : '2ddec795-4cf0-445d-b800-4d02470180f2',
    autoRemediationParameters:
      'autoRemediationParameters' in overrides ? overrides.autoRemediationParameters : '"bar"',
    body: 'body' in overrides ? overrides.body : 'Fantastic Concrete Table',
    description: 'description' in overrides ? overrides.description : 'Qatar',
    displayName: 'displayName' in overrides ? overrides.displayName : 'matrix',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    id: 'id' in overrides ? overrides.id : '7612f488-c028-4e4f-904f-07e707ce7bdd',
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['16ca6d99-9a12-404b-aef5-9e522075db0d'],
    reference: 'reference' in overrides ? overrides.reference : 'Clothing',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['Digitized'],
    runbook: 'runbook' in overrides ? overrides.runbook : 'HTTP',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.High,
    suppressions: 'suppressions' in overrides ? overrides.suppressions : ['Tunisian Dinar'],
    tags: 'tags' in overrides ? overrides.tags : ['Security'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildAddRuleInput = (overrides: Partial<AddRuleInput> = {}): AddRuleInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'microchip',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 429,
    threshold: 'threshold' in overrides ? overrides.threshold : 140,
    description: 'description' in overrides ? overrides.description : 'purple',
    displayName: 'displayName' in overrides ? overrides.displayName : 'Investment Account',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    id: 'id' in overrides ? overrides.id : 'f9463be1-4ef2-4950-b272-31540bb0cff3',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['end-to-end'],
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['0f6aac24-85db-4208-9f04-5f9cae908a5b'],
    reference: 'reference' in overrides ? overrides.reference : 'mobile',
    runbook: 'runbook' in overrides ? overrides.runbook : 'Practical Granite Salad',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Medium,
    tags: 'tags' in overrides ? overrides.tags : ['Way'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildAddS3LogIntegrationInput = (
  overrides: Partial<AddS3LogIntegrationInput> = {}
): AddS3LogIntegrationInput => {
  return {
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'Ireland',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'payment',
    s3Bucket: 's3Bucket' in overrides ? overrides.s3Bucket : 'backing up',
    kmsKey: 'kmsKey' in overrides ? overrides.kmsKey : 'Personal Loan Account',
    s3PrefixLogTypes:
      's3PrefixLogTypes' in overrides ? overrides.s3PrefixLogTypes : [buildS3PrefixLogTypesInput()],
  };
};

export const buildAddSqsLogIntegrationInput = (
  overrides: Partial<AddSqsLogIntegrationInput> = {}
): AddSqsLogIntegrationInput => {
  return {
    integrationLabel:
      'integrationLabel' in overrides ? overrides.integrationLabel : 'data-warehouse',
    sqsConfig: 'sqsConfig' in overrides ? overrides.sqsConfig : buildSqsLogConfigInput(),
  };
};

export const buildAlertDetails = (overrides: Partial<AlertDetails> = {}): AlertDetails => {
  return {
    __typename: 'AlertDetails',
    alertId: 'alertId' in overrides ? overrides.alertId : '2c5aa76d-eb43-49f0-a65c-50e4daa756a4',
    creationTime: 'creationTime' in overrides ? overrides.creationTime : '2020-10-28T02:06:29.865Z',
    deliveryResponses:
      'deliveryResponses' in overrides ? overrides.deliveryResponses : [buildDeliveryResponse()],
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Critical,
    status: 'status' in overrides ? overrides.status : AlertStatusesEnum.Closed,
    title: 'title' in overrides ? overrides.title : 'Steel',
    type: 'type' in overrides ? overrides.type : AlertTypesEnum.Rule,
    lastUpdatedBy:
      'lastUpdatedBy' in overrides
        ? overrides.lastUpdatedBy
        : '15cffa0a-6a52-49cc-a5d6-d52aa26209ac',
    lastUpdatedByTime:
      'lastUpdatedByTime' in overrides ? overrides.lastUpdatedByTime : '2020-07-02T20:00:23.050Z',
    updateTime: 'updateTime' in overrides ? overrides.updateTime : '2020-02-22T04:54:35.910Z',
    detection: 'detection' in overrides ? overrides.detection : buildAlertDetailsRuleInfo(),
  };
};

export const buildAlertDetailsRuleInfo = (
  overrides: Partial<AlertDetailsRuleInfo> = {}
): AlertDetailsRuleInfo => {
  return {
    __typename: 'AlertDetailsRuleInfo',
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '17db7258-2d08-4d56-b993-666b8e6db65e',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Baht'],
    eventsMatched: 'eventsMatched' in overrides ? overrides.eventsMatched : 545,
    dedupString: 'dedupString' in overrides ? overrides.dedupString : 'panel',
    events: 'events' in overrides ? overrides.events : ['"car"'],
    eventsLastEvaluatedKey:
      'eventsLastEvaluatedKey' in overrides ? overrides.eventsLastEvaluatedKey : 'index',
  };
};

export const buildAlertSummary = (overrides: Partial<AlertSummary> = {}): AlertSummary => {
  return {
    __typename: 'AlertSummary',
    alertId: 'alertId' in overrides ? overrides.alertId : 'f67b8f04-5fac-404a-93a4-38db29f258ba',
    creationTime: 'creationTime' in overrides ? overrides.creationTime : '2020-08-08T12:15:31.121Z',
    deliveryResponses:
      'deliveryResponses' in overrides ? overrides.deliveryResponses : [buildDeliveryResponse()],
    type: 'type' in overrides ? overrides.type : AlertTypesEnum.RuleError,
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Medium,
    status: 'status' in overrides ? overrides.status : AlertStatusesEnum.Triaged,
    title: 'title' in overrides ? overrides.title : 'indexing',
    lastUpdatedBy:
      'lastUpdatedBy' in overrides
        ? overrides.lastUpdatedBy
        : '2b032d04-ec9e-41cd-9bb7-cb8d0b6eee9e',
    lastUpdatedByTime:
      'lastUpdatedByTime' in overrides ? overrides.lastUpdatedByTime : '2020-07-29T23:42:06.903Z',
    updateTime: 'updateTime' in overrides ? overrides.updateTime : '2020-09-17T19:32:46.882Z',
    detection: 'detection' in overrides ? overrides.detection : buildAlertSummaryRuleInfo(),
  };
};

export const buildAlertSummaryPolicyInfo = (
  overrides: Partial<AlertSummaryPolicyInfo> = {}
): AlertSummaryPolicyInfo => {
  return {
    __typename: 'AlertSummaryPolicyInfo',
    policyId: 'policyId' in overrides ? overrides.policyId : 'a68babd7-7c1c-4dee-a33e-b8009e6d8017',
    resourceId: 'resourceId' in overrides ? overrides.resourceId : '5th generation',
    policySourceId: 'policySourceId' in overrides ? overrides.policySourceId : 'program',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['brand'],
  };
};

export const buildAlertSummaryRuleInfo = (
  overrides: Partial<AlertSummaryRuleInfo> = {}
): AlertSummaryRuleInfo => {
  return {
    __typename: 'AlertSummaryRuleInfo',
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '8780849b-30b8-4ce2-934b-bf033369b110',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Personal Loan Account'],
    eventsMatched: 'eventsMatched' in overrides ? overrides.eventsMatched : 240,
  };
};

export const buildAsanaConfig = (overrides: Partial<AsanaConfig> = {}): AsanaConfig => {
  return {
    __typename: 'AsanaConfig',
    personalAccessToken:
      'personalAccessToken' in overrides ? overrides.personalAccessToken : 'Chief',
    projectGids: 'projectGids' in overrides ? overrides.projectGids : ['Central'],
  };
};

export const buildAsanaConfigInput = (
  overrides: Partial<AsanaConfigInput> = {}
): AsanaConfigInput => {
  return {
    personalAccessToken:
      'personalAccessToken' in overrides ? overrides.personalAccessToken : 'connect',
    projectGids: 'projectGids' in overrides ? overrides.projectGids : ['Executive'],
  };
};

export const buildComplianceIntegration = (
  overrides: Partial<ComplianceIntegration> = {}
): ComplianceIntegration => {
  return {
    __typename: 'ComplianceIntegration',
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'Metrics',
    createdAtTime:
      'createdAtTime' in overrides ? overrides.createdAtTime : '2020-11-23T16:57:57.973Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : '460977ce-2de5-408b-8cd9-69796ea9f675',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : 'd61dbbdd-68fd-4c1d-8a21-508d2115b3d3',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'Movies',
    cweEnabled: 'cweEnabled' in overrides ? overrides.cweEnabled : true,
    remediationEnabled: 'remediationEnabled' in overrides ? overrides.remediationEnabled : false,
    health: 'health' in overrides ? overrides.health : buildComplianceIntegrationHealth(),
    stackName: 'stackName' in overrides ? overrides.stackName : 'Chips',
  };
};

export const buildComplianceIntegrationHealth = (
  overrides: Partial<ComplianceIntegrationHealth> = {}
): ComplianceIntegrationHealth => {
  return {
    __typename: 'ComplianceIntegrationHealth',
    auditRoleStatus:
      'auditRoleStatus' in overrides
        ? overrides.auditRoleStatus
        : buildIntegrationItemHealthStatus(),
    cweRoleStatus:
      'cweRoleStatus' in overrides ? overrides.cweRoleStatus : buildIntegrationItemHealthStatus(),
    remediationRoleStatus:
      'remediationRoleStatus' in overrides
        ? overrides.remediationRoleStatus
        : buildIntegrationItemHealthStatus(),
  };
};

export const buildComplianceItem = (overrides: Partial<ComplianceItem> = {}): ComplianceItem => {
  return {
    __typename: 'ComplianceItem',
    errorMessage: 'errorMessage' in overrides ? overrides.errorMessage : 'functionalities',
    lastUpdated: 'lastUpdated' in overrides ? overrides.lastUpdated : '2020-10-29T15:59:39.128Z',
    policyId: 'policyId' in overrides ? overrides.policyId : '7704cb04-183c-44c9-9d90-8e66b37d8cb7',
    policySeverity:
      'policySeverity' in overrides ? overrides.policySeverity : SeverityEnum.Critical,
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : '89b815e3-cb3b-4df5-8a6e-8f6159ca308a',
    resourceType: 'resourceType' in overrides ? overrides.resourceType : 'Leone',
    status: 'status' in overrides ? overrides.status : ComplianceStatusEnum.Fail,
    suppressed: 'suppressed' in overrides ? overrides.suppressed : true,
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : '0aec2717-f82d-47fc-a2e5-2c2a8cd72160',
  };
};

export const buildComplianceStatusCounts = (
  overrides: Partial<ComplianceStatusCounts> = {}
): ComplianceStatusCounts => {
  return {
    __typename: 'ComplianceStatusCounts',
    error: 'error' in overrides ? overrides.error : 71,
    fail: 'fail' in overrides ? overrides.fail : 488,
    pass: 'pass' in overrides ? overrides.pass : 154,
  };
};

export const buildCustomWebhookConfig = (
  overrides: Partial<CustomWebhookConfig> = {}
): CustomWebhookConfig => {
  return {
    __typename: 'CustomWebhookConfig',
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'web services',
  };
};

export const buildCustomWebhookConfigInput = (
  overrides: Partial<CustomWebhookConfigInput> = {}
): CustomWebhookConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'bypass',
  };
};

export const buildDeleteGlobalPythonInputItem = (
  overrides: Partial<DeleteGlobalPythonInputItem> = {}
): DeleteGlobalPythonInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : '28c248cf-f729-4ac6-af32-da12f186a8bd',
  };
};

export const buildDeleteGlobalPythonModuleInput = (
  overrides: Partial<DeleteGlobalPythonModuleInput> = {}
): DeleteGlobalPythonModuleInput => {
  return {
    globals: 'globals' in overrides ? overrides.globals : [buildDeleteGlobalPythonInputItem()],
  };
};

export const buildDeletePolicyInput = (
  overrides: Partial<DeletePolicyInput> = {}
): DeletePolicyInput => {
  return {
    policies: 'policies' in overrides ? overrides.policies : [buildDeletePolicyInputItem()],
  };
};

export const buildDeletePolicyInputItem = (
  overrides: Partial<DeletePolicyInputItem> = {}
): DeletePolicyInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : 'a5304976-d86e-44d0-abe1-902e2565a38b',
  };
};

export const buildDeleteRuleInput = (overrides: Partial<DeleteRuleInput> = {}): DeleteRuleInput => {
  return {
    rules: 'rules' in overrides ? overrides.rules : [buildDeleteRuleInputItem()],
  };
};

export const buildDeleteRuleInputItem = (
  overrides: Partial<DeleteRuleInputItem> = {}
): DeleteRuleInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : '9c1a40a6-8106-4f56-82b7-b71d4afc0065',
  };
};

export const buildDeliverAlertInput = (
  overrides: Partial<DeliverAlertInput> = {}
): DeliverAlertInput => {
  return {
    alertId: 'alertId' in overrides ? overrides.alertId : '30b3fadd-7760-4b10-8f08-4d180b56cbc8',
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['ce7260ff-2562-4f2d-b5db-362c013dec73'],
  };
};

export const buildDeliveryResponse = (
  overrides: Partial<DeliveryResponse> = {}
): DeliveryResponse => {
  return {
    __typename: 'DeliveryResponse',
    outputId: 'outputId' in overrides ? overrides.outputId : 'bb9f4174-594c-4dc0-9308-f4c28c0e29eb',
    message: 'message' in overrides ? overrides.message : 'Delaware',
    statusCode: 'statusCode' in overrides ? overrides.statusCode : 319,
    success: 'success' in overrides ? overrides.success : true,
    dispatchedAt: 'dispatchedAt' in overrides ? overrides.dispatchedAt : '2020-09-25T00:14:42.514Z',
  };
};

export const buildDestination = (overrides: Partial<Destination> = {}): Destination => {
  return {
    __typename: 'Destination',
    createdBy: 'createdBy' in overrides ? overrides.createdBy : 'best-of-breed',
    creationTime: 'creationTime' in overrides ? overrides.creationTime : '2020-08-01T19:40:18.778Z',
    displayName: 'displayName' in overrides ? overrides.displayName : 'Accountability',
    lastModifiedBy: 'lastModifiedBy' in overrides ? overrides.lastModifiedBy : 'Tasty Granite Bike',
    lastModifiedTime:
      'lastModifiedTime' in overrides ? overrides.lastModifiedTime : '2020-07-05T06:23:49.280Z',
    outputId: 'outputId' in overrides ? overrides.outputId : '8c0eb672-b7bb-4ef0-9d96-a2bc1abe94d7',
    outputType: 'outputType' in overrides ? overrides.outputType : DestinationTypeEnum.Sns,
    outputConfig: 'outputConfig' in overrides ? overrides.outputConfig : buildDestinationConfig(),
    verificationStatus:
      'verificationStatus' in overrides ? overrides.verificationStatus : 'Licensed',
    defaultForSeverity:
      'defaultForSeverity' in overrides ? overrides.defaultForSeverity : [SeverityEnum.Critical],
  };
};

export const buildDestinationConfig = (
  overrides: Partial<DestinationConfig> = {}
): DestinationConfig => {
  return {
    __typename: 'DestinationConfig',
    slack: 'slack' in overrides ? overrides.slack : buildSlackConfig(),
    sns: 'sns' in overrides ? overrides.sns : buildSnsConfig(),
    sqs: 'sqs' in overrides ? overrides.sqs : buildSqsDestinationConfig(),
    pagerDuty: 'pagerDuty' in overrides ? overrides.pagerDuty : buildPagerDutyConfig(),
    github: 'github' in overrides ? overrides.github : buildGithubConfig(),
    jira: 'jira' in overrides ? overrides.jira : buildJiraConfig(),
    opsgenie: 'opsgenie' in overrides ? overrides.opsgenie : buildOpsgenieConfig(),
    msTeams: 'msTeams' in overrides ? overrides.msTeams : buildMsTeamsConfig(),
    asana: 'asana' in overrides ? overrides.asana : buildAsanaConfig(),
    customWebhook:
      'customWebhook' in overrides ? overrides.customWebhook : buildCustomWebhookConfig(),
  };
};

export const buildDestinationConfigInput = (
  overrides: Partial<DestinationConfigInput> = {}
): DestinationConfigInput => {
  return {
    slack: 'slack' in overrides ? overrides.slack : buildSlackConfigInput(),
    sns: 'sns' in overrides ? overrides.sns : buildSnsConfigInput(),
    sqs: 'sqs' in overrides ? overrides.sqs : buildSqsConfigInput(),
    pagerDuty: 'pagerDuty' in overrides ? overrides.pagerDuty : buildPagerDutyConfigInput(),
    github: 'github' in overrides ? overrides.github : buildGithubConfigInput(),
    jira: 'jira' in overrides ? overrides.jira : buildJiraConfigInput(),
    opsgenie: 'opsgenie' in overrides ? overrides.opsgenie : buildOpsgenieConfigInput(),
    msTeams: 'msTeams' in overrides ? overrides.msTeams : buildMsTeamsConfigInput(),
    asana: 'asana' in overrides ? overrides.asana : buildAsanaConfigInput(),
    customWebhook:
      'customWebhook' in overrides ? overrides.customWebhook : buildCustomWebhookConfigInput(),
  };
};

export const buildDestinationInput = (
  overrides: Partial<DestinationInput> = {}
): DestinationInput => {
  return {
    outputId: 'outputId' in overrides ? overrides.outputId : '736c7660-4609-4a00-b6fe-2fabc99955d3',
    displayName: 'displayName' in overrides ? overrides.displayName : 'morph',
    outputConfig:
      'outputConfig' in overrides ? overrides.outputConfig : buildDestinationConfigInput(),
    outputType: 'outputType' in overrides ? overrides.outputType : 'New Hampshire',
    defaultForSeverity:
      'defaultForSeverity' in overrides ? overrides.defaultForSeverity : [SeverityEnum.Critical],
  };
};

export const buildDetectionTestDefinition = (
  overrides: Partial<DetectionTestDefinition> = {}
): DetectionTestDefinition => {
  return {
    __typename: 'DetectionTestDefinition',
    expectedResult: 'expectedResult' in overrides ? overrides.expectedResult : true,
    name: 'name' in overrides ? overrides.name : 'Investment Account',
    resource: 'resource' in overrides ? overrides.resource : 'capacitor',
  };
};

export const buildDetectionTestDefinitionInput = (
  overrides: Partial<DetectionTestDefinitionInput> = {}
): DetectionTestDefinitionInput => {
  return {
    expectedResult: 'expectedResult' in overrides ? overrides.expectedResult : false,
    name: 'name' in overrides ? overrides.name : 'Direct',
    resource: 'resource' in overrides ? overrides.resource : 'Versatile',
  };
};

export const buildError = (overrides: Partial<Error> = {}): Error => {
  return {
    __typename: 'Error',
    code: 'code' in overrides ? overrides.code : 'navigating',
    message: 'message' in overrides ? overrides.message : 'deposit',
  };
};

export const buildFloatSeries = (overrides: Partial<FloatSeries> = {}): FloatSeries => {
  return {
    __typename: 'FloatSeries',
    label: 'label' in overrides ? overrides.label : 'functionalities',
    values: 'values' in overrides ? overrides.values : [5.25],
  };
};

export const buildFloatSeriesData = (overrides: Partial<FloatSeriesData> = {}): FloatSeriesData => {
  return {
    __typename: 'FloatSeriesData',
    timestamps: 'timestamps' in overrides ? overrides.timestamps : ['2020-04-22T20:42:06.736Z'],
    series: 'series' in overrides ? overrides.series : [buildFloatSeries()],
  };
};

export const buildGeneralSettings = (overrides: Partial<GeneralSettings> = {}): GeneralSettings => {
  return {
    __typename: 'GeneralSettings',
    displayName: 'displayName' in overrides ? overrides.displayName : 'Rustic',
    email: 'email' in overrides ? overrides.email : 'tertiary',
    errorReportingConsent:
      'errorReportingConsent' in overrides ? overrides.errorReportingConsent : false,
    analyticsConsent: 'analyticsConsent' in overrides ? overrides.analyticsConsent : true,
  };
};

export const buildGetAlertInput = (overrides: Partial<GetAlertInput> = {}): GetAlertInput => {
  return {
    alertId: 'alertId' in overrides ? overrides.alertId : '7dccc616-0ef2-4b9e-87ed-63b936c53e09',
    eventsPageSize: 'eventsPageSize' in overrides ? overrides.eventsPageSize : 385,
    eventsExclusiveStartKey:
      'eventsExclusiveStartKey' in overrides ? overrides.eventsExclusiveStartKey : 'Sleek',
  };
};

export const buildGetComplianceIntegrationTemplateInput = (
  overrides: Partial<GetComplianceIntegrationTemplateInput> = {}
): GetComplianceIntegrationTemplateInput => {
  return {
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'monetize',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : '24 hour',
    remediationEnabled: 'remediationEnabled' in overrides ? overrides.remediationEnabled : true,
    cweEnabled: 'cweEnabled' in overrides ? overrides.cweEnabled : true,
  };
};

export const buildGetGlobalPythonModuleInput = (
  overrides: Partial<GetGlobalPythonModuleInput> = {}
): GetGlobalPythonModuleInput => {
  return {
    id: 'id' in overrides ? overrides.id : 'e675af0e-1ceb-4036-bd7a-00301fac3e48',
    versionId:
      'versionId' in overrides ? overrides.versionId : '9fe39f4b-d18f-4a21-99a0-eeef9b77cb11',
  };
};

export const buildGetPolicyInput = (overrides: Partial<GetPolicyInput> = {}): GetPolicyInput => {
  return {
    id: 'id' in overrides ? overrides.id : '4abd6317-f970-4f92-a670-e7d0b9e3ec8d',
    versionId:
      'versionId' in overrides ? overrides.versionId : 'd394a64d-9476-44de-a8ab-7f8666cd4c8c',
  };
};

export const buildGetResourceInput = (
  overrides: Partial<GetResourceInput> = {}
): GetResourceInput => {
  return {
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : '913c64fb-c124-4dce-9757-51846aa5f4df',
  };
};

export const buildGetRuleInput = (overrides: Partial<GetRuleInput> = {}): GetRuleInput => {
  return {
    id: 'id' in overrides ? overrides.id : 'c191c85f-bb80-4a6a-baf2-1c466abe0031',
    versionId:
      'versionId' in overrides ? overrides.versionId : '1b6ea7a4-7775-4b65-8315-89b764428571',
  };
};

export const buildGetS3LogIntegrationTemplateInput = (
  overrides: Partial<GetS3LogIntegrationTemplateInput> = {}
): GetS3LogIntegrationTemplateInput => {
  return {
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'Armenia',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'Concrete',
    s3Bucket: 's3Bucket' in overrides ? overrides.s3Bucket : 'generating',
    kmsKey: 'kmsKey' in overrides ? overrides.kmsKey : 'Books',
    s3PrefixLogTypes:
      's3PrefixLogTypes' in overrides ? overrides.s3PrefixLogTypes : [buildS3PrefixLogTypesInput()],
  };
};

export const buildGithubConfig = (overrides: Partial<GithubConfig> = {}): GithubConfig => {
  return {
    __typename: 'GithubConfig',
    repoName: 'repoName' in overrides ? overrides.repoName : 'quantify',
    token: 'token' in overrides ? overrides.token : 'International',
  };
};

export const buildGithubConfigInput = (
  overrides: Partial<GithubConfigInput> = {}
): GithubConfigInput => {
  return {
    repoName: 'repoName' in overrides ? overrides.repoName : 'Route',
    token: 'token' in overrides ? overrides.token : 'Hat',
  };
};

export const buildGlobalPythonModule = (
  overrides: Partial<GlobalPythonModule> = {}
): GlobalPythonModule => {
  return {
    __typename: 'GlobalPythonModule',
    body: 'body' in overrides ? overrides.body : '5th generation',
    description: 'description' in overrides ? overrides.description : 'models',
    id: 'id' in overrides ? overrides.id : '42f3a049-dced-4b20-925c-a8e861b2d2d0',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-02-07T06:16:18.558Z',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-01-27T02:38:32.897Z',
  };
};

export const buildIntegrationItemHealthStatus = (
  overrides: Partial<IntegrationItemHealthStatus> = {}
): IntegrationItemHealthStatus => {
  return {
    __typename: 'IntegrationItemHealthStatus',
    healthy: 'healthy' in overrides ? overrides.healthy : false,
    message: 'message' in overrides ? overrides.message : 'Home Loan Account',
    rawErrorMessage: 'rawErrorMessage' in overrides ? overrides.rawErrorMessage : 'Markets',
  };
};

export const buildIntegrationTemplate = (
  overrides: Partial<IntegrationTemplate> = {}
): IntegrationTemplate => {
  return {
    __typename: 'IntegrationTemplate',
    body: 'body' in overrides ? overrides.body : 'bandwidth',
    stackName: 'stackName' in overrides ? overrides.stackName : 'Handcrafted Granite Mouse',
  };
};

export const buildInviteUserInput = (overrides: Partial<InviteUserInput> = {}): InviteUserInput => {
  return {
    givenName: 'givenName' in overrides ? overrides.givenName : 'system-worthy',
    familyName: 'familyName' in overrides ? overrides.familyName : 'copy',
    email: 'email' in overrides ? overrides.email : 'Gennaro_Kerluke71@gmail.com',
  };
};

export const buildJiraConfig = (overrides: Partial<JiraConfig> = {}): JiraConfig => {
  return {
    __typename: 'JiraConfig',
    orgDomain: 'orgDomain' in overrides ? overrides.orgDomain : 'deposit',
    projectKey: 'projectKey' in overrides ? overrides.projectKey : 'Investor',
    userName: 'userName' in overrides ? overrides.userName : 'payment',
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'bluetooth',
    assigneeId: 'assigneeId' in overrides ? overrides.assigneeId : 'bleeding-edge',
    issueType: 'issueType' in overrides ? overrides.issueType : 'Iowa',
  };
};

export const buildJiraConfigInput = (overrides: Partial<JiraConfigInput> = {}): JiraConfigInput => {
  return {
    orgDomain: 'orgDomain' in overrides ? overrides.orgDomain : 'bus',
    projectKey: 'projectKey' in overrides ? overrides.projectKey : 'XSS',
    userName: 'userName' in overrides ? overrides.userName : 'SQL',
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'Sleek Cotton Car',
    assigneeId: 'assigneeId' in overrides ? overrides.assigneeId : 'Virgin Islands, British',
    issueType: 'issueType' in overrides ? overrides.issueType : 'strategic',
  };
};

export const buildListAlertsInput = (overrides: Partial<ListAlertsInput> = {}): ListAlertsInput => {
  return {
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '4d7dfe6a-56ac-41c2-bfc1-1eaf33c0215a',
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 828,
    exclusiveStartKey:
      'exclusiveStartKey' in overrides ? overrides.exclusiveStartKey : 'Throughway',
    severity: 'severity' in overrides ? overrides.severity : [SeverityEnum.Low],
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Awesome Wooden Mouse'],
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['24 hour'],
    types: 'types' in overrides ? overrides.types : [AlertTypesEnum.Policy],
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'Island',
    createdAtBefore:
      'createdAtBefore' in overrides ? overrides.createdAtBefore : '2020-05-22T12:33:45.819Z',
    createdAtAfter:
      'createdAtAfter' in overrides ? overrides.createdAtAfter : '2020-04-26T13:02:02.091Z',
    status: 'status' in overrides ? overrides.status : [AlertStatusesEnum.Open],
    eventCountMin: 'eventCountMin' in overrides ? overrides.eventCountMin : 694,
    eventCountMax: 'eventCountMax' in overrides ? overrides.eventCountMax : 911,
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListAlertsSortFieldsEnum.CreatedAt,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Descending,
  };
};

export const buildListAlertsResponse = (
  overrides: Partial<ListAlertsResponse> = {}
): ListAlertsResponse => {
  return {
    __typename: 'ListAlertsResponse',
    alertSummaries:
      'alertSummaries' in overrides ? overrides.alertSummaries : [buildAlertSummary()],
    lastEvaluatedKey: 'lastEvaluatedKey' in overrides ? overrides.lastEvaluatedKey : 'Arkansas',
  };
};

export const buildListAvailableLogTypesResponse = (
  overrides: Partial<ListAvailableLogTypesResponse> = {}
): ListAvailableLogTypesResponse => {
  return {
    __typename: 'ListAvailableLogTypesResponse',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['silver'],
  };
};

export const buildListComplianceItemsResponse = (
  overrides: Partial<ListComplianceItemsResponse> = {}
): ListComplianceItemsResponse => {
  return {
    __typename: 'ListComplianceItemsResponse',
    items: 'items' in overrides ? overrides.items : [buildComplianceItem()],
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    status: 'status' in overrides ? overrides.status : ComplianceStatusEnum.Fail,
    totals: 'totals' in overrides ? overrides.totals : buildActiveSuppressCount(),
  };
};

export const buildListGlobalPythonModuleInput = (
  overrides: Partial<ListGlobalPythonModuleInput> = {}
): ListGlobalPythonModuleInput => {
  return {
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'Kyat',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Descending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 444,
    page: 'page' in overrides ? overrides.page : 404,
  };
};

export const buildListGlobalPythonModulesResponse = (
  overrides: Partial<ListGlobalPythonModulesResponse> = {}
): ListGlobalPythonModulesResponse => {
  return {
    __typename: 'ListGlobalPythonModulesResponse',
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    globals: 'globals' in overrides ? overrides.globals : [buildGlobalPythonModule()],
  };
};

export const buildListPoliciesInput = (
  overrides: Partial<ListPoliciesInput> = {}
): ListPoliciesInput => {
  return {
    createdBy: 'createdBy' in overrides ? overrides.createdBy : 'Sports',
    lastModifiedBy: 'lastModifiedBy' in overrides ? overrides.lastModifiedBy : 'incubate',
    initialSet: 'initialSet' in overrides ? overrides.initialSet : false,
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Pass,
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'parse',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    hasRemediation: 'hasRemediation' in overrides ? overrides.hasRemediation : false,
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['software'],
    severity: 'severity' in overrides ? overrides.severity : [SeverityEnum.High],
    tags: 'tags' in overrides ? overrides.tags : ['Fish'],
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListPoliciesSortFieldsEnum.ResourceTypes,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Ascending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 50,
    page: 'page' in overrides ? overrides.page : 254,
  };
};

export const buildListPoliciesResponse = (
  overrides: Partial<ListPoliciesResponse> = {}
): ListPoliciesResponse => {
  return {
    __typename: 'ListPoliciesResponse',
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    policies: 'policies' in overrides ? overrides.policies : [buildPolicySummary()],
  };
};

export const buildListResourcesInput = (
  overrides: Partial<ListResourcesInput> = {}
): ListResourcesInput => {
  return {
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Error,
    deleted: 'deleted' in overrides ? overrides.deleted : true,
    idContains: 'idContains' in overrides ? overrides.idContains : 'Borders',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : 'ccdadc7d-2460-418b-9e63-69d7110ffc5f',
    types: 'types' in overrides ? overrides.types : ['black'],
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListResourcesSortFieldsEnum.Type,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Descending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 228,
    page: 'page' in overrides ? overrides.page : 643,
  };
};

export const buildListResourcesResponse = (
  overrides: Partial<ListResourcesResponse> = {}
): ListResourcesResponse => {
  return {
    __typename: 'ListResourcesResponse',
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    resources: 'resources' in overrides ? overrides.resources : [buildResourceSummary()],
  };
};

export const buildListRulesInput = (overrides: Partial<ListRulesInput> = {}): ListRulesInput => {
  return {
    createdBy: 'createdBy' in overrides ? overrides.createdBy : 'neural',
    lastModifiedBy: 'lastModifiedBy' in overrides ? overrides.lastModifiedBy : 'Integration',
    initialSet: 'initialSet' in overrides ? overrides.initialSet : true,
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'Cotton',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Drive'],
    severity: 'severity' in overrides ? overrides.severity : [SeverityEnum.Low],
    tags: 'tags' in overrides ? overrides.tags : ['channels'],
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListRulesSortFieldsEnum.DisplayName,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Ascending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 19,
    page: 'page' in overrides ? overrides.page : 323,
  };
};

export const buildListRulesResponse = (
  overrides: Partial<ListRulesResponse> = {}
): ListRulesResponse => {
  return {
    __typename: 'ListRulesResponse',
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    rules: 'rules' in overrides ? overrides.rules : [buildRuleSummary()],
  };
};

export const buildLogAnalysisMetricsInput = (
  overrides: Partial<LogAnalysisMetricsInput> = {}
): LogAnalysisMetricsInput => {
  return {
    intervalMinutes: 'intervalMinutes' in overrides ? overrides.intervalMinutes : 816,
    fromDate: 'fromDate' in overrides ? overrides.fromDate : '2020-09-12T00:49:46.314Z',
    toDate: 'toDate' in overrides ? overrides.toDate : '2020-04-12T07:15:32.902Z',
    metricNames: 'metricNames' in overrides ? overrides.metricNames : ['Investment Account'],
  };
};

export const buildLogAnalysisMetricsResponse = (
  overrides: Partial<LogAnalysisMetricsResponse> = {}
): LogAnalysisMetricsResponse => {
  return {
    __typename: 'LogAnalysisMetricsResponse',
    eventsProcessed:
      'eventsProcessed' in overrides ? overrides.eventsProcessed : buildLongSeriesData(),
    alertsBySeverity:
      'alertsBySeverity' in overrides ? overrides.alertsBySeverity : buildLongSeriesData(),
    eventsLatency: 'eventsLatency' in overrides ? overrides.eventsLatency : buildFloatSeriesData(),
    totalAlertsDelta:
      'totalAlertsDelta' in overrides ? overrides.totalAlertsDelta : [buildSingleValue()],
    alertsByRuleID: 'alertsByRuleID' in overrides ? overrides.alertsByRuleID : [buildSingleValue()],
    fromDate: 'fromDate' in overrides ? overrides.fromDate : '2020-06-15T22:39:08.690Z',
    toDate: 'toDate' in overrides ? overrides.toDate : '2020-06-29T16:49:54.582Z',
    intervalMinutes: 'intervalMinutes' in overrides ? overrides.intervalMinutes : 670,
  };
};

export const buildLongSeries = (overrides: Partial<LongSeries> = {}): LongSeries => {
  return {
    __typename: 'LongSeries',
    label: 'label' in overrides ? overrides.label : 'envisioneer',
    values: 'values' in overrides ? overrides.values : [95698],
  };
};

export const buildLongSeriesData = (overrides: Partial<LongSeriesData> = {}): LongSeriesData => {
  return {
    __typename: 'LongSeriesData',
    timestamps: 'timestamps' in overrides ? overrides.timestamps : ['2020-05-29T02:52:10.141Z'],
    series: 'series' in overrides ? overrides.series : [buildLongSeries()],
  };
};

export const buildModifyGlobalPythonModuleInput = (
  overrides: Partial<ModifyGlobalPythonModuleInput> = {}
): ModifyGlobalPythonModuleInput => {
  return {
    description: 'description' in overrides ? overrides.description : 'Tools',
    id: 'id' in overrides ? overrides.id : 'af4a9975-adcf-4efc-b667-f59f6214197c',
    body: 'body' in overrides ? overrides.body : 'evolve',
  };
};

export const buildMsTeamsConfig = (overrides: Partial<MsTeamsConfig> = {}): MsTeamsConfig => {
  return {
    __typename: 'MsTeamsConfig',
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'eyeballs',
  };
};

export const buildMsTeamsConfigInput = (
  overrides: Partial<MsTeamsConfigInput> = {}
): MsTeamsConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'USB',
  };
};

export const buildOpsgenieConfig = (overrides: Partial<OpsgenieConfig> = {}): OpsgenieConfig => {
  return {
    __typename: 'OpsgenieConfig',
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'IB',
    serviceRegion:
      'serviceRegion' in overrides ? overrides.serviceRegion : OpsgenieServiceRegionEnum.Us,
  };
};

export const buildOpsgenieConfigInput = (
  overrides: Partial<OpsgenieConfigInput> = {}
): OpsgenieConfigInput => {
  return {
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'hacking',
    serviceRegion:
      'serviceRegion' in overrides ? overrides.serviceRegion : OpsgenieServiceRegionEnum.Us,
  };
};

export const buildOrganizationReportBySeverity = (
  overrides: Partial<OrganizationReportBySeverity> = {}
): OrganizationReportBySeverity => {
  return {
    __typename: 'OrganizationReportBySeverity',
    info: 'info' in overrides ? overrides.info : buildComplianceStatusCounts(),
    low: 'low' in overrides ? overrides.low : buildComplianceStatusCounts(),
    medium: 'medium' in overrides ? overrides.medium : buildComplianceStatusCounts(),
    high: 'high' in overrides ? overrides.high : buildComplianceStatusCounts(),
    critical: 'critical' in overrides ? overrides.critical : buildComplianceStatusCounts(),
  };
};

export const buildOrganizationStatsInput = (
  overrides: Partial<OrganizationStatsInput> = {}
): OrganizationStatsInput => {
  return {
    limitTopFailing: 'limitTopFailing' in overrides ? overrides.limitTopFailing : 818,
  };
};

export const buildOrganizationStatsResponse = (
  overrides: Partial<OrganizationStatsResponse> = {}
): OrganizationStatsResponse => {
  return {
    __typename: 'OrganizationStatsResponse',
    appliedPolicies:
      'appliedPolicies' in overrides
        ? overrides.appliedPolicies
        : buildOrganizationReportBySeverity(),
    scannedResources:
      'scannedResources' in overrides ? overrides.scannedResources : buildScannedResources(),
    topFailingPolicies:
      'topFailingPolicies' in overrides ? overrides.topFailingPolicies : [buildPolicySummary()],
    topFailingResources:
      'topFailingResources' in overrides ? overrides.topFailingResources : [buildResourceSummary()],
  };
};

export const buildPagerDutyConfig = (overrides: Partial<PagerDutyConfig> = {}): PagerDutyConfig => {
  return {
    __typename: 'PagerDutyConfig',
    integrationKey: 'integrationKey' in overrides ? overrides.integrationKey : 'transform',
  };
};

export const buildPagerDutyConfigInput = (
  overrides: Partial<PagerDutyConfigInput> = {}
): PagerDutyConfigInput => {
  return {
    integrationKey: 'integrationKey' in overrides ? overrides.integrationKey : 'Soft',
  };
};

export const buildPagingData = (overrides: Partial<PagingData> = {}): PagingData => {
  return {
    __typename: 'PagingData',
    thisPage: 'thisPage' in overrides ? overrides.thisPage : 289,
    totalPages: 'totalPages' in overrides ? overrides.totalPages : 812,
    totalItems: 'totalItems' in overrides ? overrides.totalItems : 394,
  };
};

export const buildPoliciesForResourceInput = (
  overrides: Partial<PoliciesForResourceInput> = {}
): PoliciesForResourceInput => {
  return {
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : 'f3bd41bd-4265-4a12-9256-53a459c62d5b',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Medium,
    status: 'status' in overrides ? overrides.status : ComplianceStatusEnum.Error,
    suppressed: 'suppressed' in overrides ? overrides.suppressed : false,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 282,
    page: 'page' in overrides ? overrides.page : 906,
  };
};

export const buildPolicyDetails = (overrides: Partial<PolicyDetails> = {}): PolicyDetails => {
  return {
    __typename: 'PolicyDetails',
    autoRemediationId:
      'autoRemediationId' in overrides
        ? overrides.autoRemediationId
        : '63631269-b304-4865-b222-bf96d4b3162c',
    autoRemediationParameters:
      'autoRemediationParameters' in overrides ? overrides.autoRemediationParameters : '"bar"',
    body: 'body' in overrides ? overrides.body : 'card',
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Fail,
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-12-25T18:48:58.096Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : 'cc4acb0d-22fe-4182-a29b-832f1f6d7f85',
    description: 'description' in overrides ? overrides.description : 'time-frame',
    displayName: 'displayName' in overrides ? overrides.displayName : 'navigating',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    id: 'id' in overrides ? overrides.id : '4193e9e6-d55b-48ad-8475-d171d8c2ea89',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-05-12T04:22:53.318Z',
    lastModifiedBy:
      'lastModifiedBy' in overrides
        ? overrides.lastModifiedBy
        : '8b4fcf01-c8f1-4fbf-bc94-e4f58d04c799',
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['213c2719-fb31-4502-9a8a-adda432a772a'],
    reference: 'reference' in overrides ? overrides.reference : 'applications',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['Specialist'],
    runbook: 'runbook' in overrides ? overrides.runbook : 'upward-trending',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Critical,
    suppressions: 'suppressions' in overrides ? overrides.suppressions : ['Bike'],
    tags: 'tags' in overrides ? overrides.tags : ['success'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinition()],
    versionId:
      'versionId' in overrides ? overrides.versionId : 'ca391fc7-f186-4bcb-b717-3e34cb330d83',
  };
};

export const buildPolicySummary = (overrides: Partial<PolicySummary> = {}): PolicySummary => {
  return {
    __typename: 'PolicySummary',
    autoRemediationId:
      'autoRemediationId' in overrides
        ? overrides.autoRemediationId
        : '43a2278e-67bf-4941-91f8-7fbe8503562c',
    autoRemediationParameters:
      'autoRemediationParameters' in overrides ? overrides.autoRemediationParameters : '"car"',
    suppressions: 'suppressions' in overrides ? overrides.suppressions : ['Senior'],
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Pass,
    displayName: 'displayName' in overrides ? overrides.displayName : 'indigo',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    id: 'id' in overrides ? overrides.id : '260cad31-ef71-4eb6-9ac1-1ca1d0da39c7',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-09-11T01:58:47.481Z',
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['94fd4ab9-7edc-4b27-8c37-bcfab0e2f825'],
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['EXE'],
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Critical,
    tags: 'tags' in overrides ? overrides.tags : ['navigating'],
  };
};

export const buildRemediateResourceInput = (
  overrides: Partial<RemediateResourceInput> = {}
): RemediateResourceInput => {
  return {
    policyId: 'policyId' in overrides ? overrides.policyId : '9f991f1d-dcc4-4ce1-8490-335f34dd4da9',
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : '17cb94ba-4961-439a-9cbf-c305e26019da',
  };
};

export const buildResourceDetails = (overrides: Partial<ResourceDetails> = {}): ResourceDetails => {
  return {
    __typename: 'ResourceDetails',
    attributes: 'attributes' in overrides ? overrides.attributes : '"car"',
    deleted: 'deleted' in overrides ? overrides.deleted : false,
    expiresAt: 'expiresAt' in overrides ? overrides.expiresAt : 969,
    id: 'id' in overrides ? overrides.id : '58de615f-2645-4b97-8a31-7cab72afe085',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : 'c3876057-6d75-4af9-b160-a51a16359574',
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Pass,
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-04-22T13:19:24.499Z',
    type: 'type' in overrides ? overrides.type : 'Ball',
  };
};

export const buildResourcesForPolicyInput = (
  overrides: Partial<ResourcesForPolicyInput> = {}
): ResourcesForPolicyInput => {
  return {
    policyId: 'policyId' in overrides ? overrides.policyId : 'acd9a6a4-7c52-43d2-8cd6-39bd74eb973f',
    status: 'status' in overrides ? overrides.status : ComplianceStatusEnum.Fail,
    suppressed: 'suppressed' in overrides ? overrides.suppressed : true,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 137,
    page: 'page' in overrides ? overrides.page : 354,
  };
};

export const buildResourceSummary = (overrides: Partial<ResourceSummary> = {}): ResourceSummary => {
  return {
    __typename: 'ResourceSummary',
    id: 'id' in overrides ? overrides.id : '9642570b-3380-417d-b139-6e9d3e887b08',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : 'bb97638e-f07d-4ca1-96f6-206967b7c092',
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Pass,
    deleted: 'deleted' in overrides ? overrides.deleted : false,
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-09-27T23:50:08.966Z',
    type: 'type' in overrides ? overrides.type : 'Illinois',
  };
};

export const buildRuleDetails = (overrides: Partial<RuleDetails> = {}): RuleDetails => {
  return {
    __typename: 'RuleDetails',
    body: 'body' in overrides ? overrides.body : 'Shoes',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-08-03T05:47:47.012Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : '6c3e570b-c621-4e3a-aab1-8a21e9aa4d17',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 34,
    threshold: 'threshold' in overrides ? overrides.threshold : 244,
    description: 'description' in overrides ? overrides.description : 'EXE',
    displayName: 'displayName' in overrides ? overrides.displayName : 'Advanced',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    id: 'id' in overrides ? overrides.id : 'Metal',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-02-01T03:09:25.999Z',
    lastModifiedBy:
      'lastModifiedBy' in overrides
        ? overrides.lastModifiedBy
        : '5c381f6d-f9c9-4de8-9d6f-dc274dc6b1e0',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Auto Loan Account'],
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['1460c173-140b-433a-af75-a657c342f229'],
    reference: 'reference' in overrides ? overrides.reference : 'wireless',
    runbook: 'runbook' in overrides ? overrides.runbook : 'withdrawal',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Low,
    tags: 'tags' in overrides ? overrides.tags : ['digital'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinition()],
    versionId:
      'versionId' in overrides ? overrides.versionId : 'cd730243-e772-446f-b820-ff796b83a51f',
  };
};

export const buildRuleSummary = (overrides: Partial<RuleSummary> = {}): RuleSummary => {
  return {
    __typename: 'RuleSummary',
    displayName: 'displayName' in overrides ? overrides.displayName : 'array',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    id: 'id' in overrides ? overrides.id : '4ce135b7-005f-4a98-8a69-9b9d3b372bdb',
    threshold: 'threshold' in overrides ? overrides.threshold : 550,
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-10-11T23:20:19.662Z',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-09-24T09:09:49.137Z',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['AI'],
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Info,
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['a2f89a13-3b31-4365-b40d-2495c13a6f65'],
    tags: 'tags' in overrides ? overrides.tags : ['Virginia'],
  };
};

export const buildS3LogIntegration = (
  overrides: Partial<S3LogIntegration> = {}
): S3LogIntegration => {
  return {
    __typename: 'S3LogIntegration',
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'Bedfordshire',
    createdAtTime:
      'createdAtTime' in overrides ? overrides.createdAtTime : '2020-07-03T08:10:02.259Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : 'f135f3dc-9654-4752-b1a9-c20f98d87e48',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : '73041328-928c-4ff9-a396-06b9b769900d',
    integrationType: 'integrationType' in overrides ? overrides.integrationType : 'Computers',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'transmitting',
    lastEventReceived:
      'lastEventReceived' in overrides ? overrides.lastEventReceived : '2020-05-25T09:20:29.138Z',
    s3Bucket: 's3Bucket' in overrides ? overrides.s3Bucket : 'generating',
    s3Prefix: 's3Prefix' in overrides ? overrides.s3Prefix : 'IB',
    kmsKey: 'kmsKey' in overrides ? overrides.kmsKey : 'robust',
    s3PrefixLogTypes:
      's3PrefixLogTypes' in overrides ? overrides.s3PrefixLogTypes : [buildS3PrefixLogTypes()],
    health: 'health' in overrides ? overrides.health : buildS3LogIntegrationHealth(),
    stackName: 'stackName' in overrides ? overrides.stackName : 'River',
  };
};

export const buildS3LogIntegrationHealth = (
  overrides: Partial<S3LogIntegrationHealth> = {}
): S3LogIntegrationHealth => {
  return {
    __typename: 'S3LogIntegrationHealth',
    processingRoleStatus:
      'processingRoleStatus' in overrides
        ? overrides.processingRoleStatus
        : buildIntegrationItemHealthStatus(),
    s3BucketStatus:
      's3BucketStatus' in overrides ? overrides.s3BucketStatus : buildIntegrationItemHealthStatus(),
    kmsKeyStatus:
      'kmsKeyStatus' in overrides ? overrides.kmsKeyStatus : buildIntegrationItemHealthStatus(),
  };
};

export const buildS3PrefixLogTypes = (
  overrides: Partial<S3PrefixLogTypes> = {}
): S3PrefixLogTypes => {
  return {
    __typename: 'S3PrefixLogTypes',
    prefix: 'prefix' in overrides ? overrides.prefix : 'synthesizing',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Markets'],
  };
};

export const buildS3PrefixLogTypesInput = (
  overrides: Partial<S3PrefixLogTypesInput> = {}
): S3PrefixLogTypesInput => {
  return {
    prefix: 'prefix' in overrides ? overrides.prefix : 'Brand',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Circles'],
  };
};

export const buildScannedResources = (
  overrides: Partial<ScannedResources> = {}
): ScannedResources => {
  return {
    __typename: 'ScannedResources',
    byType: 'byType' in overrides ? overrides.byType : [buildScannedResourceStats()],
  };
};

export const buildScannedResourceStats = (
  overrides: Partial<ScannedResourceStats> = {}
): ScannedResourceStats => {
  return {
    __typename: 'ScannedResourceStats',
    count: 'count' in overrides ? overrides.count : buildComplianceStatusCounts(),
    type: 'type' in overrides ? overrides.type : 'proactive',
  };
};

export const buildSendTestAlertInput = (
  overrides: Partial<SendTestAlertInput> = {}
): SendTestAlertInput => {
  return {
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['900d0911-ac12-4720-a1a9-89d6f1995c9f'],
  };
};

export const buildSingleValue = (overrides: Partial<SingleValue> = {}): SingleValue => {
  return {
    __typename: 'SingleValue',
    label: 'label' in overrides ? overrides.label : 'blue',
    value: 'value' in overrides ? overrides.value : 72,
  };
};

export const buildSlackConfig = (overrides: Partial<SlackConfig> = {}): SlackConfig => {
  return {
    __typename: 'SlackConfig',
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'Manat',
  };
};

export const buildSlackConfigInput = (
  overrides: Partial<SlackConfigInput> = {}
): SlackConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'Prairie',
  };
};

export const buildSnsConfig = (overrides: Partial<SnsConfig> = {}): SnsConfig => {
  return {
    __typename: 'SnsConfig',
    topicArn: 'topicArn' in overrides ? overrides.topicArn : 'Outdoors',
  };
};

export const buildSnsConfigInput = (overrides: Partial<SnsConfigInput> = {}): SnsConfigInput => {
  return {
    topicArn: 'topicArn' in overrides ? overrides.topicArn : 'algorithm',
  };
};

export const buildSqsConfig = (overrides: Partial<SqsConfig> = {}): SqsConfig => {
  return {
    __typename: 'SqsConfig',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Direct'],
    allowedPrincipalArns:
      'allowedPrincipalArns' in overrides ? overrides.allowedPrincipalArns : ['HTTP'],
    allowedSourceArns:
      'allowedSourceArns' in overrides ? overrides.allowedSourceArns : ['holistic'],
    queueUrl: 'queueUrl' in overrides ? overrides.queueUrl : 'Engineer',
  };
};

export const buildSqsConfigInput = (overrides: Partial<SqsConfigInput> = {}): SqsConfigInput => {
  return {
    queueUrl: 'queueUrl' in overrides ? overrides.queueUrl : 'Seamless',
  };
};

export const buildSqsDestinationConfig = (
  overrides: Partial<SqsDestinationConfig> = {}
): SqsDestinationConfig => {
  return {
    __typename: 'SqsDestinationConfig',
    queueUrl: 'queueUrl' in overrides ? overrides.queueUrl : 'mobile',
  };
};

export const buildSqsLogConfigInput = (
  overrides: Partial<SqsLogConfigInput> = {}
): SqsLogConfigInput => {
  return {
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Incredible'],
    allowedPrincipalArns:
      'allowedPrincipalArns' in overrides ? overrides.allowedPrincipalArns : ['Zloty'],
    allowedSourceArns:
      'allowedSourceArns' in overrides ? overrides.allowedSourceArns : ['partnerships'],
  };
};

export const buildSqsLogIntegrationHealth = (
  overrides: Partial<SqsLogIntegrationHealth> = {}
): SqsLogIntegrationHealth => {
  return {
    __typename: 'SqsLogIntegrationHealth',
    sqsStatus: 'sqsStatus' in overrides ? overrides.sqsStatus : buildIntegrationItemHealthStatus(),
  };
};

export const buildSqsLogSourceIntegration = (
  overrides: Partial<SqsLogSourceIntegration> = {}
): SqsLogSourceIntegration => {
  return {
    __typename: 'SqsLogSourceIntegration',
    createdAtTime:
      'createdAtTime' in overrides ? overrides.createdAtTime : '2020-11-22T04:16:09.421Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : '8db76f97-491c-446e-b3f2-eec061dd9b79',
    integrationId:
      'integrationId' in overrides
        ? overrides.integrationId
        : '53e839d8-068b-4f1e-a593-5868c37a1403',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'Future',
    integrationType: 'integrationType' in overrides ? overrides.integrationType : 'Sleek Steel Hat',
    lastEventReceived:
      'lastEventReceived' in overrides ? overrides.lastEventReceived : '2020-03-01T16:22:21.931Z',
    sqsConfig: 'sqsConfig' in overrides ? overrides.sqsConfig : buildSqsConfig(),
    health: 'health' in overrides ? overrides.health : buildSqsLogIntegrationHealth(),
  };
};

export const buildSuppressPoliciesInput = (
  overrides: Partial<SuppressPoliciesInput> = {}
): SuppressPoliciesInput => {
  return {
    policyIds:
      'policyIds' in overrides ? overrides.policyIds : ['b2796f03-2f72-4717-a45b-eea5c8b2943f'],
    resourcePatterns:
      'resourcePatterns' in overrides
        ? overrides.resourcePatterns
        : ['Cuban Peso Peso Convertible'],
  };
};

export const buildTestDetectionSubRecord = (
  overrides: Partial<TestDetectionSubRecord> = {}
): TestDetectionSubRecord => {
  return {
    __typename: 'TestDetectionSubRecord',
    output: 'output' in overrides ? overrides.output : 'Borders',
    error: 'error' in overrides ? overrides.error : buildError(),
  };
};

export const buildTestPolicyInput = (overrides: Partial<TestPolicyInput> = {}): TestPolicyInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'Centralized',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['Automotive'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildTestPolicyRecord = (
  overrides: Partial<TestPolicyRecord> = {}
): TestPolicyRecord => {
  return {
    __typename: 'TestPolicyRecord',
    id: 'id' in overrides ? overrides.id : 'Soft',
    name: 'name' in overrides ? overrides.name : 'Utah',
    passed: 'passed' in overrides ? overrides.passed : false,
    functions: 'functions' in overrides ? overrides.functions : buildTestPolicyRecordFunctions(),
    error: 'error' in overrides ? overrides.error : buildError(),
  };
};

export const buildTestPolicyRecordFunctions = (
  overrides: Partial<TestPolicyRecordFunctions> = {}
): TestPolicyRecordFunctions => {
  return {
    __typename: 'TestPolicyRecordFunctions',
    policyFunction:
      'policyFunction' in overrides ? overrides.policyFunction : buildTestDetectionSubRecord(),
  };
};

export const buildTestPolicyResponse = (
  overrides: Partial<TestPolicyResponse> = {}
): TestPolicyResponse => {
  return {
    __typename: 'TestPolicyResponse',
    results: 'results' in overrides ? overrides.results : [buildTestPolicyRecord()],
  };
};

export const buildTestRuleInput = (overrides: Partial<TestRuleInput> = {}): TestRuleInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'Steel',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['project'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildTestRuleRecord = (overrides: Partial<TestRuleRecord> = {}): TestRuleRecord => {
  return {
    __typename: 'TestRuleRecord',
    id: 'id' in overrides ? overrides.id : 'Oklahoma',
    name: 'name' in overrides ? overrides.name : 'Pants',
    passed: 'passed' in overrides ? overrides.passed : true,
    functions: 'functions' in overrides ? overrides.functions : buildTestRuleRecordFunctions(),
    error: 'error' in overrides ? overrides.error : buildError(),
  };
};

export const buildTestRuleRecordFunctions = (
  overrides: Partial<TestRuleRecordFunctions> = {}
): TestRuleRecordFunctions => {
  return {
    __typename: 'TestRuleRecordFunctions',
    ruleFunction:
      'ruleFunction' in overrides ? overrides.ruleFunction : buildTestDetectionSubRecord(),
    titleFunction:
      'titleFunction' in overrides ? overrides.titleFunction : buildTestDetectionSubRecord(),
    dedupFunction:
      'dedupFunction' in overrides ? overrides.dedupFunction : buildTestDetectionSubRecord(),
    alertContextFunction:
      'alertContextFunction' in overrides
        ? overrides.alertContextFunction
        : buildTestDetectionSubRecord(),
  };
};

export const buildTestRuleResponse = (
  overrides: Partial<TestRuleResponse> = {}
): TestRuleResponse => {
  return {
    __typename: 'TestRuleResponse',
    results: 'results' in overrides ? overrides.results : [buildTestRuleRecord()],
  };
};

export const buildUpdateAlertStatusInput = (
  overrides: Partial<UpdateAlertStatusInput> = {}
): UpdateAlertStatusInput => {
  return {
    alertIds:
      'alertIds' in overrides ? overrides.alertIds : ['eb2e440c-22b8-4ba2-91ba-23d223957554'],
    status: 'status' in overrides ? overrides.status : AlertStatusesEnum.Closed,
  };
};

export const buildUpdateComplianceIntegrationInput = (
  overrides: Partial<UpdateComplianceIntegrationInput> = {}
): UpdateComplianceIntegrationInput => {
  return {
    integrationId: 'integrationId' in overrides ? overrides.integrationId : 'support',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'holistic',
    cweEnabled: 'cweEnabled' in overrides ? overrides.cweEnabled : false,
    remediationEnabled: 'remediationEnabled' in overrides ? overrides.remediationEnabled : false,
  };
};

export const buildUpdateGeneralSettingsInput = (
  overrides: Partial<UpdateGeneralSettingsInput> = {}
): UpdateGeneralSettingsInput => {
  return {
    displayName: 'displayName' in overrides ? overrides.displayName : 'Borders',
    email: 'email' in overrides ? overrides.email : 'olive',
    errorReportingConsent:
      'errorReportingConsent' in overrides ? overrides.errorReportingConsent : true,
    analyticsConsent: 'analyticsConsent' in overrides ? overrides.analyticsConsent : false,
  };
};

export const buildUpdatePolicyInput = (
  overrides: Partial<UpdatePolicyInput> = {}
): UpdatePolicyInput => {
  return {
    autoRemediationId:
      'autoRemediationId' in overrides
        ? overrides.autoRemediationId
        : '3ec80d46-fb82-458d-9293-ccefffe7eeaa',
    autoRemediationParameters:
      'autoRemediationParameters' in overrides ? overrides.autoRemediationParameters : '"bar"',
    body: 'body' in overrides ? overrides.body : 'Front-line',
    description: 'description' in overrides ? overrides.description : 'dot-com',
    displayName: 'displayName' in overrides ? overrides.displayName : 'deposit',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    id: 'id' in overrides ? overrides.id : 'cdf83cf0-6494-413a-a723-ddfd28c60cc7',
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['92126800-afab-49cc-b6fb-d7d45589f268'],
    reference: 'reference' in overrides ? overrides.reference : 'Table',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['Buckinghamshire'],
    runbook: 'runbook' in overrides ? overrides.runbook : 'productize',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Info,
    suppressions: 'suppressions' in overrides ? overrides.suppressions : ['green'],
    tags: 'tags' in overrides ? overrides.tags : ['transmit'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildUpdateRuleInput = (overrides: Partial<UpdateRuleInput> = {}): UpdateRuleInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'capacitor',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 748,
    threshold: 'threshold' in overrides ? overrides.threshold : 475,
    description: 'description' in overrides ? overrides.description : 'Utah',
    displayName: 'displayName' in overrides ? overrides.displayName : 'Internal',
    enabled: 'enabled' in overrides ? overrides.enabled : true,
    id: 'id' in overrides ? overrides.id : '18acb268-562c-44de-9424-28c46a166088',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['initiatives'],
    outputIds:
      'outputIds' in overrides ? overrides.outputIds : ['de925222-db76-43b8-a891-b7b6f90d8180'],
    reference: 'reference' in overrides ? overrides.reference : 'e-commerce',
    runbook: 'runbook' in overrides ? overrides.runbook : 'Fresh',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.High,
    tags: 'tags' in overrides ? overrides.tags : ['Senior'],
    tests: 'tests' in overrides ? overrides.tests : [buildDetectionTestDefinitionInput()],
  };
};

export const buildUpdateS3LogIntegrationInput = (
  overrides: Partial<UpdateS3LogIntegrationInput> = {}
): UpdateS3LogIntegrationInput => {
  return {
    integrationId: 'integrationId' in overrides ? overrides.integrationId : 'expedite',
    integrationLabel:
      'integrationLabel' in overrides ? overrides.integrationLabel : 'Buckinghamshire',
    s3Bucket: 's3Bucket' in overrides ? overrides.s3Bucket : 'green',
    kmsKey: 'kmsKey' in overrides ? overrides.kmsKey : 'deposit',
    s3PrefixLogTypes:
      's3PrefixLogTypes' in overrides ? overrides.s3PrefixLogTypes : [buildS3PrefixLogTypesInput()],
  };
};

export const buildUpdateSqsLogIntegrationInput = (
  overrides: Partial<UpdateSqsLogIntegrationInput> = {}
): UpdateSqsLogIntegrationInput => {
  return {
    integrationId: 'integrationId' in overrides ? overrides.integrationId : 'Pennsylvania',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'morph',
    sqsConfig: 'sqsConfig' in overrides ? overrides.sqsConfig : buildSqsLogConfigInput(),
  };
};

export const buildUpdateUserInput = (overrides: Partial<UpdateUserInput> = {}): UpdateUserInput => {
  return {
    id: 'id' in overrides ? overrides.id : '0d6a9360-d92b-4660-9e5f-14155047bddc',
    givenName: 'givenName' in overrides ? overrides.givenName : 'Personal Loan Account',
    familyName: 'familyName' in overrides ? overrides.familyName : 'connecting',
    email: 'email' in overrides ? overrides.email : 'Eldon.Gusikowski@hotmail.com',
  };
};

export const buildUploadPoliciesInput = (
  overrides: Partial<UploadPoliciesInput> = {}
): UploadPoliciesInput => {
  return {
    data: 'data' in overrides ? overrides.data : 'back-end',
  };
};

export const buildUploadPoliciesResponse = (
  overrides: Partial<UploadPoliciesResponse> = {}
): UploadPoliciesResponse => {
  return {
    __typename: 'UploadPoliciesResponse',
    totalPolicies: 'totalPolicies' in overrides ? overrides.totalPolicies : 102,
    newPolicies: 'newPolicies' in overrides ? overrides.newPolicies : 971,
    modifiedPolicies: 'modifiedPolicies' in overrides ? overrides.modifiedPolicies : 829,
    totalRules: 'totalRules' in overrides ? overrides.totalRules : 916,
    newRules: 'newRules' in overrides ? overrides.newRules : 898,
    modifiedRules: 'modifiedRules' in overrides ? overrides.modifiedRules : 463,
    totalGlobals: 'totalGlobals' in overrides ? overrides.totalGlobals : 491,
    newGlobals: 'newGlobals' in overrides ? overrides.newGlobals : 544,
    modifiedGlobals: 'modifiedGlobals' in overrides ? overrides.modifiedGlobals : 197,
  };
};

export const buildUser = (overrides: Partial<User> = {}): User => {
  return {
    __typename: 'User',
    givenName: 'givenName' in overrides ? overrides.givenName : 'function',
    familyName: 'familyName' in overrides ? overrides.familyName : 'Future-proofed',
    id: 'id' in overrides ? overrides.id : 'b5756f00-51a6-422a-9a7d-c13ee6a63750',
    email: 'email' in overrides ? overrides.email : 'Mac13@yahoo.com',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : 1578015894449,
    status: 'status' in overrides ? overrides.status : 'experiences',
  };
};
