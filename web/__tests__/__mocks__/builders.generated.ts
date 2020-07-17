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
  AlertDetails,
  AlertSummary,
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
  Destination,
  DestinationConfig,
  DestinationConfigInput,
  DestinationInput,
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
  ListComplianceItemsResponse,
  ListGlobalPythonModuleInput,
  ListGlobalPythonModulesResponse,
  ListPoliciesInput,
  ListPoliciesResponse,
  ListResourcesInput,
  ListResourcesResponse,
  ListRulesInput,
  ListRulesResponse,
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
  PolicyUnitTest,
  PolicyUnitTestError,
  PolicyUnitTestInput,
  RemediateResourceInput,
  ResourceDetails,
  ResourcesForPolicyInput,
  ResourceSummary,
  RuleDetails,
  RuleSummary,
  S3LogIntegration,
  S3LogIntegrationHealth,
  ScannedResources,
  ScannedResourceStats,
  SlackConfig,
  SlackConfigInput,
  SnsConfig,
  SnsConfigInput,
  SqsConfig,
  SqsConfigInput,
  SuppressPoliciesInput,
  TestPolicyInput,
  TestPolicyResponse,
  UpdateComplianceIntegrationInput,
  UpdateGeneralSettingsInput,
  UpdatePolicyInput,
  UpdateRuleInput,
  UpdateS3LogIntegrationInput,
  UpdateUserInput,
  UploadPoliciesInput,
  UploadPoliciesResponse,
  User,
  AccountTypeEnum,
  AnalysisTypeEnum,
  ComplianceStatusEnum,
  DestinationTypeEnum,
  ListAlertsSortFieldsEnum,
  ListPoliciesSortFieldsEnum,
  ListResourcesSortFieldsEnum,
  ListRulesSortFieldsEnum,
  LogIntegration,
  SeverityEnum,
  SortDirEnum,
} from '../../__generated__/schema';
import { generateRandomArray, faker } from 'test-utils';

export const buildActiveSuppressCount = (
  overrides: Partial<ActiveSuppressCount> = {}
): ActiveSuppressCount => {
  return {
    active: 'active' in overrides ? overrides.active : buildComplianceStatusCounts(),
    suppressed: 'suppressed' in overrides ? overrides.suppressed : buildComplianceStatusCounts(),
    ...overrides,
    __typename: 'ActiveSuppressCount',
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
    ...overrides,
  };
};

export const buildAddGlobalPythonModuleInput = (
  overrides: Partial<AddGlobalPythonModuleInput> = {}
): AddGlobalPythonModuleInput => {
  return {
    id: 'id' in overrides ? overrides.id : '6b0f1c64-e650-48e8-abcf-37c23c6cf854',
    description: 'description' in overrides ? overrides.description : 'Dynamic',
    body: 'body' in overrides ? overrides.body : 'methodologies',
    ...overrides,
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTestInput()],
    ...overrides,
  };
};

export const buildAddRuleInput = (overrides: Partial<AddRuleInput> = {}): AddRuleInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'microchip',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 429,
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTestInput()],
    ...overrides,
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
    s3Prefix: 's3Prefix' in overrides ? overrides.s3Prefix : 'reintermediate',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['expedite'],
    ...overrides,
  };
};

export const buildAlertDetails = (overrides: Partial<AlertDetails> = {}): AlertDetails => {
  return {
    alertId: 'alertId' in overrides ? overrides.alertId : '2c5aa76d-eb43-49f0-a65c-50e4daa756a4',
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '9ad2c6da-417d-414f-a3e5-7959acdeaa9e',
    title: 'title' in overrides ? overrides.title : 'Steel',
    creationTime: 'creationTime' in overrides ? overrides.creationTime : '2020-10-28T02:06:29.865Z',
    updateTime: 'updateTime' in overrides ? overrides.updateTime : '2020-02-22T04:54:35.910Z',
    eventsMatched: 'eventsMatched' in overrides ? overrides.eventsMatched : 516,
    events: 'events' in overrides ? overrides.events : ['"bar"'],
    eventsLastEvaluatedKey:
      'eventsLastEvaluatedKey' in overrides ? overrides.eventsLastEvaluatedKey : 'Accountability',
    dedupString: 'dedupString' in overrides ? overrides.dedupString : 'Auto Loan Account',
    ...overrides,
    __typename: 'AlertDetails',
  };
};

export const buildAlertSummary = (overrides: Partial<AlertSummary> = {}): AlertSummary => {
  return {
    alertId: 'alertId' in overrides ? overrides.alertId : 'Administrator',
    creationTime: 'creationTime' in overrides ? overrides.creationTime : '2020-08-08T12:15:31.121Z',
    eventsMatched: 'eventsMatched' in overrides ? overrides.eventsMatched : 670,
    title: 'title' in overrides ? overrides.title : 'indexing',
    updateTime: 'updateTime' in overrides ? overrides.updateTime : '2020-09-17T19:32:46.882Z',
    ruleId: 'ruleId' in overrides ? overrides.ruleId : 'functionalities',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Medium,
    ...overrides,
    __typename: 'AlertSummary',
  };
};

export const buildAsanaConfig = (overrides: Partial<AsanaConfig> = {}): AsanaConfig => {
  return {
    personalAccessToken:
      'personalAccessToken' in overrides ? overrides.personalAccessToken : 'Chief',
    projectGids: 'projectGids' in overrides ? overrides.projectGids : ['Central'],
    ...overrides,
    __typename: 'AsanaConfig',
  };
};

export const buildAsanaConfigInput = (
  overrides: Partial<AsanaConfigInput> = {}
): AsanaConfigInput => {
  return {
    personalAccessToken:
      'personalAccessToken' in overrides ? overrides.personalAccessToken : 'connect',
    projectGids: 'projectGids' in overrides ? overrides.projectGids : ['Executive'],
    ...overrides,
  };
};

export const buildComplianceIntegration = (
  overrides: Partial<ComplianceIntegration> = {}
): ComplianceIntegration => {
  return {
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
    ...overrides,
    __typename: 'ComplianceIntegration',
  };
};

export const buildComplianceIntegrationHealth = (
  overrides: Partial<ComplianceIntegrationHealth> = {}
): ComplianceIntegrationHealth => {
  return {
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
    ...overrides,
    __typename: 'ComplianceIntegrationHealth',
  };
};

export const buildComplianceItem = (overrides: Partial<ComplianceItem> = {}): ComplianceItem => {
  return {
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
    ...overrides,
    __typename: 'ComplianceItem',
  };
};

export const buildComplianceStatusCounts = (
  overrides: Partial<ComplianceStatusCounts> = {}
): ComplianceStatusCounts => {
  return {
    error: 'error' in overrides ? overrides.error : 71,
    fail: 'fail' in overrides ? overrides.fail : 488,
    pass: 'pass' in overrides ? overrides.pass : 154,
    ...overrides,
    __typename: 'ComplianceStatusCounts',
  };
};

export const buildCustomWebhookConfig = (
  overrides: Partial<CustomWebhookConfig> = {}
): CustomWebhookConfig => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'web services',
    ...overrides,
    __typename: 'CustomWebhookConfig',
  };
};

export const buildCustomWebhookConfigInput = (
  overrides: Partial<CustomWebhookConfigInput> = {}
): CustomWebhookConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'bypass',
    ...overrides,
  };
};

export const buildDeleteGlobalPythonInputItem = (
  overrides: Partial<DeleteGlobalPythonInputItem> = {}
): DeleteGlobalPythonInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : '28c248cf-f729-4ac6-af32-da12f186a8bd',
    ...overrides,
  };
};

export const buildDeleteGlobalPythonModuleInput = (
  overrides: Partial<DeleteGlobalPythonModuleInput> = {}
): DeleteGlobalPythonModuleInput => {
  return {
    globals: 'globals' in overrides ? overrides.globals : [buildDeleteGlobalPythonInputItem()],
    ...overrides,
  };
};

export const buildDeletePolicyInput = (
  overrides: Partial<DeletePolicyInput> = {}
): DeletePolicyInput => {
  return {
    policies: 'policies' in overrides ? overrides.policies : [buildDeletePolicyInputItem()],
    ...overrides,
  };
};

export const buildDeletePolicyInputItem = (
  overrides: Partial<DeletePolicyInputItem> = {}
): DeletePolicyInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : 'a5304976-d86e-44d0-abe1-902e2565a38b',
    ...overrides,
  };
};

export const buildDeleteRuleInput = (overrides: Partial<DeleteRuleInput> = {}): DeleteRuleInput => {
  return {
    rules: 'rules' in overrides ? overrides.rules : [buildDeleteRuleInputItem()],
    ...overrides,
  };
};

export const buildDeleteRuleInputItem = (
  overrides: Partial<DeleteRuleInputItem> = {}
): DeleteRuleInputItem => {
  return {
    id: 'id' in overrides ? overrides.id : '9c1a40a6-8106-4f56-82b7-b71d4afc0065',
    ...overrides,
  };
};

export const buildDestination = (overrides: Partial<Destination> = {}): Destination => {
  return {
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
    ...overrides,
    __typename: 'Destination',
  };
};

export const buildDestinationConfig = (
  overrides: Partial<DestinationConfig> = {}
): DestinationConfig => {
  return {
    slack: 'slack' in overrides ? overrides.slack : buildSlackConfig(),
    sns: 'sns' in overrides ? overrides.sns : buildSnsConfig(),
    sqs: 'sqs' in overrides ? overrides.sqs : buildSqsConfig(),
    pagerDuty: 'pagerDuty' in overrides ? overrides.pagerDuty : buildPagerDutyConfig(),
    github: 'github' in overrides ? overrides.github : buildGithubConfig(),
    jira: 'jira' in overrides ? overrides.jira : buildJiraConfig(),
    opsgenie: 'opsgenie' in overrides ? overrides.opsgenie : buildOpsgenieConfig(),
    msTeams: 'msTeams' in overrides ? overrides.msTeams : buildMsTeamsConfig(),
    asana: 'asana' in overrides ? overrides.asana : buildAsanaConfig(),
    customWebhook:
      'customWebhook' in overrides ? overrides.customWebhook : buildCustomWebhookConfig(),
    ...overrides,
    __typename: 'DestinationConfig',
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
    ...overrides,
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
    ...overrides,
  };
};

export const buildGeneralSettings = (overrides: Partial<GeneralSettings> = {}): GeneralSettings => {
  return {
    displayName: 'displayName' in overrides ? overrides.displayName : 'Rustic',
    email: 'email' in overrides ? overrides.email : 'tertiary',
    errorReportingConsent:
      'errorReportingConsent' in overrides ? overrides.errorReportingConsent : false,
    ...overrides,
    __typename: 'GeneralSettings',
  };
};

export const buildGetAlertInput = (overrides: Partial<GetAlertInput> = {}): GetAlertInput => {
  return {
    alertId: 'alertId' in overrides ? overrides.alertId : '7dccc616-0ef2-4b9e-87ed-63b936c53e09',
    eventsPageSize: 'eventsPageSize' in overrides ? overrides.eventsPageSize : 385,
    eventsExclusiveStartKey:
      'eventsExclusiveStartKey' in overrides ? overrides.eventsExclusiveStartKey : 'Sleek',
    ...overrides,
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
    ...overrides,
  };
};

export const buildGetGlobalPythonModuleInput = (
  overrides: Partial<GetGlobalPythonModuleInput> = {}
): GetGlobalPythonModuleInput => {
  return {
    globalId: 'globalId' in overrides ? overrides.globalId : '0f341f61-9f20-4e1f-b8e0-5854a50dc594',
    versionId:
      'versionId' in overrides ? overrides.versionId : '9fe39f4b-d18f-4a21-99a0-eeef9b77cb11',
    ...overrides,
  };
};

export const buildGetPolicyInput = (overrides: Partial<GetPolicyInput> = {}): GetPolicyInput => {
  return {
    policyId: 'policyId' in overrides ? overrides.policyId : 'f6a78c98-6d80-46bf-89e7-3df8975184a0',
    versionId:
      'versionId' in overrides ? overrides.versionId : 'd394a64d-9476-44de-a8ab-7f8666cd4c8c',
    ...overrides,
  };
};

export const buildGetResourceInput = (
  overrides: Partial<GetResourceInput> = {}
): GetResourceInput => {
  return {
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : '913c64fb-c124-4dce-9757-51846aa5f4df',
    ...overrides,
  };
};

export const buildGetRuleInput = (overrides: Partial<GetRuleInput> = {}): GetRuleInput => {
  return {
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '3b255df9-8276-4060-8f0c-cca418b158d6',
    versionId:
      'versionId' in overrides ? overrides.versionId : '1b6ea7a4-7775-4b65-8315-89b764428571',
    ...overrides,
  };
};

export const buildGetS3LogIntegrationTemplateInput = (
  overrides: Partial<GetS3LogIntegrationTemplateInput> = {}
): GetS3LogIntegrationTemplateInput => {
  return {
    awsAccountId: 'awsAccountId' in overrides ? overrides.awsAccountId : 'Armenia',
    integrationLabel: 'integrationLabel' in overrides ? overrides.integrationLabel : 'Concrete',
    s3Bucket: 's3Bucket' in overrides ? overrides.s3Bucket : 'generating',
    s3Prefix: 's3Prefix' in overrides ? overrides.s3Prefix : 'optical',
    kmsKey: 'kmsKey' in overrides ? overrides.kmsKey : 'Books',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Borders'],
    ...overrides,
  };
};

export const buildGithubConfig = (overrides: Partial<GithubConfig> = {}): GithubConfig => {
  return {
    repoName: 'repoName' in overrides ? overrides.repoName : 'quantify',
    token: 'token' in overrides ? overrides.token : 'International',
    ...overrides,
    __typename: 'GithubConfig',
  };
};

export const buildGithubConfigInput = (
  overrides: Partial<GithubConfigInput> = {}
): GithubConfigInput => {
  return {
    repoName: 'repoName' in overrides ? overrides.repoName : 'Route',
    token: 'token' in overrides ? overrides.token : 'Hat',
    ...overrides,
  };
};

export const buildGlobalPythonModule = (
  overrides: Partial<GlobalPythonModule> = {}
): GlobalPythonModule => {
  return {
    body: 'body' in overrides ? overrides.body : '5th generation',
    description: 'description' in overrides ? overrides.description : 'models',
    id: 'id' in overrides ? overrides.id : '42f3a049-dced-4b20-925c-a8e861b2d2d0',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-02-07T06:16:18.558Z',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-01-27T02:38:32.897Z',
    ...overrides,
    __typename: 'GlobalPythonModule',
  };
};

export const buildIntegrationItemHealthStatus = (
  overrides: Partial<IntegrationItemHealthStatus> = {}
): IntegrationItemHealthStatus => {
  return {
    healthy: 'healthy' in overrides ? overrides.healthy : false,
    errorMessage: 'errorMessage' in overrides ? overrides.errorMessage : 'Nebraska',
    ...overrides,
    __typename: 'IntegrationItemHealthStatus',
  };
};

export const buildIntegrationTemplate = (
  overrides: Partial<IntegrationTemplate> = {}
): IntegrationTemplate => {
  return {
    body: 'body' in overrides ? overrides.body : 'bandwidth',
    stackName: 'stackName' in overrides ? overrides.stackName : 'Handcrafted Granite Mouse',
    ...overrides,
    __typename: 'IntegrationTemplate',
  };
};

export const buildInviteUserInput = (overrides: Partial<InviteUserInput> = {}): InviteUserInput => {
  return {
    givenName: 'givenName' in overrides ? overrides.givenName : 'system-worthy',
    familyName: 'familyName' in overrides ? overrides.familyName : 'copy',
    email: 'email' in overrides ? overrides.email : 'Gennaro_Kerluke71@gmail.com',
    ...overrides,
  };
};

export const buildJiraConfig = (overrides: Partial<JiraConfig> = {}): JiraConfig => {
  return {
    orgDomain: 'orgDomain' in overrides ? overrides.orgDomain : 'deposit',
    projectKey: 'projectKey' in overrides ? overrides.projectKey : 'Investor',
    userName: 'userName' in overrides ? overrides.userName : 'payment',
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'bluetooth',
    assigneeId: 'assigneeId' in overrides ? overrides.assigneeId : 'bleeding-edge',
    issueType: 'issueType' in overrides ? overrides.issueType : 'Iowa',
    ...overrides,
    __typename: 'JiraConfig',
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
    ...overrides,
  };
};

export const buildListAlertsInput = (overrides: Partial<ListAlertsInput> = {}): ListAlertsInput => {
  return {
    ruleId: 'ruleId' in overrides ? overrides.ruleId : '4d7dfe6a-56ac-41c2-bfc1-1eaf33c0215a',
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 828,
    exclusiveStartKey:
      'exclusiveStartKey' in overrides ? overrides.exclusiveStartKey : 'Throughway',
    severity: 'severity' in overrides ? overrides.severity : [SeverityEnum.Low],
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'Island',
    createdAtBefore:
      'createdAtBefore' in overrides ? overrides.createdAtBefore : '2020-05-22T12:33:45.819Z',
    createdAtAfter:
      'createdAtAfter' in overrides ? overrides.createdAtAfter : '2020-04-26T13:02:02.091Z',
    ruleIdContains: 'ruleIdContains' in overrides ? overrides.ruleIdContains : 'virtual',
    alertIdContains: 'alertIdContains' in overrides ? overrides.alertIdContains : 'Garden',
    eventCountMin: 'eventCountMin' in overrides ? overrides.eventCountMin : 694,
    eventCountMax: 'eventCountMax' in overrides ? overrides.eventCountMax : 911,
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListAlertsSortFieldsEnum.CreatedAt,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Descending,
    ...overrides,
  };
};

export const buildListAlertsResponse = (
  overrides: Partial<ListAlertsResponse> = {}
): ListAlertsResponse => {
  return {
    alertSummaries:
      'alertSummaries' in overrides ? overrides.alertSummaries : [buildAlertSummary()],
    lastEvaluatedKey: 'lastEvaluatedKey' in overrides ? overrides.lastEvaluatedKey : 'Arkansas',
    ...overrides,
    __typename: 'ListAlertsResponse',
  };
};

export const buildListComplianceItemsResponse = (
  overrides: Partial<ListComplianceItemsResponse> = {}
): ListComplianceItemsResponse => {
  return {
    items: 'items' in overrides ? overrides.items : [buildComplianceItem()],
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    status: 'status' in overrides ? overrides.status : ComplianceStatusEnum.Fail,
    totals: 'totals' in overrides ? overrides.totals : buildActiveSuppressCount(),
    ...overrides,
    __typename: 'ListComplianceItemsResponse',
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
    ...overrides,
  };
};

export const buildListGlobalPythonModulesResponse = (
  overrides: Partial<ListGlobalPythonModulesResponse> = {}
): ListGlobalPythonModulesResponse => {
  return {
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    globals: 'globals' in overrides ? overrides.globals : [buildGlobalPythonModule()],
    ...overrides,
    __typename: 'ListGlobalPythonModulesResponse',
  };
};

export const buildListPoliciesInput = (
  overrides: Partial<ListPoliciesInput> = {}
): ListPoliciesInput => {
  return {
    complianceStatus:
      'complianceStatus' in overrides ? overrides.complianceStatus : ComplianceStatusEnum.Pass,
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'parse',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    hasRemediation: 'hasRemediation' in overrides ? overrides.hasRemediation : false,
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : 'software',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.High,
    tags: 'tags' in overrides ? overrides.tags : 'Fish',
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListPoliciesSortFieldsEnum.ResourceTypes,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Ascending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 50,
    page: 'page' in overrides ? overrides.page : 254,
    ...overrides,
  };
};

export const buildListPoliciesResponse = (
  overrides: Partial<ListPoliciesResponse> = {}
): ListPoliciesResponse => {
  return {
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    policies: 'policies' in overrides ? overrides.policies : [buildPolicySummary()],
    ...overrides,
    __typename: 'ListPoliciesResponse',
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
    types: 'types' in overrides ? overrides.types : 'black',
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListResourcesSortFieldsEnum.Type,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Descending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 228,
    page: 'page' in overrides ? overrides.page : 643,
    ...overrides,
  };
};

export const buildListResourcesResponse = (
  overrides: Partial<ListResourcesResponse> = {}
): ListResourcesResponse => {
  return {
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    resources: 'resources' in overrides ? overrides.resources : [buildResourceSummary()],
    ...overrides,
    __typename: 'ListResourcesResponse',
  };
};

export const buildListRulesInput = (overrides: Partial<ListRulesInput> = {}): ListRulesInput => {
  return {
    nameContains: 'nameContains' in overrides ? overrides.nameContains : 'Cotton',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    logTypes: 'logTypes' in overrides ? overrides.logTypes : 'Drive',
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Low,
    tags: 'tags' in overrides ? overrides.tags : 'channels',
    sortBy: 'sortBy' in overrides ? overrides.sortBy : ListRulesSortFieldsEnum.Enabled,
    sortDir: 'sortDir' in overrides ? overrides.sortDir : SortDirEnum.Ascending,
    pageSize: 'pageSize' in overrides ? overrides.pageSize : 19,
    page: 'page' in overrides ? overrides.page : 323,
    ...overrides,
  };
};

export const buildListRulesResponse = (
  overrides: Partial<ListRulesResponse> = {}
): ListRulesResponse => {
  return {
    paging: 'paging' in overrides ? overrides.paging : buildPagingData(),
    rules: 'rules' in overrides ? overrides.rules : [buildRuleSummary()],
    ...overrides,
    __typename: 'ListRulesResponse',
  };
};

export const buildModifyGlobalPythonModuleInput = (
  overrides: Partial<ModifyGlobalPythonModuleInput> = {}
): ModifyGlobalPythonModuleInput => {
  return {
    description: 'description' in overrides ? overrides.description : 'Tools',
    id: 'id' in overrides ? overrides.id : 'af4a9975-adcf-4efc-b667-f59f6214197c',
    body: 'body' in overrides ? overrides.body : 'evolve',
    ...overrides,
  };
};

export const buildMsTeamsConfig = (overrides: Partial<MsTeamsConfig> = {}): MsTeamsConfig => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'eyeballs',
    ...overrides,
    __typename: 'MsTeamsConfig',
  };
};

export const buildMsTeamsConfigInput = (
  overrides: Partial<MsTeamsConfigInput> = {}
): MsTeamsConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'USB',
    ...overrides,
  };
};

export const buildOpsgenieConfig = (overrides: Partial<OpsgenieConfig> = {}): OpsgenieConfig => {
  return {
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'IB',
    ...overrides,
    __typename: 'OpsgenieConfig',
  };
};

export const buildOpsgenieConfigInput = (
  overrides: Partial<OpsgenieConfigInput> = {}
): OpsgenieConfigInput => {
  return {
    apiKey: 'apiKey' in overrides ? overrides.apiKey : 'hacking',
    ...overrides,
  };
};

export const buildOrganizationReportBySeverity = (
  overrides: Partial<OrganizationReportBySeverity> = {}
): OrganizationReportBySeverity => {
  return {
    info: 'info' in overrides ? overrides.info : buildComplianceStatusCounts(),
    low: 'low' in overrides ? overrides.low : buildComplianceStatusCounts(),
    medium: 'medium' in overrides ? overrides.medium : buildComplianceStatusCounts(),
    high: 'high' in overrides ? overrides.high : buildComplianceStatusCounts(),
    critical: 'critical' in overrides ? overrides.critical : buildComplianceStatusCounts(),
    ...overrides,
    __typename: 'OrganizationReportBySeverity',
  };
};

export const buildOrganizationStatsInput = (
  overrides: Partial<OrganizationStatsInput> = {}
): OrganizationStatsInput => {
  return {
    limitTopFailing: 'limitTopFailing' in overrides ? overrides.limitTopFailing : 818,
    ...overrides,
  };
};

export const buildOrganizationStatsResponse = (
  overrides: Partial<OrganizationStatsResponse> = {}
): OrganizationStatsResponse => {
  return {
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
    ...overrides,
    __typename: 'OrganizationStatsResponse',
  };
};

export const buildPagerDutyConfig = (overrides: Partial<PagerDutyConfig> = {}): PagerDutyConfig => {
  return {
    integrationKey: 'integrationKey' in overrides ? overrides.integrationKey : 'transform',
    ...overrides,
    __typename: 'PagerDutyConfig',
  };
};

export const buildPagerDutyConfigInput = (
  overrides: Partial<PagerDutyConfigInput> = {}
): PagerDutyConfigInput => {
  return {
    integrationKey: 'integrationKey' in overrides ? overrides.integrationKey : 'Soft',
    ...overrides,
  };
};

export const buildPagingData = (overrides: Partial<PagingData> = {}): PagingData => {
  return {
    thisPage: 'thisPage' in overrides ? overrides.thisPage : 289,
    totalPages: 'totalPages' in overrides ? overrides.totalPages : 812,
    totalItems: 'totalItems' in overrides ? overrides.totalItems : 394,
    ...overrides,
    __typename: 'PagingData',
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
    ...overrides,
  };
};

export const buildPolicyDetails = (overrides: Partial<PolicyDetails> = {}): PolicyDetails => {
  return {
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTest()],
    versionId:
      'versionId' in overrides ? overrides.versionId : 'ca391fc7-f186-4bcb-b717-3e34cb330d83',
    ...overrides,
    __typename: 'PolicyDetails',
  };
};

export const buildPolicySummary = (overrides: Partial<PolicySummary> = {}): PolicySummary => {
  return {
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
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['EXE'],
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Critical,
    tags: 'tags' in overrides ? overrides.tags : ['navigating'],
    ...overrides,
    __typename: 'PolicySummary',
  };
};

export const buildPolicyUnitTest = (overrides: Partial<PolicyUnitTest> = {}): PolicyUnitTest => {
  return {
    expectedResult: 'expectedResult' in overrides ? overrides.expectedResult : true,
    name: 'name' in overrides ? overrides.name : 'Table',
    resource: 'resource' in overrides ? overrides.resource : 'deposit',
    ...overrides,
    __typename: 'PolicyUnitTest',
  };
};

export const buildPolicyUnitTestError = (
  overrides: Partial<PolicyUnitTestError> = {}
): PolicyUnitTestError => {
  return {
    name: 'name' in overrides ? overrides.name : 'override',
    errorMessage: 'errorMessage' in overrides ? overrides.errorMessage : 'Frozen',
    ...overrides,
    __typename: 'PolicyUnitTestError',
  };
};

export const buildPolicyUnitTestInput = (
  overrides: Partial<PolicyUnitTestInput> = {}
): PolicyUnitTestInput => {
  return {
    expectedResult: 'expectedResult' in overrides ? overrides.expectedResult : false,
    name: 'name' in overrides ? overrides.name : 'application',
    resource: 'resource' in overrides ? overrides.resource : 'Right-sized',
    ...overrides,
  };
};

export const buildRemediateResourceInput = (
  overrides: Partial<RemediateResourceInput> = {}
): RemediateResourceInput => {
  return {
    policyId: 'policyId' in overrides ? overrides.policyId : '9f991f1d-dcc4-4ce1-8490-335f34dd4da9',
    resourceId:
      'resourceId' in overrides ? overrides.resourceId : '17cb94ba-4961-439a-9cbf-c305e26019da',
    ...overrides,
  };
};

export const buildResourceDetails = (overrides: Partial<ResourceDetails> = {}): ResourceDetails => {
  return {
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
    ...overrides,
    __typename: 'ResourceDetails',
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
    ...overrides,
  };
};

export const buildResourceSummary = (overrides: Partial<ResourceSummary> = {}): ResourceSummary => {
  return {
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
    ...overrides,
    __typename: 'ResourceSummary',
  };
};

export const buildRuleDetails = (overrides: Partial<RuleDetails> = {}): RuleDetails => {
  return {
    body: 'body' in overrides ? overrides.body : 'Shoes',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : '2020-08-03T05:47:47.012Z',
    createdBy:
      'createdBy' in overrides ? overrides.createdBy : '6c3e570b-c621-4e3a-aab1-8a21e9aa4d17',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 34,
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTest()],
    versionId:
      'versionId' in overrides ? overrides.versionId : 'cd730243-e772-446f-b820-ff796b83a51f',
    ...overrides,
    __typename: 'RuleDetails',
  };
};

export const buildRuleSummary = (overrides: Partial<RuleSummary> = {}): RuleSummary => {
  return {
    displayName: 'displayName' in overrides ? overrides.displayName : 'array',
    enabled: 'enabled' in overrides ? overrides.enabled : false,
    id: 'id' in overrides ? overrides.id : '4ce135b7-005f-4a98-8a69-9b9d3b372bdb',
    lastModified: 'lastModified' in overrides ? overrides.lastModified : '2020-10-11T23:20:19.662Z',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['AI'],
    severity: 'severity' in overrides ? overrides.severity : SeverityEnum.Info,
    tags: 'tags' in overrides ? overrides.tags : ['Virginia'],
    ...overrides,
    __typename: 'RuleSummary',
  };
};

export const buildS3LogIntegration = (
  overrides: Partial<S3LogIntegration> = {}
): S3LogIntegration => {
  return {
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
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['strategize'],
    health: 'health' in overrides ? overrides.health : buildS3LogIntegrationHealth(),
    stackName: 'stackName' in overrides ? overrides.stackName : 'River',
    ...overrides,
    __typename: 'S3LogIntegration',
  };
};

export const buildS3LogIntegrationHealth = (
  overrides: Partial<S3LogIntegrationHealth> = {}
): S3LogIntegrationHealth => {
  return {
    processingRoleStatus:
      'processingRoleStatus' in overrides
        ? overrides.processingRoleStatus
        : buildIntegrationItemHealthStatus(),
    s3BucketStatus:
      's3BucketStatus' in overrides ? overrides.s3BucketStatus : buildIntegrationItemHealthStatus(),
    kmsKeyStatus:
      'kmsKeyStatus' in overrides ? overrides.kmsKeyStatus : buildIntegrationItemHealthStatus(),
    ...overrides,
    __typename: 'S3LogIntegrationHealth',
  };
};

export const buildScannedResources = (
  overrides: Partial<ScannedResources> = {}
): ScannedResources => {
  return {
    byType: 'byType' in overrides ? overrides.byType : [buildScannedResourceStats()],
    ...overrides,
    __typename: 'ScannedResources',
  };
};

export const buildScannedResourceStats = (
  overrides: Partial<ScannedResourceStats> = {}
): ScannedResourceStats => {
  return {
    count: 'count' in overrides ? overrides.count : buildComplianceStatusCounts(),
    type: 'type' in overrides ? overrides.type : 'proactive',
    ...overrides,
    __typename: 'ScannedResourceStats',
  };
};

export const buildSlackConfig = (overrides: Partial<SlackConfig> = {}): SlackConfig => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'Manat',
    ...overrides,
    __typename: 'SlackConfig',
  };
};

export const buildSlackConfigInput = (
  overrides: Partial<SlackConfigInput> = {}
): SlackConfigInput => {
  return {
    webhookURL: 'webhookURL' in overrides ? overrides.webhookURL : 'Prairie',
    ...overrides,
  };
};

export const buildSnsConfig = (overrides: Partial<SnsConfig> = {}): SnsConfig => {
  return {
    topicArn: 'topicArn' in overrides ? overrides.topicArn : 'Outdoors',
    ...overrides,
    __typename: 'SnsConfig',
  };
};

export const buildSnsConfigInput = (overrides: Partial<SnsConfigInput> = {}): SnsConfigInput => {
  return {
    topicArn: 'topicArn' in overrides ? overrides.topicArn : 'algorithm',
    ...overrides,
  };
};

export const buildSqsConfig = (overrides: Partial<SqsConfig> = {}): SqsConfig => {
  return {
    queueUrl: 'queueUrl' in overrides ? overrides.queueUrl : 'Engineer',
    ...overrides,
    __typename: 'SqsConfig',
  };
};

export const buildSqsConfigInput = (overrides: Partial<SqsConfigInput> = {}): SqsConfigInput => {
  return {
    queueUrl: 'queueUrl' in overrides ? overrides.queueUrl : 'Seamless',
    ...overrides,
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
    ...overrides,
  };
};

export const buildTestPolicyInput = (overrides: Partial<TestPolicyInput> = {}): TestPolicyInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'Centralized',
    resourceTypes: 'resourceTypes' in overrides ? overrides.resourceTypes : ['Automotive'],
    analysisType: 'analysisType' in overrides ? overrides.analysisType : AnalysisTypeEnum.Rule,
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTestInput()],
    ...overrides,
  };
};

export const buildTestPolicyResponse = (
  overrides: Partial<TestPolicyResponse> = {}
): TestPolicyResponse => {
  return {
    testSummary: 'testSummary' in overrides ? overrides.testSummary : false,
    testsPassed: 'testsPassed' in overrides ? overrides.testsPassed : ['Producer'],
    testsFailed: 'testsFailed' in overrides ? overrides.testsFailed : ['Granite'],
    testsErrored:
      'testsErrored' in overrides ? overrides.testsErrored : [buildPolicyUnitTestError()],
    ...overrides,
    __typename: 'TestPolicyResponse',
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
    ...overrides,
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
    ...overrides,
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTestInput()],
    ...overrides,
  };
};

export const buildUpdateRuleInput = (overrides: Partial<UpdateRuleInput> = {}): UpdateRuleInput => {
  return {
    body: 'body' in overrides ? overrides.body : 'capacitor',
    dedupPeriodMinutes: 'dedupPeriodMinutes' in overrides ? overrides.dedupPeriodMinutes : 748,
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
    tests: 'tests' in overrides ? overrides.tests : [buildPolicyUnitTestInput()],
    ...overrides,
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
    s3Prefix: 's3Prefix' in overrides ? overrides.s3Prefix : 'Keyboard',
    logTypes: 'logTypes' in overrides ? overrides.logTypes : ['Dynamic'],
    ...overrides,
  };
};

export const buildUpdateUserInput = (overrides: Partial<UpdateUserInput> = {}): UpdateUserInput => {
  return {
    id: 'id' in overrides ? overrides.id : '0d6a9360-d92b-4660-9e5f-14155047bddc',
    givenName: 'givenName' in overrides ? overrides.givenName : 'Personal Loan Account',
    familyName: 'familyName' in overrides ? overrides.familyName : 'connecting',
    email: 'email' in overrides ? overrides.email : 'Eldon.Gusikowski@hotmail.com',
    ...overrides,
  };
};

export const buildUploadPoliciesInput = (
  overrides: Partial<UploadPoliciesInput> = {}
): UploadPoliciesInput => {
  return {
    data: 'data' in overrides ? overrides.data : 'back-end',
    ...overrides,
  };
};

export const buildUploadPoliciesResponse = (
  overrides: Partial<UploadPoliciesResponse> = {}
): UploadPoliciesResponse => {
  return {
    totalPolicies: 'totalPolicies' in overrides ? overrides.totalPolicies : 102,
    newPolicies: 'newPolicies' in overrides ? overrides.newPolicies : 971,
    modifiedPolicies: 'modifiedPolicies' in overrides ? overrides.modifiedPolicies : 829,
    totalRules: 'totalRules' in overrides ? overrides.totalRules : 916,
    newRules: 'newRules' in overrides ? overrides.newRules : 898,
    modifiedRules: 'modifiedRules' in overrides ? overrides.modifiedRules : 463,
    ...overrides,
    __typename: 'UploadPoliciesResponse',
  };
};

export const buildUser = (overrides: Partial<User> = {}): User => {
  return {
    givenName: 'givenName' in overrides ? overrides.givenName : 'function',
    familyName: 'familyName' in overrides ? overrides.familyName : 'Future-proofed',
    id: 'id' in overrides ? overrides.id : 'b5756f00-51a6-422a-9a7d-c13ee6a63750',
    email: 'email' in overrides ? overrides.email : 'Mac13@yahoo.com',
    createdAt: 'createdAt' in overrides ? overrides.createdAt : 1578015894449,
    status: 'status' in overrides ? overrides.status : 'experiences',
    ...overrides,
    __typename: 'User',
  };
};
