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
  overrides?: Partial<ActiveSuppressCount>
): ActiveSuppressCount => {
  return {
    __typename: 'ActiveSuppressCount',
    active: buildComplianceStatusCounts(),
    suppressed: buildComplianceStatusCounts(),
  };
};

export const buildAddComplianceIntegrationInput = (
  overrides?: Partial<AddComplianceIntegrationInput>
): AddComplianceIntegrationInput => {
  return {
    awsAccountId: 'protocol',
    integrationLabel: 'withdrawal',
    remediationEnabled: false,
    cweEnabled: false,
  };
};

export const buildAddGlobalPythonModuleInput = (
  overrides?: Partial<AddGlobalPythonModuleInput>
): AddGlobalPythonModuleInput => {
  return {
    id: '6b0f1c64-e650-48e8-abcf-37c23c6cf854',
    description: 'Dynamic',
    body: 'methodologies',
  };
};

export const buildAddPolicyInput = (overrides?: Partial<AddPolicyInput>): AddPolicyInput => {
  return {
    autoRemediationId: '2ddec795-4cf0-445d-b800-4d02470180f2',
    autoRemediationParameters: '"bar"',
    body: 'Fantastic Concrete Table',
    description: 'Qatar',
    displayName: 'matrix',
    enabled: true,
    id: '7612f488-c028-4e4f-904f-07e707ce7bdd',
    outputIds: ['16ca6d99-9a12-404b-aef5-9e522075db0d'],
    reference: 'Clothing',
    resourceTypes: ['Digitized'],
    runbook: 'HTTP',
    severity: SeverityEnum.High,
    suppressions: ['Tunisian Dinar'],
    tags: ['Security'],
    tests: [buildPolicyUnitTestInput()],
  };
};

export const buildAddRuleInput = (overrides?: Partial<AddRuleInput>): AddRuleInput => {
  return {
    body: 'microchip',
    dedupPeriodMinutes: 429,
    description: 'purple',
    displayName: 'Investment Account',
    enabled: true,
    id: 'f9463be1-4ef2-4950-b272-31540bb0cff3',
    logTypes: ['end-to-end'],
    outputIds: ['0f6aac24-85db-4208-9f04-5f9cae908a5b'],
    reference: 'mobile',
    runbook: 'Practical Granite Salad',
    severity: SeverityEnum.Medium,
    tags: ['Way'],
    tests: [buildPolicyUnitTestInput()],
  };
};

export const buildAddS3LogIntegrationInput = (
  overrides?: Partial<AddS3LogIntegrationInput>
): AddS3LogIntegrationInput => {
  return {
    awsAccountId: 'Ireland',
    integrationLabel: 'payment',
    s3Bucket: 'backing up',
    kmsKey: 'Personal Loan Account',
    s3Prefix: 'reintermediate',
    logTypes: ['expedite'],
  };
};

export const buildAlertDetails = (overrides?: Partial<AlertDetails>): AlertDetails => {
  return {
    __typename: 'AlertDetails',
    alertId: '2c5aa76d-eb43-49f0-a65c-50e4daa756a4',
    ruleId: '9ad2c6da-417d-414f-a3e5-7959acdeaa9e',
    title: 'Steel',
    creationTime: '2020-10-28T02:06:29.865Z',
    updateTime: '2020-02-22T04:54:35.910Z',
    eventsMatched: 516,
    events: ['"bar"'],
    eventsLastEvaluatedKey: 'Accountability',
    dedupString: 'Auto Loan Account',
  };
};

export const buildAlertSummary = (overrides?: Partial<AlertSummary>): AlertSummary => {
  return {
    __typename: 'AlertSummary',
    alertId: 'Administrator',
    creationTime: '2020-08-08T12:15:31.121Z',
    eventsMatched: 670,
    title: 'indexing',
    updateTime: '2020-09-17T19:32:46.882Z',
    ruleId: 'functionalities',
    severity: SeverityEnum.Medium,
  };
};

export const buildAsanaConfig = (overrides?: Partial<AsanaConfig>): AsanaConfig => {
  return {
    __typename: 'AsanaConfig',
    personalAccessToken: 'Chief',
    projectGids: ['Central'],
  };
};

export const buildAsanaConfigInput = (overrides?: Partial<AsanaConfigInput>): AsanaConfigInput => {
  return {
    personalAccessToken: 'connect',
    projectGids: ['Executive'],
  };
};

export const buildComplianceIntegration = (
  overrides?: Partial<ComplianceIntegration>
): ComplianceIntegration => {
  return {
    __typename: 'ComplianceIntegration',
    awsAccountId: 'Metrics',
    createdAtTime: '2020-11-23T16:57:57.973Z',
    createdBy: '460977ce-2de5-408b-8cd9-69796ea9f675',
    integrationId: 'd61dbbdd-68fd-4c1d-8a21-508d2115b3d3',
    integrationLabel: 'Movies',
    cweEnabled: true,
    remediationEnabled: false,
    health: buildComplianceIntegrationHealth(),
    stackName: 'Chips',
  };
};

export const buildComplianceIntegrationHealth = (
  overrides?: Partial<ComplianceIntegrationHealth>
): ComplianceIntegrationHealth => {
  return {
    __typename: 'ComplianceIntegrationHealth',
    auditRoleStatus: buildIntegrationItemHealthStatus(),
    cweRoleStatus: buildIntegrationItemHealthStatus(),
    remediationRoleStatus: buildIntegrationItemHealthStatus(),
  };
};

export const buildComplianceItem = (overrides?: Partial<ComplianceItem>): ComplianceItem => {
  return {
    __typename: 'ComplianceItem',
    errorMessage: 'functionalities',
    lastUpdated: '2020-10-29T15:59:39.128Z',
    policyId: '7704cb04-183c-44c9-9d90-8e66b37d8cb7',
    policySeverity: SeverityEnum.Critical,
    resourceId: '89b815e3-cb3b-4df5-8a6e-8f6159ca308a',
    resourceType: 'Leone',
    status: ComplianceStatusEnum.Fail,
    suppressed: true,
    integrationId: '0aec2717-f82d-47fc-a2e5-2c2a8cd72160',
  };
};

export const buildComplianceStatusCounts = (
  overrides?: Partial<ComplianceStatusCounts>
): ComplianceStatusCounts => {
  return {
    __typename: 'ComplianceStatusCounts',
    error: 71,
    fail: 488,
    pass: 154,
  };
};

export const buildCustomWebhookConfig = (
  overrides?: Partial<CustomWebhookConfig>
): CustomWebhookConfig => {
  return {
    __typename: 'CustomWebhookConfig',
    webhookURL: 'web services',
  };
};

export const buildCustomWebhookConfigInput = (
  overrides?: Partial<CustomWebhookConfigInput>
): CustomWebhookConfigInput => {
  return {
    webhookURL: 'bypass',
  };
};

export const buildDeleteGlobalPythonInputItem = (
  overrides?: Partial<DeleteGlobalPythonInputItem>
): DeleteGlobalPythonInputItem => {
  return {
    id: '28c248cf-f729-4ac6-af32-da12f186a8bd',
  };
};

export const buildDeleteGlobalPythonModuleInput = (
  overrides?: Partial<DeleteGlobalPythonModuleInput>
): DeleteGlobalPythonModuleInput => {
  return {
    globals: [buildDeleteGlobalPythonInputItem()],
  };
};

export const buildDeletePolicyInput = (
  overrides?: Partial<DeletePolicyInput>
): DeletePolicyInput => {
  return {
    policies: [buildDeletePolicyInputItem()],
  };
};

export const buildDeletePolicyInputItem = (
  overrides?: Partial<DeletePolicyInputItem>
): DeletePolicyInputItem => {
  return {
    id: 'a5304976-d86e-44d0-abe1-902e2565a38b',
  };
};

export const buildDeleteRuleInput = (overrides?: Partial<DeleteRuleInput>): DeleteRuleInput => {
  return {
    rules: [buildDeleteRuleInputItem()],
  };
};

export const buildDeleteRuleInputItem = (
  overrides?: Partial<DeleteRuleInputItem>
): DeleteRuleInputItem => {
  return {
    id: '9c1a40a6-8106-4f56-82b7-b71d4afc0065',
  };
};

export const buildDestination = (overrides?: Partial<Destination>): Destination => {
  return {
    __typename: 'Destination',
    createdBy: 'best-of-breed',
    creationTime: '2020-08-01T19:40:18.778Z',
    displayName: 'Accountability',
    lastModifiedBy: 'Tasty Granite Bike',
    lastModifiedTime: '2020-07-05T06:23:49.280Z',
    outputId: '8c0eb672-b7bb-4ef0-9d96-a2bc1abe94d7',
    outputType: DestinationTypeEnum.Sns,
    outputConfig: buildDestinationConfig(),
    verificationStatus: 'Licensed',
    defaultForSeverity: [SeverityEnum.Critical],
  };
};

export const buildDestinationConfig = (
  overrides?: Partial<DestinationConfig>
): DestinationConfig => {
  return {
    __typename: 'DestinationConfig',
    slack: buildSlackConfig(),
    sns: buildSnsConfig(),
    sqs: buildSqsConfig(),
    pagerDuty: buildPagerDutyConfig(),
    github: buildGithubConfig(),
    jira: buildJiraConfig(),
    opsgenie: buildOpsgenieConfig(),
    msTeams: buildMsTeamsConfig(),
    asana: buildAsanaConfig(),
    customWebhook: buildCustomWebhookConfig(),
  };
};

export const buildDestinationConfigInput = (
  overrides?: Partial<DestinationConfigInput>
): DestinationConfigInput => {
  return {
    slack: buildSlackConfigInput(),
    sns: buildSnsConfigInput(),
    sqs: buildSqsConfigInput(),
    pagerDuty: buildPagerDutyConfigInput(),
    github: buildGithubConfigInput(),
    jira: buildJiraConfigInput(),
    opsgenie: buildOpsgenieConfigInput(),
    msTeams: buildMsTeamsConfigInput(),
    asana: buildAsanaConfigInput(),
    customWebhook: buildCustomWebhookConfigInput(),
  };
};

export const buildDestinationInput = (overrides?: Partial<DestinationInput>): DestinationInput => {
  return {
    outputId: '736c7660-4609-4a00-b6fe-2fabc99955d3',
    displayName: 'morph',
    outputConfig: buildDestinationConfigInput(),
    outputType: 'New Hampshire',
    defaultForSeverity: [SeverityEnum.Critical],
  };
};

export const buildGeneralSettings = (overrides?: Partial<GeneralSettings>): GeneralSettings => {
  return {
    __typename: 'GeneralSettings',
    displayName: 'Rustic',
    email: 'tertiary',
    errorReportingConsent: false,
  };
};

export const buildGetAlertInput = (overrides?: Partial<GetAlertInput>): GetAlertInput => {
  return {
    alertId: '7dccc616-0ef2-4b9e-87ed-63b936c53e09',
    eventsPageSize: 385,
    eventsExclusiveStartKey: 'Sleek',
  };
};

export const buildGetComplianceIntegrationTemplateInput = (
  overrides?: Partial<GetComplianceIntegrationTemplateInput>
): GetComplianceIntegrationTemplateInput => {
  return {
    awsAccountId: 'monetize',
    integrationLabel: '24 hour',
    remediationEnabled: true,
    cweEnabled: true,
  };
};

export const buildGetGlobalPythonModuleInput = (
  overrides?: Partial<GetGlobalPythonModuleInput>
): GetGlobalPythonModuleInput => {
  return {
    globalId: '0f341f61-9f20-4e1f-b8e0-5854a50dc594',
    versionId: '9fe39f4b-d18f-4a21-99a0-eeef9b77cb11',
  };
};

export const buildGetPolicyInput = (overrides?: Partial<GetPolicyInput>): GetPolicyInput => {
  return {
    policyId: 'f6a78c98-6d80-46bf-89e7-3df8975184a0',
    versionId: 'd394a64d-9476-44de-a8ab-7f8666cd4c8c',
  };
};

export const buildGetResourceInput = (overrides?: Partial<GetResourceInput>): GetResourceInput => {
  return {
    resourceId: '913c64fb-c124-4dce-9757-51846aa5f4df',
  };
};

export const buildGetRuleInput = (overrides?: Partial<GetRuleInput>): GetRuleInput => {
  return {
    ruleId: '3b255df9-8276-4060-8f0c-cca418b158d6',
    versionId: '1b6ea7a4-7775-4b65-8315-89b764428571',
  };
};

export const buildGetS3LogIntegrationTemplateInput = (
  overrides?: Partial<GetS3LogIntegrationTemplateInput>
): GetS3LogIntegrationTemplateInput => {
  return {
    awsAccountId: 'Armenia',
    integrationLabel: 'Concrete',
    s3Bucket: 'generating',
    s3Prefix: 'optical',
    kmsKey: 'Books',
    logTypes: ['Borders'],
  };
};

export const buildGithubConfig = (overrides?: Partial<GithubConfig>): GithubConfig => {
  return {
    __typename: 'GithubConfig',
    repoName: 'quantify',
    token: 'International',
  };
};

export const buildGithubConfigInput = (
  overrides?: Partial<GithubConfigInput>
): GithubConfigInput => {
  return {
    repoName: 'Route',
    token: 'Hat',
  };
};

export const buildGlobalPythonModule = (
  overrides?: Partial<GlobalPythonModule>
): GlobalPythonModule => {
  return {
    __typename: 'GlobalPythonModule',
    body: '5th generation',
    description: 'models',
    id: '42f3a049-dced-4b20-925c-a8e861b2d2d0',
    createdAt: '2020-02-07T06:16:18.558Z',
    lastModified: '2020-01-27T02:38:32.897Z',
  };
};

export const buildIntegrationItemHealthStatus = (
  overrides?: Partial<IntegrationItemHealthStatus>
): IntegrationItemHealthStatus => {
  return {
    __typename: 'IntegrationItemHealthStatus',
    healthy: false,
    errorMessage: 'Nebraska',
  };
};

export const buildIntegrationTemplate = (
  overrides?: Partial<IntegrationTemplate>
): IntegrationTemplate => {
  return {
    __typename: 'IntegrationTemplate',
    body: 'bandwidth',
    stackName: 'Handcrafted Granite Mouse',
  };
};

export const buildInviteUserInput = (overrides?: Partial<InviteUserInput>): InviteUserInput => {
  return {
    givenName: 'system-worthy',
    familyName: 'copy',
    email: 'Gennaro_Kerluke71@gmail.com',
  };
};

export const buildJiraConfig = (overrides?: Partial<JiraConfig>): JiraConfig => {
  return {
    __typename: 'JiraConfig',
    orgDomain: 'deposit',
    projectKey: 'Investor',
    userName: 'payment',
    apiKey: 'bluetooth',
    assigneeId: 'bleeding-edge',
    issueType: 'Iowa',
  };
};

export const buildJiraConfigInput = (overrides?: Partial<JiraConfigInput>): JiraConfigInput => {
  return {
    orgDomain: 'bus',
    projectKey: 'XSS',
    userName: 'SQL',
    apiKey: 'Sleek Cotton Car',
    assigneeId: 'Virgin Islands, British',
    issueType: 'strategic',
  };
};

export const buildListAlertsInput = (overrides?: Partial<ListAlertsInput>): ListAlertsInput => {
  return {
    ruleId: '4d7dfe6a-56ac-41c2-bfc1-1eaf33c0215a',
    pageSize: 828,
    exclusiveStartKey: 'Throughway',
    severity: [SeverityEnum.Low],
    nameContains: 'Island',
    createdAtBefore: '2020-05-22T12:33:45.819Z',
    createdAtAfter: '2020-04-26T13:02:02.091Z',
    ruleIdContains: 'virtual',
    alertIdContains: 'Garden',
    eventCountMin: 694,
    eventCountMax: 911,
    sortBy: ListAlertsSortFieldsEnum.CreatedAt,
    sortDir: SortDirEnum.Descending,
  };
};

export const buildListAlertsResponse = (
  overrides?: Partial<ListAlertsResponse>
): ListAlertsResponse => {
  return {
    __typename: 'ListAlertsResponse',
    alertSummaries: [buildAlertSummary()],
    lastEvaluatedKey: 'Arkansas',
  };
};

export const buildListComplianceItemsResponse = (
  overrides?: Partial<ListComplianceItemsResponse>
): ListComplianceItemsResponse => {
  return {
    __typename: 'ListComplianceItemsResponse',
    items: [buildComplianceItem()],
    paging: buildPagingData(),
    status: ComplianceStatusEnum.Fail,
    totals: buildActiveSuppressCount(),
  };
};

export const buildListGlobalPythonModuleInput = (
  overrides?: Partial<ListGlobalPythonModuleInput>
): ListGlobalPythonModuleInput => {
  return {
    nameContains: 'Kyat',
    enabled: true,
    sortDir: SortDirEnum.Descending,
    pageSize: 444,
    page: 404,
  };
};

export const buildListGlobalPythonModulesResponse = (
  overrides?: Partial<ListGlobalPythonModulesResponse>
): ListGlobalPythonModulesResponse => {
  return {
    __typename: 'ListGlobalPythonModulesResponse',
    paging: buildPagingData(),
    globals: [buildGlobalPythonModule()],
  };
};

export const buildListPoliciesInput = (
  overrides?: Partial<ListPoliciesInput>
): ListPoliciesInput => {
  return {
    complianceStatus: ComplianceStatusEnum.Pass,
    nameContains: 'parse',
    enabled: false,
    hasRemediation: false,
    resourceTypes: 'software',
    severity: SeverityEnum.High,
    tags: 'Fish',
    sortBy: ListPoliciesSortFieldsEnum.ResourceTypes,
    sortDir: SortDirEnum.Ascending,
    pageSize: 50,
    page: 254,
  };
};

export const buildListPoliciesResponse = (
  overrides?: Partial<ListPoliciesResponse>
): ListPoliciesResponse => {
  return {
    __typename: 'ListPoliciesResponse',
    paging: buildPagingData(),
    policies: [buildPolicySummary()],
  };
};

export const buildListResourcesInput = (
  overrides?: Partial<ListResourcesInput>
): ListResourcesInput => {
  return {
    complianceStatus: ComplianceStatusEnum.Error,
    deleted: true,
    idContains: 'Borders',
    integrationId: 'ccdadc7d-2460-418b-9e63-69d7110ffc5f',
    types: 'black',
    sortBy: ListResourcesSortFieldsEnum.Type,
    sortDir: SortDirEnum.Descending,
    pageSize: 228,
    page: 643,
  };
};

export const buildListResourcesResponse = (
  overrides?: Partial<ListResourcesResponse>
): ListResourcesResponse => {
  return {
    __typename: 'ListResourcesResponse',
    paging: buildPagingData(),
    resources: [buildResourceSummary()],
  };
};

export const buildListRulesInput = (overrides?: Partial<ListRulesInput>): ListRulesInput => {
  return {
    nameContains: 'Cotton',
    enabled: false,
    logTypes: 'Drive',
    severity: SeverityEnum.Low,
    tags: 'channels',
    sortBy: ListRulesSortFieldsEnum.Enabled,
    sortDir: SortDirEnum.Ascending,
    pageSize: 19,
    page: 323,
  };
};

export const buildListRulesResponse = (
  overrides?: Partial<ListRulesResponse>
): ListRulesResponse => {
  return {
    __typename: 'ListRulesResponse',
    paging: buildPagingData(),
    rules: [buildRuleSummary()],
  };
};

export const buildModifyGlobalPythonModuleInput = (
  overrides?: Partial<ModifyGlobalPythonModuleInput>
): ModifyGlobalPythonModuleInput => {
  return {
    description: 'Tools',
    id: 'af4a9975-adcf-4efc-b667-f59f6214197c',
    body: 'evolve',
  };
};

export const buildMsTeamsConfig = (overrides?: Partial<MsTeamsConfig>): MsTeamsConfig => {
  return {
    __typename: 'MsTeamsConfig',
    webhookURL: 'eyeballs',
  };
};

export const buildMsTeamsConfigInput = (
  overrides?: Partial<MsTeamsConfigInput>
): MsTeamsConfigInput => {
  return {
    webhookURL: 'USB',
  };
};

export const buildOpsgenieConfig = (overrides?: Partial<OpsgenieConfig>): OpsgenieConfig => {
  return {
    __typename: 'OpsgenieConfig',
    apiKey: 'IB',
  };
};

export const buildOpsgenieConfigInput = (
  overrides?: Partial<OpsgenieConfigInput>
): OpsgenieConfigInput => {
  return {
    apiKey: 'hacking',
  };
};

export const buildOrganizationReportBySeverity = (
  overrides?: Partial<OrganizationReportBySeverity>
): OrganizationReportBySeverity => {
  return {
    __typename: 'OrganizationReportBySeverity',
    info: buildComplianceStatusCounts(),
    low: buildComplianceStatusCounts(),
    medium: buildComplianceStatusCounts(),
    high: buildComplianceStatusCounts(),
    critical: buildComplianceStatusCounts(),
  };
};

export const buildOrganizationStatsInput = (
  overrides?: Partial<OrganizationStatsInput>
): OrganizationStatsInput => {
  return {
    limitTopFailing: 818,
  };
};

export const buildOrganizationStatsResponse = (
  overrides?: Partial<OrganizationStatsResponse>
): OrganizationStatsResponse => {
  return {
    __typename: 'OrganizationStatsResponse',
    appliedPolicies: buildOrganizationReportBySeverity(),
    scannedResources: buildScannedResources(),
    topFailingPolicies: [buildPolicySummary()],
    topFailingResources: [buildResourceSummary()],
  };
};

export const buildPagerDutyConfig = (overrides?: Partial<PagerDutyConfig>): PagerDutyConfig => {
  return {
    __typename: 'PagerDutyConfig',
    integrationKey: 'transform',
  };
};

export const buildPagerDutyConfigInput = (
  overrides?: Partial<PagerDutyConfigInput>
): PagerDutyConfigInput => {
  return {
    integrationKey: 'Soft',
  };
};

export const buildPagingData = (overrides?: Partial<PagingData>): PagingData => {
  return {
    __typename: 'PagingData',
    thisPage: 289,
    totalPages: 812,
    totalItems: 394,
  };
};

export const buildPoliciesForResourceInput = (
  overrides?: Partial<PoliciesForResourceInput>
): PoliciesForResourceInput => {
  return {
    resourceId: 'f3bd41bd-4265-4a12-9256-53a459c62d5b',
    severity: SeverityEnum.Medium,
    status: ComplianceStatusEnum.Error,
    suppressed: false,
    pageSize: 282,
    page: 906,
  };
};

export const buildPolicyDetails = (overrides?: Partial<PolicyDetails>): PolicyDetails => {
  return {
    __typename: 'PolicyDetails',
    autoRemediationId: '63631269-b304-4865-b222-bf96d4b3162c',
    autoRemediationParameters: '"bar"',
    body: 'card',
    complianceStatus: ComplianceStatusEnum.Fail,
    createdAt: '2020-12-25T18:48:58.096Z',
    createdBy: 'cc4acb0d-22fe-4182-a29b-832f1f6d7f85',
    description: 'time-frame',
    displayName: 'navigating',
    enabled: true,
    id: '4193e9e6-d55b-48ad-8475-d171d8c2ea89',
    lastModified: '2020-05-12T04:22:53.318Z',
    lastModifiedBy: '8b4fcf01-c8f1-4fbf-bc94-e4f58d04c799',
    outputIds: ['213c2719-fb31-4502-9a8a-adda432a772a'],
    reference: 'applications',
    resourceTypes: ['Specialist'],
    runbook: 'upward-trending',
    severity: SeverityEnum.Critical,
    suppressions: ['Bike'],
    tags: ['success'],
    tests: [buildPolicyUnitTest()],
    versionId: 'ca391fc7-f186-4bcb-b717-3e34cb330d83',
  };
};

export const buildPolicySummary = (overrides?: Partial<PolicySummary>): PolicySummary => {
  return {
    __typename: 'PolicySummary',
    autoRemediationId: '43a2278e-67bf-4941-91f8-7fbe8503562c',
    autoRemediationParameters: '"car"',
    suppressions: ['Senior'],
    complianceStatus: ComplianceStatusEnum.Pass,
    displayName: 'indigo',
    enabled: false,
    id: '260cad31-ef71-4eb6-9ac1-1ca1d0da39c7',
    lastModified: '2020-09-11T01:58:47.481Z',
    resourceTypes: ['EXE'],
    severity: SeverityEnum.Critical,
    tags: ['navigating'],
  };
};

export const buildPolicyUnitTest = (overrides?: Partial<PolicyUnitTest>): PolicyUnitTest => {
  return {
    __typename: 'PolicyUnitTest',
    expectedResult: true,
    name: 'Table',
    resource: 'deposit',
  };
};

export const buildPolicyUnitTestError = (
  overrides?: Partial<PolicyUnitTestError>
): PolicyUnitTestError => {
  return {
    __typename: 'PolicyUnitTestError',
    name: 'override',
    errorMessage: 'Frozen',
  };
};

export const buildPolicyUnitTestInput = (
  overrides?: Partial<PolicyUnitTestInput>
): PolicyUnitTestInput => {
  return {
    expectedResult: false,
    name: 'application',
    resource: 'Right-sized',
  };
};

export const buildRemediateResourceInput = (
  overrides?: Partial<RemediateResourceInput>
): RemediateResourceInput => {
  return {
    policyId: '9f991f1d-dcc4-4ce1-8490-335f34dd4da9',
    resourceId: '17cb94ba-4961-439a-9cbf-c305e26019da',
  };
};

export const buildResourceDetails = (overrides?: Partial<ResourceDetails>): ResourceDetails => {
  return {
    __typename: 'ResourceDetails',
    attributes: '"car"',
    deleted: false,
    expiresAt: 969,
    id: '58de615f-2645-4b97-8a31-7cab72afe085',
    integrationId: 'c3876057-6d75-4af9-b160-a51a16359574',
    complianceStatus: ComplianceStatusEnum.Pass,
    lastModified: '2020-04-22T13:19:24.499Z',
    type: 'Ball',
  };
};

export const buildResourcesForPolicyInput = (
  overrides?: Partial<ResourcesForPolicyInput>
): ResourcesForPolicyInput => {
  return {
    policyId: 'acd9a6a4-7c52-43d2-8cd6-39bd74eb973f',
    status: ComplianceStatusEnum.Fail,
    suppressed: true,
    pageSize: 137,
    page: 354,
  };
};

export const buildResourceSummary = (overrides?: Partial<ResourceSummary>): ResourceSummary => {
  return {
    __typename: 'ResourceSummary',
    id: '9642570b-3380-417d-b139-6e9d3e887b08',
    integrationId: 'bb97638e-f07d-4ca1-96f6-206967b7c092',
    complianceStatus: ComplianceStatusEnum.Pass,
    deleted: false,
    lastModified: '2020-09-27T23:50:08.966Z',
    type: 'Illinois',
  };
};

export const buildRuleDetails = (overrides?: Partial<RuleDetails>): RuleDetails => {
  return {
    __typename: 'RuleDetails',
    body: 'Shoes',
    createdAt: '2020-08-03T05:47:47.012Z',
    createdBy: '6c3e570b-c621-4e3a-aab1-8a21e9aa4d17',
    dedupPeriodMinutes: 34,
    description: 'EXE',
    displayName: 'Advanced',
    enabled: false,
    id: 'Metal',
    lastModified: '2020-02-01T03:09:25.999Z',
    lastModifiedBy: '5c381f6d-f9c9-4de8-9d6f-dc274dc6b1e0',
    logTypes: ['Auto Loan Account'],
    outputIds: ['1460c173-140b-433a-af75-a657c342f229'],
    reference: 'wireless',
    runbook: 'withdrawal',
    severity: SeverityEnum.Low,
    tags: ['digital'],
    tests: [buildPolicyUnitTest()],
    versionId: 'cd730243-e772-446f-b820-ff796b83a51f',
  };
};

export const buildRuleSummary = (overrides?: Partial<RuleSummary>): RuleSummary => {
  return {
    __typename: 'RuleSummary',
    displayName: 'array',
    enabled: false,
    id: '4ce135b7-005f-4a98-8a69-9b9d3b372bdb',
    lastModified: '2020-10-11T23:20:19.662Z',
    logTypes: ['AI'],
    severity: SeverityEnum.Info,
    tags: ['Virginia'],
  };
};

export const buildS3LogIntegration = (overrides?: Partial<S3LogIntegration>): S3LogIntegration => {
  return {
    __typename: 'S3LogIntegration',
    awsAccountId: 'Bedfordshire',
    createdAtTime: '2020-07-03T08:10:02.259Z',
    createdBy: 'f135f3dc-9654-4752-b1a9-c20f98d87e48',
    integrationId: '73041328-928c-4ff9-a396-06b9b769900d',
    integrationType: 'Computers',
    integrationLabel: 'transmitting',
    lastEventReceived: '2020-05-25T09:20:29.138Z',
    s3Bucket: 'generating',
    s3Prefix: 'IB',
    kmsKey: 'robust',
    logTypes: ['strategize'],
    health: buildS3LogIntegrationHealth(),
    stackName: 'River',
  };
};

export const buildS3LogIntegrationHealth = (
  overrides?: Partial<S3LogIntegrationHealth>
): S3LogIntegrationHealth => {
  return {
    __typename: 'S3LogIntegrationHealth',
    processingRoleStatus: buildIntegrationItemHealthStatus(),
    s3BucketStatus: buildIntegrationItemHealthStatus(),
    kmsKeyStatus: buildIntegrationItemHealthStatus(),
  };
};

export const buildScannedResources = (overrides?: Partial<ScannedResources>): ScannedResources => {
  return {
    __typename: 'ScannedResources',
    byType: [buildScannedResourceStats()],
  };
};

export const buildScannedResourceStats = (
  overrides?: Partial<ScannedResourceStats>
): ScannedResourceStats => {
  return {
    __typename: 'ScannedResourceStats',
    count: buildComplianceStatusCounts(),
    type: 'proactive',
  };
};

export const buildSlackConfig = (overrides?: Partial<SlackConfig>): SlackConfig => {
  return {
    __typename: 'SlackConfig',
    webhookURL: 'Manat',
  };
};

export const buildSlackConfigInput = (overrides?: Partial<SlackConfigInput>): SlackConfigInput => {
  return {
    webhookURL: 'Prairie',
  };
};

export const buildSnsConfig = (overrides?: Partial<SnsConfig>): SnsConfig => {
  return {
    __typename: 'SnsConfig',
    topicArn: 'Outdoors',
  };
};

export const buildSnsConfigInput = (overrides?: Partial<SnsConfigInput>): SnsConfigInput => {
  return {
    topicArn: 'algorithm',
  };
};

export const buildSqsConfig = (overrides?: Partial<SqsConfig>): SqsConfig => {
  return {
    __typename: 'SqsConfig',
    queueUrl: 'Engineer',
  };
};

export const buildSqsConfigInput = (overrides?: Partial<SqsConfigInput>): SqsConfigInput => {
  return {
    queueUrl: 'Seamless',
  };
};

export const buildSuppressPoliciesInput = (
  overrides?: Partial<SuppressPoliciesInput>
): SuppressPoliciesInput => {
  return {
    policyIds: ['b2796f03-2f72-4717-a45b-eea5c8b2943f'],
    resourcePatterns: ['Cuban Peso Peso Convertible'],
  };
};

export const buildTestPolicyInput = (overrides?: Partial<TestPolicyInput>): TestPolicyInput => {
  return {
    body: 'Centralized',
    resourceTypes: ['Automotive'],
    analysisType: AnalysisTypeEnum.Rule,
    tests: [buildPolicyUnitTestInput()],
  };
};

export const buildTestPolicyResponse = (
  overrides?: Partial<TestPolicyResponse>
): TestPolicyResponse => {
  return {
    __typename: 'TestPolicyResponse',
    testSummary: false,
    testsPassed: ['Producer'],
    testsFailed: ['Granite'],
    testsErrored: [buildPolicyUnitTestError()],
  };
};

export const buildUpdateComplianceIntegrationInput = (
  overrides?: Partial<UpdateComplianceIntegrationInput>
): UpdateComplianceIntegrationInput => {
  return {
    integrationId: 'support',
    integrationLabel: 'holistic',
    cweEnabled: false,
    remediationEnabled: false,
  };
};

export const buildUpdateGeneralSettingsInput = (
  overrides?: Partial<UpdateGeneralSettingsInput>
): UpdateGeneralSettingsInput => {
  return {
    displayName: 'Borders',
    email: 'olive',
    errorReportingConsent: true,
  };
};

export const buildUpdatePolicyInput = (
  overrides?: Partial<UpdatePolicyInput>
): UpdatePolicyInput => {
  return {
    autoRemediationId: '3ec80d46-fb82-458d-9293-ccefffe7eeaa',
    autoRemediationParameters: '"bar"',
    body: 'Front-line',
    description: 'dot-com',
    displayName: 'deposit',
    enabled: true,
    id: 'cdf83cf0-6494-413a-a723-ddfd28c60cc7',
    outputIds: ['92126800-afab-49cc-b6fb-d7d45589f268'],
    reference: 'Table',
    resourceTypes: ['Buckinghamshire'],
    runbook: 'productize',
    severity: SeverityEnum.Info,
    suppressions: ['green'],
    tags: ['transmit'],
    tests: [buildPolicyUnitTestInput()],
  };
};

export const buildUpdateRuleInput = (overrides?: Partial<UpdateRuleInput>): UpdateRuleInput => {
  return {
    body: 'capacitor',
    dedupPeriodMinutes: 748,
    description: 'Utah',
    displayName: 'Internal',
    enabled: true,
    id: '18acb268-562c-44de-9424-28c46a166088',
    logTypes: ['initiatives'],
    outputIds: ['de925222-db76-43b8-a891-b7b6f90d8180'],
    reference: 'e-commerce',
    runbook: 'Fresh',
    severity: SeverityEnum.High,
    tags: ['Senior'],
    tests: [buildPolicyUnitTestInput()],
  };
};

export const buildUpdateS3LogIntegrationInput = (
  overrides?: Partial<UpdateS3LogIntegrationInput>
): UpdateS3LogIntegrationInput => {
  return {
    integrationId: 'expedite',
    integrationLabel: 'Buckinghamshire',
    s3Bucket: 'green',
    kmsKey: 'deposit',
    s3Prefix: 'Keyboard',
    logTypes: ['Dynamic'],
  };
};

export const buildUpdateUserInput = (overrides?: Partial<UpdateUserInput>): UpdateUserInput => {
  return {
    id: '0d6a9360-d92b-4660-9e5f-14155047bddc',
    givenName: 'Personal Loan Account',
    familyName: 'connecting',
    email: 'Eldon.Gusikowski@hotmail.com',
  };
};

export const buildUploadPoliciesInput = (
  overrides?: Partial<UploadPoliciesInput>
): UploadPoliciesInput => {
  return {
    data: 'back-end',
  };
};

export const buildUploadPoliciesResponse = (
  overrides?: Partial<UploadPoliciesResponse>
): UploadPoliciesResponse => {
  return {
    __typename: 'UploadPoliciesResponse',
    totalPolicies: 102,
    newPolicies: 971,
    modifiedPolicies: 829,
    totalRules: 916,
    newRules: 898,
    modifiedRules: 463,
  };
};

export const buildUser = (overrides?: Partial<User>): User => {
  return {
    __typename: 'User',
    givenName: 'function',
    familyName: 'Future-proofed',
    id: 'b5756f00-51a6-422a-9a7d-c13ee6a63750',
    email: 'Mac13@yahoo.com',
    createdAt: 1578015894449,
    status: 'experiences',
  };
};
