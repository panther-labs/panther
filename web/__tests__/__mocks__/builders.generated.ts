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
    active: buildComplianceStatusCounts(),
    suppressed: buildComplianceStatusCounts(),
    ...overrides,
    __typename: 'ActiveSuppressCount',
  };
};

export const buildAddComplianceIntegrationInput = (
  overrides?: Partial<AddComplianceIntegrationInput>
): AddComplianceIntegrationInput => {
  return {
    awsAccountId: faker.random.word(),
    integrationLabel: faker.random.word(),
    remediationEnabled: faker.random.boolean(),
    cweEnabled: faker.random.boolean(),
    ...overrides,
  };
};

export const buildAddGlobalPythonModuleInput = (
  overrides?: Partial<AddGlobalPythonModuleInput>
): AddGlobalPythonModuleInput => {
  return {
    id: faker.random.uuid(),
    description: faker.random.word(),
    body: faker.random.word(),
    ...overrides,
  };
};

export const buildAddPolicyInput = (overrides?: Partial<AddPolicyInput>): AddPolicyInput => {
  return {
    autoRemediationId: faker.random.uuid(),
    autoRemediationParameters: JSON.stringify(faker.random.objectElement()),
    body: faker.random.word(),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    resourceTypes: generateRandomArray(() => faker.random.word()),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    suppressions: generateRandomArray(() => faker.random.word()),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTestInput()),
    ...overrides,
  };
};

export const buildAddRuleInput = (overrides?: Partial<AddRuleInput>): AddRuleInput => {
  return {
    body: faker.random.word(),
    dedupPeriodMinutes: faker.random.number({ min: 0, max: 1000 }),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    logTypes: generateRandomArray(() => faker.random.word()),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTestInput()),
    ...overrides,
  };
};

export const buildAddS3LogIntegrationInput = (
  overrides?: Partial<AddS3LogIntegrationInput>
): AddS3LogIntegrationInput => {
  return {
    awsAccountId: faker.random.word(),
    integrationLabel: faker.random.word(),
    s3Bucket: faker.random.word(),
    kmsKey: faker.random.word(),
    s3Prefix: faker.random.word(),
    logTypes: generateRandomArray(() => faker.random.word()),
    ...overrides,
  };
};

export const buildAlertDetails = (overrides?: Partial<AlertDetails>): AlertDetails => {
  return {
    alertId: faker.random.uuid(),
    ruleId: faker.random.uuid(),
    title: faker.random.word(),
    creationTime: faker.date.past().toISOString(),
    updateTime: faker.date.past().toISOString(),
    eventsMatched: faker.random.number({ min: 0, max: 1000 }),
    events: generateRandomArray(() => JSON.stringify(faker.random.objectElement())),
    eventsLastEvaluatedKey: faker.random.word(),
    dedupString: faker.random.word(),
    ...overrides,
    __typename: 'AlertDetails',
  };
};

export const buildAlertSummary = (overrides?: Partial<AlertSummary>): AlertSummary => {
  return {
    alertId: faker.random.word(),
    creationTime: faker.date.past().toISOString(),
    eventsMatched: faker.random.number({ min: 0, max: 1000 }),
    title: faker.random.word(),
    updateTime: faker.date.past().toISOString(),
    ruleId: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    ...overrides,
    __typename: 'AlertSummary',
  };
};

export const buildAsanaConfig = (overrides?: Partial<AsanaConfig>): AsanaConfig => {
  return {
    personalAccessToken: faker.random.word(),
    projectGids: generateRandomArray(() => faker.random.word()),
    ...overrides,
    __typename: 'AsanaConfig',
  };
};

export const buildAsanaConfigInput = (overrides?: Partial<AsanaConfigInput>): AsanaConfigInput => {
  return {
    personalAccessToken: faker.random.word(),
    projectGids: generateRandomArray(() => faker.random.word()),
    ...overrides,
  };
};

export const buildComplianceIntegration = (
  overrides?: Partial<ComplianceIntegration>
): ComplianceIntegration => {
  return {
    awsAccountId: faker.random.word(),
    createdAtTime: faker.date.past().toISOString(),
    createdBy: faker.random.uuid(),
    integrationId: faker.random.uuid(),
    integrationLabel: faker.random.word(),
    cweEnabled: faker.random.boolean(),
    remediationEnabled: faker.random.boolean(),
    health: buildComplianceIntegrationHealth(),
    stackName: faker.random.word(),
    ...overrides,
    __typename: 'ComplianceIntegration',
  };
};

export const buildComplianceIntegrationHealth = (
  overrides?: Partial<ComplianceIntegrationHealth>
): ComplianceIntegrationHealth => {
  return {
    auditRoleStatus: buildIntegrationItemHealthStatus(),
    cweRoleStatus: buildIntegrationItemHealthStatus(),
    remediationRoleStatus: buildIntegrationItemHealthStatus(),
    ...overrides,
    __typename: 'ComplianceIntegrationHealth',
  };
};

export const buildComplianceItem = (overrides?: Partial<ComplianceItem>): ComplianceItem => {
  return {
    errorMessage: faker.random.word(),
    lastUpdated: faker.date.past().toISOString(),
    policyId: faker.random.uuid(),
    policySeverity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    resourceId: faker.random.uuid(),
    resourceType: faker.random.word(),
    status: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    suppressed: faker.random.boolean(),
    integrationId: faker.random.uuid(),
    ...overrides,
    __typename: 'ComplianceItem',
  };
};

export const buildComplianceStatusCounts = (
  overrides?: Partial<ComplianceStatusCounts>
): ComplianceStatusCounts => {
  return {
    error: faker.random.number({ min: 0, max: 1000 }),
    fail: faker.random.number({ min: 0, max: 1000 }),
    pass: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
    __typename: 'ComplianceStatusCounts',
  };
};

export const buildCustomWebhookConfig = (
  overrides?: Partial<CustomWebhookConfig>
): CustomWebhookConfig => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
    __typename: 'CustomWebhookConfig',
  };
};

export const buildCustomWebhookConfigInput = (
  overrides?: Partial<CustomWebhookConfigInput>
): CustomWebhookConfigInput => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
  };
};

export const buildDeleteGlobalPythonInputItem = (
  overrides?: Partial<DeleteGlobalPythonInputItem>
): DeleteGlobalPythonInputItem => {
  return {
    id: faker.random.uuid(),
    ...overrides,
  };
};

export const buildDeleteGlobalPythonModuleInput = (
  overrides?: Partial<DeleteGlobalPythonModuleInput>
): DeleteGlobalPythonModuleInput => {
  return {
    globals: generateRandomArray(() => buildDeleteGlobalPythonInputItem()),
    ...overrides,
  };
};

export const buildDeletePolicyInput = (
  overrides?: Partial<DeletePolicyInput>
): DeletePolicyInput => {
  return {
    policies: generateRandomArray(() => buildDeletePolicyInputItem()),
    ...overrides,
  };
};

export const buildDeletePolicyInputItem = (
  overrides?: Partial<DeletePolicyInputItem>
): DeletePolicyInputItem => {
  return {
    id: faker.random.uuid(),
    ...overrides,
  };
};

export const buildDeleteRuleInput = (overrides?: Partial<DeleteRuleInput>): DeleteRuleInput => {
  return {
    rules: generateRandomArray(() => buildDeleteRuleInputItem()),
    ...overrides,
  };
};

export const buildDeleteRuleInputItem = (
  overrides?: Partial<DeleteRuleInputItem>
): DeleteRuleInputItem => {
  return {
    id: faker.random.uuid(),
    ...overrides,
  };
};

export const buildDestination = (overrides?: Partial<Destination>): Destination => {
  return {
    createdBy: faker.random.word(),
    creationTime: faker.date.past().toISOString(),
    displayName: faker.random.word(),
    lastModifiedBy: faker.random.word(),
    lastModifiedTime: faker.date.past().toISOString(),
    outputId: faker.random.uuid(),
    outputType: faker.random.arrayElement([
      DestinationTypeEnum.Slack,
      DestinationTypeEnum.Pagerduty,
      DestinationTypeEnum.Github,
      DestinationTypeEnum.Jira,
      DestinationTypeEnum.Opsgenie,
      DestinationTypeEnum.Msteams,
      DestinationTypeEnum.Sns,
      DestinationTypeEnum.Sqs,
      DestinationTypeEnum.Asana,
      DestinationTypeEnum.Customwebhook,
    ]),
    outputConfig: buildDestinationConfig(),
    verificationStatus: faker.random.word(),
    defaultForSeverity: generateRandomArray(() =>
      faker.random.arrayElement([
        SeverityEnum.Info,
        SeverityEnum.Low,
        SeverityEnum.Medium,
        SeverityEnum.High,
        SeverityEnum.Critical,
      ])
    ),
    ...overrides,
    __typename: 'Destination',
  };
};

export const buildDestinationConfig = (
  overrides?: Partial<DestinationConfig>
): DestinationConfig => {
  return {
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
    ...overrides,
    __typename: 'DestinationConfig',
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
    ...overrides,
  };
};

export const buildDestinationInput = (overrides?: Partial<DestinationInput>): DestinationInput => {
  return {
    outputId: faker.random.uuid(),
    displayName: faker.random.word(),
    outputConfig: buildDestinationConfigInput(),
    outputType: faker.random.word(),
    defaultForSeverity: generateRandomArray(() =>
      faker.random.arrayElement([
        SeverityEnum.Info,
        SeverityEnum.Low,
        SeverityEnum.Medium,
        SeverityEnum.High,
        SeverityEnum.Critical,
      ])
    ),
    ...overrides,
  };
};

export const buildGeneralSettings = (overrides?: Partial<GeneralSettings>): GeneralSettings => {
  return {
    displayName: faker.random.word(),
    email: faker.random.word(),
    errorReportingConsent: faker.random.boolean(),
    ...overrides,
    __typename: 'GeneralSettings',
  };
};

export const buildGetAlertInput = (overrides?: Partial<GetAlertInput>): GetAlertInput => {
  return {
    alertId: faker.random.uuid(),
    eventsPageSize: faker.random.number({ min: 0, max: 1000 }),
    eventsExclusiveStartKey: faker.random.word(),
    ...overrides,
  };
};

export const buildGetComplianceIntegrationTemplateInput = (
  overrides?: Partial<GetComplianceIntegrationTemplateInput>
): GetComplianceIntegrationTemplateInput => {
  return {
    awsAccountId: faker.random.word(),
    integrationLabel: faker.random.word(),
    remediationEnabled: faker.random.boolean(),
    cweEnabled: faker.random.boolean(),
    ...overrides,
  };
};

export const buildGetGlobalPythonModuleInput = (
  overrides?: Partial<GetGlobalPythonModuleInput>
): GetGlobalPythonModuleInput => {
  return {
    globalId: faker.random.uuid(),
    versionId: faker.random.uuid(),
    ...overrides,
  };
};

export const buildGetPolicyInput = (overrides?: Partial<GetPolicyInput>): GetPolicyInput => {
  return {
    policyId: faker.random.uuid(),
    versionId: faker.random.uuid(),
    ...overrides,
  };
};

export const buildGetResourceInput = (overrides?: Partial<GetResourceInput>): GetResourceInput => {
  return {
    resourceId: faker.random.uuid(),
    ...overrides,
  };
};

export const buildGetRuleInput = (overrides?: Partial<GetRuleInput>): GetRuleInput => {
  return {
    ruleId: faker.random.uuid(),
    versionId: faker.random.uuid(),
    ...overrides,
  };
};

export const buildGetS3LogIntegrationTemplateInput = (
  overrides?: Partial<GetS3LogIntegrationTemplateInput>
): GetS3LogIntegrationTemplateInput => {
  return {
    awsAccountId: faker.random.word(),
    integrationLabel: faker.random.word(),
    s3Bucket: faker.random.word(),
    s3Prefix: faker.random.word(),
    kmsKey: faker.random.word(),
    logTypes: generateRandomArray(() => faker.random.word()),
    ...overrides,
  };
};

export const buildGithubConfig = (overrides?: Partial<GithubConfig>): GithubConfig => {
  return {
    repoName: faker.random.word(),
    token: faker.random.word(),
    ...overrides,
    __typename: 'GithubConfig',
  };
};

export const buildGithubConfigInput = (
  overrides?: Partial<GithubConfigInput>
): GithubConfigInput => {
  return {
    repoName: faker.random.word(),
    token: faker.random.word(),
    ...overrides,
  };
};

export const buildGlobalPythonModule = (
  overrides?: Partial<GlobalPythonModule>
): GlobalPythonModule => {
  return {
    body: faker.random.word(),
    description: faker.random.word(),
    id: faker.random.uuid(),
    createdAt: faker.date.past().toISOString(),
    lastModified: faker.date.past().toISOString(),
    ...overrides,
    __typename: 'GlobalPythonModule',
  };
};

export const buildIntegrationItemHealthStatus = (
  overrides?: Partial<IntegrationItemHealthStatus>
): IntegrationItemHealthStatus => {
  return {
    healthy: faker.random.boolean(),
    errorMessage: faker.random.word(),
    ...overrides,
    __typename: 'IntegrationItemHealthStatus',
  };
};

export const buildIntegrationTemplate = (
  overrides?: Partial<IntegrationTemplate>
): IntegrationTemplate => {
  return {
    body: faker.random.word(),
    stackName: faker.random.word(),
    ...overrides,
    __typename: 'IntegrationTemplate',
  };
};

export const buildInviteUserInput = (overrides?: Partial<InviteUserInput>): InviteUserInput => {
  return {
    givenName: faker.random.word(),
    familyName: faker.random.word(),
    email: faker.internet.email(),
    ...overrides,
  };
};

export const buildJiraConfig = (overrides?: Partial<JiraConfig>): JiraConfig => {
  return {
    orgDomain: faker.random.word(),
    projectKey: faker.random.word(),
    userName: faker.random.word(),
    apiKey: faker.random.word(),
    assigneeId: faker.random.word(),
    issueType: faker.random.word(),
    ...overrides,
    __typename: 'JiraConfig',
  };
};

export const buildJiraConfigInput = (overrides?: Partial<JiraConfigInput>): JiraConfigInput => {
  return {
    orgDomain: faker.random.word(),
    projectKey: faker.random.word(),
    userName: faker.random.word(),
    apiKey: faker.random.word(),
    assigneeId: faker.random.word(),
    issueType: faker.random.word(),
    ...overrides,
  };
};

export const buildListAlertsInput = (overrides?: Partial<ListAlertsInput>): ListAlertsInput => {
  return {
    ruleId: faker.random.uuid(),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    exclusiveStartKey: faker.random.word(),
    severity: generateRandomArray(() =>
      faker.random.arrayElement([
        SeverityEnum.Info,
        SeverityEnum.Low,
        SeverityEnum.Medium,
        SeverityEnum.High,
        SeverityEnum.Critical,
      ])
    ),
    nameContains: faker.random.word(),
    createdAtBefore: faker.date.past().toISOString(),
    createdAtAfter: faker.date.past().toISOString(),
    ruleIdContains: faker.random.word(),
    alertIdContains: faker.random.word(),
    eventCountMin: faker.random.number({ min: 0, max: 1000 }),
    eventCountMax: faker.random.number({ min: 0, max: 1000 }),
    sortBy: faker.random.arrayElement([ListAlertsSortFieldsEnum.CreatedAt]),
    sortDir: faker.random.arrayElement([SortDirEnum.Ascending, SortDirEnum.Descending]),
    ...overrides,
  };
};

export const buildListAlertsResponse = (
  overrides?: Partial<ListAlertsResponse>
): ListAlertsResponse => {
  return {
    alertSummaries: generateRandomArray(() => buildAlertSummary()),
    lastEvaluatedKey: faker.random.word(),
    ...overrides,
    __typename: 'ListAlertsResponse',
  };
};

export const buildListComplianceItemsResponse = (
  overrides?: Partial<ListComplianceItemsResponse>
): ListComplianceItemsResponse => {
  return {
    items: generateRandomArray(() => buildComplianceItem()),
    paging: buildPagingData(),
    status: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    totals: buildActiveSuppressCount(),
    ...overrides,
    __typename: 'ListComplianceItemsResponse',
  };
};

export const buildListGlobalPythonModuleInput = (
  overrides?: Partial<ListGlobalPythonModuleInput>
): ListGlobalPythonModuleInput => {
  return {
    nameContains: faker.random.word(),
    enabled: faker.random.boolean(),
    sortDir: faker.random.arrayElement([SortDirEnum.Ascending, SortDirEnum.Descending]),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildListGlobalPythonModulesResponse = (
  overrides?: Partial<ListGlobalPythonModulesResponse>
): ListGlobalPythonModulesResponse => {
  return {
    paging: buildPagingData(),
    globals: generateRandomArray(() => buildGlobalPythonModule()),
    ...overrides,
    __typename: 'ListGlobalPythonModulesResponse',
  };
};

export const buildListPoliciesInput = (
  overrides?: Partial<ListPoliciesInput>
): ListPoliciesInput => {
  return {
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    nameContains: faker.random.word(),
    enabled: faker.random.boolean(),
    hasRemediation: faker.random.boolean(),
    resourceTypes: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: faker.random.word(),
    sortBy: faker.random.arrayElement([
      ListPoliciesSortFieldsEnum.ComplianceStatus,
      ListPoliciesSortFieldsEnum.Enabled,
      ListPoliciesSortFieldsEnum.Id,
      ListPoliciesSortFieldsEnum.LastModified,
      ListPoliciesSortFieldsEnum.Severity,
      ListPoliciesSortFieldsEnum.ResourceTypes,
    ]),
    sortDir: faker.random.arrayElement([SortDirEnum.Ascending, SortDirEnum.Descending]),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildListPoliciesResponse = (
  overrides?: Partial<ListPoliciesResponse>
): ListPoliciesResponse => {
  return {
    paging: buildPagingData(),
    policies: generateRandomArray(() => buildPolicySummary()),
    ...overrides,
    __typename: 'ListPoliciesResponse',
  };
};

export const buildListResourcesInput = (
  overrides?: Partial<ListResourcesInput>
): ListResourcesInput => {
  return {
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    deleted: faker.random.boolean(),
    idContains: faker.random.word(),
    integrationId: faker.random.uuid(),
    types: faker.random.word(),
    sortBy: faker.random.arrayElement([
      ListResourcesSortFieldsEnum.ComplianceStatus,
      ListResourcesSortFieldsEnum.Id,
      ListResourcesSortFieldsEnum.LastModified,
      ListResourcesSortFieldsEnum.Type,
    ]),
    sortDir: faker.random.arrayElement([SortDirEnum.Ascending, SortDirEnum.Descending]),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildListResourcesResponse = (
  overrides?: Partial<ListResourcesResponse>
): ListResourcesResponse => {
  return {
    paging: buildPagingData(),
    resources: generateRandomArray(() => buildResourceSummary()),
    ...overrides,
    __typename: 'ListResourcesResponse',
  };
};

export const buildListRulesInput = (overrides?: Partial<ListRulesInput>): ListRulesInput => {
  return {
    nameContains: faker.random.word(),
    enabled: faker.random.boolean(),
    logTypes: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: faker.random.word(),
    sortBy: faker.random.arrayElement([
      ListRulesSortFieldsEnum.Enabled,
      ListRulesSortFieldsEnum.Id,
      ListRulesSortFieldsEnum.LastModified,
      ListRulesSortFieldsEnum.LogTypes,
      ListRulesSortFieldsEnum.Severity,
    ]),
    sortDir: faker.random.arrayElement([SortDirEnum.Ascending, SortDirEnum.Descending]),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildListRulesResponse = (
  overrides?: Partial<ListRulesResponse>
): ListRulesResponse => {
  return {
    paging: buildPagingData(),
    rules: generateRandomArray(() => buildRuleSummary()),
    ...overrides,
    __typename: 'ListRulesResponse',
  };
};

export const buildModifyGlobalPythonModuleInput = (
  overrides?: Partial<ModifyGlobalPythonModuleInput>
): ModifyGlobalPythonModuleInput => {
  return {
    description: faker.random.word(),
    id: faker.random.uuid(),
    body: faker.random.word(),
    ...overrides,
  };
};

export const buildMsTeamsConfig = (overrides?: Partial<MsTeamsConfig>): MsTeamsConfig => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
    __typename: 'MsTeamsConfig',
  };
};

export const buildMsTeamsConfigInput = (
  overrides?: Partial<MsTeamsConfigInput>
): MsTeamsConfigInput => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
  };
};

export const buildOpsgenieConfig = (overrides?: Partial<OpsgenieConfig>): OpsgenieConfig => {
  return {
    apiKey: faker.random.word(),
    ...overrides,
    __typename: 'OpsgenieConfig',
  };
};

export const buildOpsgenieConfigInput = (
  overrides?: Partial<OpsgenieConfigInput>
): OpsgenieConfigInput => {
  return {
    apiKey: faker.random.word(),
    ...overrides,
  };
};

export const buildOrganizationReportBySeverity = (
  overrides?: Partial<OrganizationReportBySeverity>
): OrganizationReportBySeverity => {
  return {
    info: buildComplianceStatusCounts(),
    low: buildComplianceStatusCounts(),
    medium: buildComplianceStatusCounts(),
    high: buildComplianceStatusCounts(),
    critical: buildComplianceStatusCounts(),
    ...overrides,
    __typename: 'OrganizationReportBySeverity',
  };
};

export const buildOrganizationStatsInput = (
  overrides?: Partial<OrganizationStatsInput>
): OrganizationStatsInput => {
  return {
    limitTopFailing: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildOrganizationStatsResponse = (
  overrides?: Partial<OrganizationStatsResponse>
): OrganizationStatsResponse => {
  return {
    appliedPolicies: buildOrganizationReportBySeverity(),
    scannedResources: buildScannedResources(),
    topFailingPolicies: generateRandomArray(() => buildPolicySummary()),
    topFailingResources: generateRandomArray(() => buildResourceSummary()),
    ...overrides,
    __typename: 'OrganizationStatsResponse',
  };
};

export const buildPagerDutyConfig = (overrides?: Partial<PagerDutyConfig>): PagerDutyConfig => {
  return {
    integrationKey: faker.random.word(),
    ...overrides,
    __typename: 'PagerDutyConfig',
  };
};

export const buildPagerDutyConfigInput = (
  overrides?: Partial<PagerDutyConfigInput>
): PagerDutyConfigInput => {
  return {
    integrationKey: faker.random.word(),
    ...overrides,
  };
};

export const buildPagingData = (overrides?: Partial<PagingData>): PagingData => {
  return {
    thisPage: faker.random.number({ min: 0, max: 1000 }),
    totalPages: faker.random.number({ min: 0, max: 1000 }),
    totalItems: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
    __typename: 'PagingData',
  };
};

export const buildPoliciesForResourceInput = (
  overrides?: Partial<PoliciesForResourceInput>
): PoliciesForResourceInput => {
  return {
    resourceId: faker.random.uuid(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    status: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    suppressed: faker.random.boolean(),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildPolicyDetails = (overrides?: Partial<PolicyDetails>): PolicyDetails => {
  return {
    autoRemediationId: faker.random.uuid(),
    autoRemediationParameters: JSON.stringify(faker.random.objectElement()),
    body: faker.random.word(),
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    createdAt: faker.date.past().toISOString(),
    createdBy: faker.random.uuid(),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    lastModified: faker.date.past().toISOString(),
    lastModifiedBy: faker.random.uuid(),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    resourceTypes: generateRandomArray(() => faker.random.word()),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    suppressions: generateRandomArray(() => faker.random.word()),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTest()),
    versionId: faker.random.uuid(),
    ...overrides,
    __typename: 'PolicyDetails',
  };
};

export const buildPolicySummary = (overrides?: Partial<PolicySummary>): PolicySummary => {
  return {
    autoRemediationId: faker.random.uuid(),
    autoRemediationParameters: JSON.stringify(faker.random.objectElement()),
    suppressions: generateRandomArray(() => faker.random.word()),
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    lastModified: faker.date.past().toISOString(),
    resourceTypes: generateRandomArray(() => faker.random.word()),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: generateRandomArray(() => faker.random.word()),
    ...overrides,
    __typename: 'PolicySummary',
  };
};

export const buildPolicyUnitTest = (overrides?: Partial<PolicyUnitTest>): PolicyUnitTest => {
  return {
    expectedResult: faker.random.boolean(),
    name: faker.random.word(),
    resource: faker.random.word(),
    ...overrides,
    __typename: 'PolicyUnitTest',
  };
};

export const buildPolicyUnitTestError = (
  overrides?: Partial<PolicyUnitTestError>
): PolicyUnitTestError => {
  return {
    name: faker.random.word(),
    errorMessage: faker.random.word(),
    ...overrides,
    __typename: 'PolicyUnitTestError',
  };
};

export const buildPolicyUnitTestInput = (
  overrides?: Partial<PolicyUnitTestInput>
): PolicyUnitTestInput => {
  return {
    expectedResult: faker.random.boolean(),
    name: faker.random.word(),
    resource: faker.random.word(),
    ...overrides,
  };
};

export const buildRemediateResourceInput = (
  overrides?: Partial<RemediateResourceInput>
): RemediateResourceInput => {
  return {
    policyId: faker.random.uuid(),
    resourceId: faker.random.uuid(),
    ...overrides,
  };
};

export const buildResourceDetails = (overrides?: Partial<ResourceDetails>): ResourceDetails => {
  return {
    attributes: JSON.stringify(faker.random.objectElement()),
    deleted: faker.random.boolean(),
    expiresAt: faker.random.number({ min: 0, max: 1000 }),
    id: faker.random.uuid(),
    integrationId: faker.random.uuid(),
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    lastModified: faker.date.past().toISOString(),
    type: faker.random.word(),
    ...overrides,
    __typename: 'ResourceDetails',
  };
};

export const buildResourcesForPolicyInput = (
  overrides?: Partial<ResourcesForPolicyInput>
): ResourcesForPolicyInput => {
  return {
    policyId: faker.random.uuid(),
    status: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    suppressed: faker.random.boolean(),
    pageSize: faker.random.number({ min: 0, max: 1000 }),
    page: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
  };
};

export const buildResourceSummary = (overrides?: Partial<ResourceSummary>): ResourceSummary => {
  return {
    id: faker.random.uuid(),
    integrationId: faker.random.uuid(),
    complianceStatus: faker.random.arrayElement([
      ComplianceStatusEnum.Error,
      ComplianceStatusEnum.Fail,
      ComplianceStatusEnum.Pass,
    ]),
    deleted: faker.random.boolean(),
    lastModified: faker.date.past().toISOString(),
    type: faker.random.word(),
    ...overrides,
    __typename: 'ResourceSummary',
  };
};

export const buildRuleDetails = (overrides?: Partial<RuleDetails>): RuleDetails => {
  return {
    body: faker.random.word(),
    createdAt: faker.date.past().toISOString(),
    createdBy: faker.random.uuid(),
    dedupPeriodMinutes: faker.random.number({ min: 0, max: 1000 }),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.word(),
    lastModified: faker.date.past().toISOString(),
    lastModifiedBy: faker.random.uuid(),
    logTypes: generateRandomArray(() => faker.random.word()),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTest()),
    versionId: faker.random.uuid(),
    ...overrides,
    __typename: 'RuleDetails',
  };
};

export const buildRuleSummary = (overrides?: Partial<RuleSummary>): RuleSummary => {
  return {
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    lastModified: faker.date.past().toISOString(),
    logTypes: generateRandomArray(() => faker.random.word()),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: generateRandomArray(() => faker.random.word()),
    ...overrides,
    __typename: 'RuleSummary',
  };
};

export const buildS3LogIntegration = (overrides?: Partial<S3LogIntegration>): S3LogIntegration => {
  return {
    awsAccountId: faker.random.word(),
    createdAtTime: faker.date.past().toISOString(),
    createdBy: faker.random.uuid(),
    integrationId: faker.random.uuid(),
    integrationType: faker.random.word(),
    integrationLabel: faker.random.word(),
    lastEventReceived: faker.date.past().toISOString(),
    s3Bucket: faker.random.word(),
    s3Prefix: faker.random.word(),
    kmsKey: faker.random.word(),
    logTypes: generateRandomArray(() => faker.random.word()),
    health: buildS3LogIntegrationHealth(),
    stackName: faker.random.word(),
    ...overrides,
    __typename: 'S3LogIntegration',
  };
};

export const buildS3LogIntegrationHealth = (
  overrides?: Partial<S3LogIntegrationHealth>
): S3LogIntegrationHealth => {
  return {
    processingRoleStatus: buildIntegrationItemHealthStatus(),
    s3BucketStatus: buildIntegrationItemHealthStatus(),
    kmsKeyStatus: buildIntegrationItemHealthStatus(),
    ...overrides,
    __typename: 'S3LogIntegrationHealth',
  };
};

export const buildScannedResources = (overrides?: Partial<ScannedResources>): ScannedResources => {
  return {
    byType: generateRandomArray(() => buildScannedResourceStats()),
    ...overrides,
    __typename: 'ScannedResources',
  };
};

export const buildScannedResourceStats = (
  overrides?: Partial<ScannedResourceStats>
): ScannedResourceStats => {
  return {
    count: buildComplianceStatusCounts(),
    type: faker.random.word(),
    ...overrides,
    __typename: 'ScannedResourceStats',
  };
};

export const buildSlackConfig = (overrides?: Partial<SlackConfig>): SlackConfig => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
    __typename: 'SlackConfig',
  };
};

export const buildSlackConfigInput = (overrides?: Partial<SlackConfigInput>): SlackConfigInput => {
  return {
    webhookURL: faker.random.word(),
    ...overrides,
  };
};

export const buildSnsConfig = (overrides?: Partial<SnsConfig>): SnsConfig => {
  return {
    topicArn: faker.random.word(),
    ...overrides,
    __typename: 'SnsConfig',
  };
};

export const buildSnsConfigInput = (overrides?: Partial<SnsConfigInput>): SnsConfigInput => {
  return {
    topicArn: faker.random.word(),
    ...overrides,
  };
};

export const buildSqsConfig = (overrides?: Partial<SqsConfig>): SqsConfig => {
  return {
    queueUrl: faker.random.word(),
    ...overrides,
    __typename: 'SqsConfig',
  };
};

export const buildSqsConfigInput = (overrides?: Partial<SqsConfigInput>): SqsConfigInput => {
  return {
    queueUrl: faker.random.word(),
    ...overrides,
  };
};

export const buildSuppressPoliciesInput = (
  overrides?: Partial<SuppressPoliciesInput>
): SuppressPoliciesInput => {
  return {
    policyIds: generateRandomArray(() => faker.random.uuid()),
    resourcePatterns: generateRandomArray(() => faker.random.word()),
    ...overrides,
  };
};

export const buildTestPolicyInput = (overrides?: Partial<TestPolicyInput>): TestPolicyInput => {
  return {
    body: faker.random.word(),
    resourceTypes: generateRandomArray(() => faker.random.word()),
    analysisType: faker.random.arrayElement([AnalysisTypeEnum.Rule, AnalysisTypeEnum.Policy]),
    tests: generateRandomArray(() => buildPolicyUnitTestInput()),
    ...overrides,
  };
};

export const buildTestPolicyResponse = (
  overrides?: Partial<TestPolicyResponse>
): TestPolicyResponse => {
  return {
    testSummary: faker.random.boolean(),
    testsPassed: generateRandomArray(() => faker.random.word()),
    testsFailed: generateRandomArray(() => faker.random.word()),
    testsErrored: generateRandomArray(() => buildPolicyUnitTestError()),
    ...overrides,
    __typename: 'TestPolicyResponse',
  };
};

export const buildUpdateComplianceIntegrationInput = (
  overrides?: Partial<UpdateComplianceIntegrationInput>
): UpdateComplianceIntegrationInput => {
  return {
    integrationId: faker.random.word(),
    integrationLabel: faker.random.word(),
    cweEnabled: faker.random.boolean(),
    remediationEnabled: faker.random.boolean(),
    ...overrides,
  };
};

export const buildUpdateGeneralSettingsInput = (
  overrides?: Partial<UpdateGeneralSettingsInput>
): UpdateGeneralSettingsInput => {
  return {
    displayName: faker.random.word(),
    email: faker.random.word(),
    errorReportingConsent: faker.random.boolean(),
    ...overrides,
  };
};

export const buildUpdatePolicyInput = (
  overrides?: Partial<UpdatePolicyInput>
): UpdatePolicyInput => {
  return {
    autoRemediationId: faker.random.uuid(),
    autoRemediationParameters: JSON.stringify(faker.random.objectElement()),
    body: faker.random.word(),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    resourceTypes: generateRandomArray(() => faker.random.word()),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    suppressions: generateRandomArray(() => faker.random.word()),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTestInput()),
    ...overrides,
  };
};

export const buildUpdateRuleInput = (overrides?: Partial<UpdateRuleInput>): UpdateRuleInput => {
  return {
    body: faker.random.word(),
    dedupPeriodMinutes: faker.random.number({ min: 0, max: 1000 }),
    description: faker.random.word(),
    displayName: faker.random.word(),
    enabled: faker.random.boolean(),
    id: faker.random.uuid(),
    logTypes: generateRandomArray(() => faker.random.word()),
    outputIds: generateRandomArray(() => faker.random.uuid()),
    reference: faker.random.word(),
    runbook: faker.random.word(),
    severity: faker.random.arrayElement([
      SeverityEnum.Info,
      SeverityEnum.Low,
      SeverityEnum.Medium,
      SeverityEnum.High,
      SeverityEnum.Critical,
    ]),
    tags: generateRandomArray(() => faker.random.word()),
    tests: generateRandomArray(() => buildPolicyUnitTestInput()),
    ...overrides,
  };
};

export const buildUpdateS3LogIntegrationInput = (
  overrides?: Partial<UpdateS3LogIntegrationInput>
): UpdateS3LogIntegrationInput => {
  return {
    integrationId: faker.random.word(),
    integrationLabel: faker.random.word(),
    s3Bucket: faker.random.word(),
    kmsKey: faker.random.word(),
    s3Prefix: faker.random.word(),
    logTypes: generateRandomArray(() => faker.random.word()),
    ...overrides,
  };
};

export const buildUpdateUserInput = (overrides?: Partial<UpdateUserInput>): UpdateUserInput => {
  return {
    id: faker.random.uuid(),
    givenName: faker.random.word(),
    familyName: faker.random.word(),
    email: faker.internet.email(),
    ...overrides,
  };
};

export const buildUploadPoliciesInput = (
  overrides?: Partial<UploadPoliciesInput>
): UploadPoliciesInput => {
  return {
    data: faker.random.word(),
    ...overrides,
  };
};

export const buildUploadPoliciesResponse = (
  overrides?: Partial<UploadPoliciesResponse>
): UploadPoliciesResponse => {
  return {
    totalPolicies: faker.random.number({ min: 0, max: 1000 }),
    newPolicies: faker.random.number({ min: 0, max: 1000 }),
    modifiedPolicies: faker.random.number({ min: 0, max: 1000 }),
    totalRules: faker.random.number({ min: 0, max: 1000 }),
    newRules: faker.random.number({ min: 0, max: 1000 }),
    modifiedRules: faker.random.number({ min: 0, max: 1000 }),
    ...overrides,
    __typename: 'UploadPoliciesResponse',
  };
};

export const buildUser = (overrides?: Partial<User>): User => {
  return {
    givenName: faker.random.word(),
    familyName: faker.random.word(),
    id: faker.random.uuid(),
    email: faker.internet.email(),
    createdAt: faker.date.past().getTime(),
    status: faker.random.word(),
    ...overrides,
    __typename: 'User',
  };
};
