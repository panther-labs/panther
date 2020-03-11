export type Maybe<T> = T | null;
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: string;
  String: string;
  Boolean: boolean;
  Int: number;
  Float: number;
  AWSDateTime: string;
  AWSJSON: string;
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

export type AddIntegrationAttributes = {
  awsAccountId?: Maybe<Scalars['String']>;
  integrationLabel: Scalars['String'];
  integrationType: Scalars['String'];
  s3Buckets?: Maybe<Array<Maybe<Scalars['String']>>>;
  kmsKeys?: Maybe<Array<Maybe<Scalars['String']>>>;
};

export type AddIntegrationInput = {
  integrations?: Maybe<Array<Maybe<AddIntegrationAttributes>>>;
};

export type AlertDetails = {
  __typename?: 'AlertDetails';
  alertId: Scalars['ID'];
  ruleId?: Maybe<Scalars['ID']>;
  creationTime: Scalars['AWSDateTime'];
  updateTime: Scalars['AWSDateTime'];
  eventsMatched: Scalars['Int'];
  events: Array<Scalars['AWSJSON']>;
  eventsLastEvaluatedKey?: Maybe<Scalars['String']>;
  dedupString?: Maybe<Scalars['String']>;
};

export type AlertSummary = {
  __typename?: 'AlertSummary';
  alertId: Scalars['String'];
  creationTime: Scalars['AWSDateTime'];
  eventsMatched: Scalars['Int'];
  updateTime: Scalars['AWSDateTime'];
  ruleId?: Maybe<Scalars['String']>;
  severity?: Maybe<Scalars['String']>;
  dedupString?: Maybe<Scalars['String']>;
};

export enum AnalysisTypeEnum {
  Rule = 'RULE',
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

export type CreateOrModifyPolicyInput = {
  actionDelaySeconds?: Maybe<Scalars['Int']>;
  alertSuppressSeconds?: Maybe<Scalars['Int']>;
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  body: Scalars['String'];
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  suppressions?: Maybe<Array<Maybe<Scalars['String']>>>;
  id: Scalars['ID'];
  reference?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<PolicyUnitTestInput>>>;
};

export type CreateOrModifyRuleInput = {
  body: Scalars['String'];
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled: Scalars['Boolean'];
  id: Scalars['ID'];
  reference?: Maybe<Scalars['String']>;
  logTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  runbook?: Maybe<Scalars['String']>;
  severity: SeverityEnum;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<PolicyUnitTestInput>>>;
};

export type DeletePolicyInput = {
  policies?: Maybe<Array<Maybe<DeletePolicyInputItem>>>;
};

export type DeletePolicyInputItem = {
  id: Scalars['ID'];
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
};

export type DestinationConfig = {
  __typename?: 'DestinationConfig';
  slack?: Maybe<SlackConfig>;
  sns?: Maybe<SnsConfig>;
  sqs?: Maybe<SqsConfig>;
  pagerDuty?: Maybe<PagerDutyConfig>;
  github?: Maybe<GithubConfig>;
  jira?: Maybe<JiraConfig>;
  opsgenie?: Maybe<OpsgenieConfig>;
  msTeams?: Maybe<MsTeamsConfig>;
  asana?: Maybe<AsanaConfig>;
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
};

export type DestinationInput = {
  outputId?: Maybe<Scalars['ID']>;
  displayName: Scalars['String'];
  outputConfig: DestinationConfigInput;
  outputType: Scalars['String'];
  defaultForSeverity: Array<Maybe<SeverityEnum>>;
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
}

export type GeneralSettings = {
  __typename?: 'GeneralSettings';
  displayName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['String']>;
  errorReportingConsent?: Maybe<Scalars['Boolean']>;
};

export type GetAlertInput = {
  alertId: Scalars['ID'];
  eventsPageSize?: Maybe<Scalars['Int']>;
  eventsExclusiveStartKey?: Maybe<Scalars['String']>;
};

export type GetPolicyInput = {
  policyId: Scalars['ID'];
  versionId?: Maybe<Scalars['ID']>;
};

export type GetResourceInput = {
  resourceId: Scalars['ID'];
};

export type GetRuleInput = {
  ruleId: Scalars['ID'];
  versionId?: Maybe<Scalars['ID']>;
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

export type Integration = {
  __typename?: 'Integration';
  awsAccountId?: Maybe<Scalars['String']>;
  createdAtTime?: Maybe<Scalars['AWSDateTime']>;
  createdBy?: Maybe<Scalars['ID']>;
  integrationId?: Maybe<Scalars['ID']>;
  integrationLabel?: Maybe<Scalars['String']>;
  integrationType?: Maybe<Scalars['String']>;
  scanEnabled?: Maybe<Scalars['Boolean']>;
  scanIntervalMins?: Maybe<Scalars['Int']>;
  scanStatus?: Maybe<Scalars['String']>;
  eventStatus?: Maybe<Scalars['String']>;
  s3Buckets?: Maybe<Array<Maybe<Scalars['String']>>>;
  kmsKeys?: Maybe<Array<Maybe<Scalars['String']>>>;
  lastScanEndTime?: Maybe<Scalars['AWSDateTime']>;
  lastScanErrorMessage?: Maybe<Scalars['String']>;
  lastScanStartTime?: Maybe<Scalars['AWSDateTime']>;
};

export type IntegrationConfig = {
  __typename?: 'IntegrationConfig';
  awsRoleArn?: Maybe<Scalars['String']>;
};

export type IntegrationConfigInput = {
  awsRoleArn?: Maybe<Scalars['String']>;
};

export type InviteUserInput = {
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['AWSEmail']>;
};

export type InviteUserResponse = {
  __typename?: 'InviteUserResponse';
  id: Scalars['ID'];
};

export type JiraConfig = {
  __typename?: 'JiraConfig';
  orgDomain: Scalars['String'];
  projectKey: Scalars['String'];
  userName: Scalars['String'];
  apiKey: Scalars['String'];
  assigneeId?: Maybe<Scalars['String']>;
  issueType?: Maybe<JiraIssueTypesEnum>;
};

export type JiraConfigInput = {
  orgDomain: Scalars['String'];
  projectKey: Scalars['String'];
  userName: Scalars['String'];
  apiKey: Scalars['String'];
  assigneeId?: Maybe<Scalars['String']>;
  issueType?: Maybe<JiraIssueTypesEnum>;
};

export enum JiraIssueTypesEnum {
  Bug = 'Bug',
  Story = 'Story',
  Task = 'Task',
}

export type ListAlertsInput = {
  ruleId?: Maybe<Scalars['ID']>;
  pageSize?: Maybe<Scalars['Int']>;
  exclusiveStartKey?: Maybe<Scalars['String']>;
};

export type ListAlertsResponse = {
  __typename?: 'ListAlertsResponse';
  alertSummaries: Array<Maybe<AlertSummary>>;
  lastEvaluatedKey?: Maybe<Scalars['String']>;
};

export type ListComplianceItemsResponse = {
  __typename?: 'ListComplianceItemsResponse';
  items?: Maybe<Array<Maybe<ComplianceItem>>>;
  paging?: Maybe<PagingData>;
  status?: Maybe<ComplianceStatusEnum>;
  totals?: Maybe<ActiveSuppressCount>;
};

export type ListIntegrationsInput = {
  integrationType: Scalars['String'];
};

export type ListPoliciesInput = {
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  nameContains?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  hasRemediation?: Maybe<Scalars['Boolean']>;
  resourceTypes?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Scalars['String']>;
  /** Sorting */
  sortBy?: Maybe<ListPoliciesSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  /** Paging */
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListPoliciesResponse = {
  __typename?: 'ListPoliciesResponse';
  paging?: Maybe<PagingData>;
  policies?: Maybe<Array<Maybe<PolicySummary>>>;
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
  integrationType?: Maybe<AccountTypeEnum>;
  types?: Maybe<Scalars['String']>;
  /** Sorting */
  sortBy?: Maybe<ListResourcesSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  /** Paging */
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

export type ListRulesInput = {
  nameContains?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  logTypes?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Scalars['String']>;
  /** Sorting */
  sortBy?: Maybe<ListRulesSortFieldsEnum>;
  sortDir?: Maybe<SortDirEnum>;
  /** Paging */
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ListRulesResponse = {
  __typename?: 'ListRulesResponse';
  paging?: Maybe<PagingData>;
  rules?: Maybe<Array<Maybe<RuleSummary>>>;
};

export enum ListRulesSortFieldsEnum {
  Enabled = 'enabled',
  Id = 'id',
  LastModified = 'lastModified',
  LogTypes = 'logTypes',
  Severity = 'severity',
}

export type ListUsersResponse = {
  __typename?: 'ListUsersResponse';
  users?: Maybe<Array<Maybe<User>>>;
  paginationToken?: Maybe<Scalars['String']>;
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
  addDestination?: Maybe<Destination>;
  addIntegration?: Maybe<Integration>;
  addPolicy?: Maybe<PolicyDetails>;
  addRule?: Maybe<RuleDetails>;
  deleteDestination?: Maybe<Scalars['Boolean']>;
  deleteIntegration?: Maybe<Scalars['Boolean']>;
  deletePolicy?: Maybe<Scalars['Boolean']>;
  deleteUser?: Maybe<Scalars['Boolean']>;
  inviteUser?: Maybe<InviteUserResponse>;
  remediateResource?: Maybe<Scalars['Boolean']>;
  resetUserPassword?: Maybe<Scalars['Boolean']>;
  suppressPolicies?: Maybe<Scalars['Boolean']>;
  testPolicy?: Maybe<TestPolicyResponse>;
  updateDestination?: Maybe<Destination>;
  updateIntegration?: Maybe<Scalars['Boolean']>;
  updateGeneralSettings: GeneralSettings;
  updatePolicy?: Maybe<PolicyDetails>;
  updateRule?: Maybe<RuleDetails>;
  updateUser?: Maybe<Scalars['Boolean']>;
  uploadPolicies?: Maybe<UploadPoliciesResponse>;
};

export type MutationAddDestinationArgs = {
  input: DestinationInput;
};

export type MutationAddIntegrationArgs = {
  input: AddIntegrationInput;
};

export type MutationAddPolicyArgs = {
  input: CreateOrModifyPolicyInput;
};

export type MutationAddRuleArgs = {
  input: CreateOrModifyRuleInput;
};

export type MutationDeleteDestinationArgs = {
  id: Scalars['ID'];
};

export type MutationDeleteIntegrationArgs = {
  id: Scalars['ID'];
};

export type MutationDeletePolicyArgs = {
  input: DeletePolicyInput;
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

export type MutationResetUserPasswordArgs = {
  id: Scalars['ID'];
};

export type MutationSuppressPoliciesArgs = {
  input: SuppressPoliciesInput;
};

export type MutationTestPolicyArgs = {
  input?: Maybe<TestPolicyInput>;
};

export type MutationUpdateDestinationArgs = {
  input: DestinationInput;
};

export type MutationUpdateIntegrationArgs = {
  input: UpdateIntegrationInput;
};

export type MutationUpdateGeneralSettingsArgs = {
  input: UpdateGeneralSettingsInput;
};

export type MutationUpdatePolicyArgs = {
  input: CreateOrModifyPolicyInput;
};

export type MutationUpdateRuleArgs = {
  input: CreateOrModifyRuleInput;
};

export type MutationUpdateUserArgs = {
  input: UpdateUserInput;
};

export type MutationUploadPoliciesArgs = {
  input: UploadPoliciesInput;
};

export type OpsgenieConfig = {
  __typename?: 'OpsgenieConfig';
  apiKey: Scalars['String'];
};

export type OpsgenieConfigInput = {
  apiKey: Scalars['String'];
};

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
  topFailingPolicies?: Maybe<Array<Maybe<PolicySummary>>>;
  topFailingResources?: Maybe<Array<Maybe<ResourceSummary>>>;
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
  /** Paging */
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type PolicyDetails = {
  __typename?: 'PolicyDetails';
  actionDelaySeconds?: Maybe<Scalars['Int']>;
  alertSuppressSeconds?: Maybe<Scalars['Int']>;
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  body?: Maybe<Scalars['String']>;
  createdAt?: Maybe<Scalars['AWSDateTime']>;
  createdBy?: Maybe<Scalars['ID']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  suppressions?: Maybe<Array<Maybe<Scalars['String']>>>;
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  lastModifiedBy?: Maybe<Scalars['ID']>;
  reference?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  runbook?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<PolicyUnitTest>>>;
  versionId?: Maybe<Scalars['ID']>;
};

export type PolicySummary = {
  __typename?: 'PolicySummary';
  autoRemediationId?: Maybe<Scalars['ID']>;
  autoRemediationParameters?: Maybe<Scalars['AWSJSON']>;
  suppressions?: Maybe<Array<Maybe<Scalars['String']>>>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
};

export type PolicyUnitTest = {
  __typename?: 'PolicyUnitTest';
  expectedResult?: Maybe<Scalars['Boolean']>;
  name?: Maybe<Scalars['String']>;
  resource?: Maybe<Scalars['String']>;
  resourceType?: Maybe<Scalars['String']>;
};

export type PolicyUnitTestError = {
  __typename?: 'PolicyUnitTestError';
  name?: Maybe<Scalars['String']>;
  errorMessage?: Maybe<Scalars['String']>;
};

export type PolicyUnitTestInput = {
  expectedResult?: Maybe<Scalars['Boolean']>;
  name?: Maybe<Scalars['String']>;
  resource?: Maybe<Scalars['String']>;
  resourceType?: Maybe<Scalars['String']>;
};

export type Query = {
  __typename?: 'Query';
  alert?: Maybe<AlertDetails>;
  alerts?: Maybe<ListAlertsResponse>;
  destination?: Maybe<Destination>;
  destinations?: Maybe<Array<Maybe<Destination>>>;
  generalSettings: GeneralSettings;
  remediations?: Maybe<Scalars['AWSJSON']>;
  resource?: Maybe<ResourceDetails>;
  resources?: Maybe<ListResourcesResponse>;
  resourcesForPolicy?: Maybe<ListComplianceItemsResponse>;
  policy?: Maybe<PolicyDetails>;
  policies?: Maybe<ListPoliciesResponse>;
  policiesForResource?: Maybe<ListComplianceItemsResponse>;
  integrations?: Maybe<Array<Integration>>;
  organizationStats?: Maybe<OrganizationStatsResponse>;
  rule?: Maybe<RuleDetails>;
  rules?: Maybe<ListRulesResponse>;
  users?: Maybe<ListUsersResponse>;
};

export type QueryAlertArgs = {
  input: GetAlertInput;
};

export type QueryAlertsArgs = {
  input?: Maybe<ListAlertsInput>;
};

export type QueryDestinationArgs = {
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

export type QueryPolicyArgs = {
  input: GetPolicyInput;
};

export type QueryPoliciesArgs = {
  input?: Maybe<ListPoliciesInput>;
};

export type QueryPoliciesForResourceArgs = {
  input?: Maybe<PoliciesForResourceInput>;
};

export type QueryIntegrationsArgs = {
  input?: Maybe<ListIntegrationsInput>;
};

export type QueryOrganizationStatsArgs = {
  input?: Maybe<OrganizationStatsInput>;
};

export type QueryRuleArgs = {
  input: GetRuleInput;
};

export type QueryRulesArgs = {
  input?: Maybe<ListRulesInput>;
};

export type QueryUsersArgs = {
  limit?: Maybe<Scalars['Int']>;
  paginationToken?: Maybe<Scalars['String']>;
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
  integrationType?: Maybe<AccountTypeEnum>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  type?: Maybe<Scalars['String']>;
};

export type ResourcesForPolicyInput = {
  policyId?: Maybe<Scalars['ID']>;
  status?: Maybe<ComplianceStatusEnum>;
  suppressed?: Maybe<Scalars['Boolean']>;
  /** Paging */
  pageSize?: Maybe<Scalars['Int']>;
  page?: Maybe<Scalars['Int']>;
};

export type ResourceSummary = {
  __typename?: 'ResourceSummary';
  id?: Maybe<Scalars['ID']>;
  integrationId?: Maybe<Scalars['ID']>;
  complianceStatus?: Maybe<ComplianceStatusEnum>;
  integrationType?: Maybe<AccountTypeEnum>;
  deleted?: Maybe<Scalars['Boolean']>;
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  type?: Maybe<Scalars['String']>;
};

export type RuleDetails = {
  __typename?: 'RuleDetails';
  body?: Maybe<Scalars['String']>;
  createdAt?: Maybe<Scalars['AWSDateTime']>;
  createdBy?: Maybe<Scalars['ID']>;
  description?: Maybe<Scalars['String']>;
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['String'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  lastModifiedBy?: Maybe<Scalars['ID']>;
  logTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  reference?: Maybe<Scalars['String']>;
  runbook?: Maybe<Scalars['String']>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
  tests?: Maybe<Array<Maybe<PolicyUnitTest>>>;
  versionId?: Maybe<Scalars['ID']>;
};

export type RuleSummary = {
  __typename?: 'RuleSummary';
  displayName?: Maybe<Scalars['String']>;
  enabled?: Maybe<Scalars['Boolean']>;
  id: Scalars['ID'];
  lastModified?: Maybe<Scalars['AWSDateTime']>;
  logTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  severity?: Maybe<SeverityEnum>;
  tags?: Maybe<Array<Maybe<Scalars['String']>>>;
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

export enum SeverityEnum {
  Info = 'INFO',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
}

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
  queueUrl: Scalars['String'];
};

export type SqsConfigInput = {
  queueUrl: Scalars['String'];
};

export type SuppressPoliciesInput = {
  policyIds: Array<Maybe<Scalars['ID']>>;
  resourcePatterns: Array<Maybe<Scalars['String']>>;
};

export type TestPolicyInput = {
  body?: Maybe<Scalars['String']>;
  resourceTypes?: Maybe<Array<Maybe<Scalars['String']>>>;
  analysisType?: Maybe<AnalysisTypeEnum>;
  tests?: Maybe<Array<PolicyUnitTestInput>>;
};

export type TestPolicyResponse = {
  __typename?: 'TestPolicyResponse';
  testSummary?: Maybe<Scalars['Boolean']>;
  testsPassed?: Maybe<Array<Maybe<Scalars['String']>>>;
  testsFailed?: Maybe<Array<Maybe<Scalars['String']>>>;
  testsErrored?: Maybe<Array<Maybe<PolicyUnitTestError>>>;
};

export type UpdateGeneralSettingsInput = {
  displayName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['String']>;
  errorReportingConsent?: Maybe<Scalars['Boolean']>;
};

export type UpdateIntegrationInput = {
  awsAccountId?: Maybe<Scalars['String']>;
  integrationId: Scalars['String'];
  integrationLabel: Scalars['String'];
};

export type UpdateUserInput = {
  id: Scalars['ID'];
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  email?: Maybe<Scalars['AWSEmail']>;
};

export type UploadPoliciesInput = {
  data: Scalars['String'];
};

export type UploadPoliciesResponse = {
  __typename?: 'UploadPoliciesResponse';
  totalPolicies?: Maybe<Scalars['Int']>;
  newPolicies?: Maybe<Scalars['Int']>;
  modifiedPolicies?: Maybe<Scalars['Int']>;
  totalRules?: Maybe<Scalars['Int']>;
  newRules?: Maybe<Scalars['Int']>;
  modifiedRules?: Maybe<Scalars['Int']>;
};

export type User = {
  __typename?: 'User';
  givenName?: Maybe<Scalars['String']>;
  familyName?: Maybe<Scalars['String']>;
  id: Scalars['ID'];
  email?: Maybe<Scalars['AWSEmail']>;
  createdAt?: Maybe<Scalars['AWSTimestamp']>;
  status?: Maybe<Scalars['String']>;
};
