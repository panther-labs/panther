import { GraphQLResolveInfo, GraphQLScalarType, GraphQLScalarTypeConfig } from 'graphql';
export type Maybe<T> = T | null;
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

export type ResolverTypeWrapper<T> = Promise<T> | T;

export type StitchingResolver<TResult, TParent, TContext, TArgs> = {
  fragment: string;
  resolve: ResolverFn<TResult, TParent, TContext, TArgs>;
};

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

export type isTypeOfResolverFn<T = {}> = (
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
  AlertDetails: ResolverTypeWrapper<AlertDetails>;
  AWSDateTime: ResolverTypeWrapper<Scalars['AWSDateTime']>;
  AWSJSON: ResolverTypeWrapper<Scalars['AWSJSON']>;
  ListAlertsInput: ListAlertsInput;
  ListAlertsResponse: ResolverTypeWrapper<ListAlertsResponse>;
  AlertSummary: ResolverTypeWrapper<AlertSummary>;
  Destination: ResolverTypeWrapper<Destination>;
  DestinationTypeEnum: DestinationTypeEnum;
  DestinationConfig: ResolverTypeWrapper<DestinationConfig>;
  SlackConfig: ResolverTypeWrapper<SlackConfig>;
  SnsConfig: ResolverTypeWrapper<SnsConfig>;
  SqsConfig: ResolverTypeWrapper<SqsConfig>;
  PagerDutyConfig: ResolverTypeWrapper<PagerDutyConfig>;
  GithubConfig: ResolverTypeWrapper<GithubConfig>;
  JiraConfig: ResolverTypeWrapper<JiraConfig>;
  JiraIssueTypesEnum: JiraIssueTypesEnum;
  OpsgenieConfig: ResolverTypeWrapper<OpsgenieConfig>;
  MsTeamsConfig: ResolverTypeWrapper<MsTeamsConfig>;
  AsanaConfig: ResolverTypeWrapper<AsanaConfig>;
  SeverityEnum: SeverityEnum;
  GeneralSettings: ResolverTypeWrapper<GeneralSettings>;
  Boolean: ResolverTypeWrapper<Scalars['Boolean']>;
  GetResourceInput: GetResourceInput;
  ResourceDetails: ResolverTypeWrapper<ResourceDetails>;
  AccountTypeEnum: AccountTypeEnum;
  ComplianceStatusEnum: ComplianceStatusEnum;
  ListResourcesInput: ListResourcesInput;
  ListResourcesSortFieldsEnum: ListResourcesSortFieldsEnum;
  SortDirEnum: SortDirEnum;
  ListResourcesResponse: ResolverTypeWrapper<ListResourcesResponse>;
  PagingData: ResolverTypeWrapper<PagingData>;
  ResourceSummary: ResolverTypeWrapper<ResourceSummary>;
  ResourcesForPolicyInput: ResourcesForPolicyInput;
  ListComplianceItemsResponse: ResolverTypeWrapper<ListComplianceItemsResponse>;
  ComplianceItem: ResolverTypeWrapper<ComplianceItem>;
  ActiveSuppressCount: ResolverTypeWrapper<ActiveSuppressCount>;
  ComplianceStatusCounts: ResolverTypeWrapper<ComplianceStatusCounts>;
  GetPolicyInput: GetPolicyInput;
  PolicyDetails: ResolverTypeWrapper<PolicyDetails>;
  PolicyUnitTest: ResolverTypeWrapper<PolicyUnitTest>;
  ListPoliciesInput: ListPoliciesInput;
  ListPoliciesSortFieldsEnum: ListPoliciesSortFieldsEnum;
  ListPoliciesResponse: ResolverTypeWrapper<ListPoliciesResponse>;
  PolicySummary: ResolverTypeWrapper<PolicySummary>;
  PoliciesForResourceInput: PoliciesForResourceInput;
  ListIntegrationsInput: ListIntegrationsInput;
  Integration: ResolverTypeWrapper<Integration>;
  OrganizationStatsInput: OrganizationStatsInput;
  OrganizationStatsResponse: ResolverTypeWrapper<OrganizationStatsResponse>;
  OrganizationReportBySeverity: ResolverTypeWrapper<OrganizationReportBySeverity>;
  ScannedResources: ResolverTypeWrapper<ScannedResources>;
  ScannedResourceStats: ResolverTypeWrapper<ScannedResourceStats>;
  GetRuleInput: GetRuleInput;
  RuleDetails: ResolverTypeWrapper<RuleDetails>;
  ListRulesInput: ListRulesInput;
  ListRulesSortFieldsEnum: ListRulesSortFieldsEnum;
  ListRulesResponse: ResolverTypeWrapper<ListRulesResponse>;
  RuleSummary: ResolverTypeWrapper<RuleSummary>;
  ListUsersResponse: ResolverTypeWrapper<ListUsersResponse>;
  User: ResolverTypeWrapper<User>;
  AWSEmail: ResolverTypeWrapper<Scalars['AWSEmail']>;
  AWSTimestamp: ResolverTypeWrapper<Scalars['AWSTimestamp']>;
  Mutation: ResolverTypeWrapper<{}>;
  DestinationInput: DestinationInput;
  DestinationConfigInput: DestinationConfigInput;
  SlackConfigInput: SlackConfigInput;
  SnsConfigInput: SnsConfigInput;
  SQSConfigInput: SqsConfigInput;
  PagerDutyConfigInput: PagerDutyConfigInput;
  GithubConfigInput: GithubConfigInput;
  JiraConfigInput: JiraConfigInput;
  OpsgenieConfigInput: OpsgenieConfigInput;
  MsTeamsConfigInput: MsTeamsConfigInput;
  AsanaConfigInput: AsanaConfigInput;
  AddIntegrationInput: AddIntegrationInput;
  AddIntegrationAttributes: AddIntegrationAttributes;
  CreateOrModifyPolicyInput: CreateOrModifyPolicyInput;
  PolicyUnitTestInput: PolicyUnitTestInput;
  CreateOrModifyRuleInput: CreateOrModifyRuleInput;
  DeletePolicyInput: DeletePolicyInput;
  DeletePolicyInputItem: DeletePolicyInputItem;
  InviteUserInput: InviteUserInput;
  InviteUserResponse: ResolverTypeWrapper<InviteUserResponse>;
  RemediateResourceInput: RemediateResourceInput;
  SuppressPoliciesInput: SuppressPoliciesInput;
  TestPolicyInput: TestPolicyInput;
  AnalysisTypeEnum: AnalysisTypeEnum;
  TestPolicyResponse: ResolverTypeWrapper<TestPolicyResponse>;
  PolicyUnitTestError: ResolverTypeWrapper<PolicyUnitTestError>;
  UpdateIntegrationInput: UpdateIntegrationInput;
  UpdateGeneralSettingsInput: UpdateGeneralSettingsInput;
  UpdateUserInput: UpdateUserInput;
  UploadPoliciesInput: UploadPoliciesInput;
  UploadPoliciesResponse: ResolverTypeWrapper<UploadPoliciesResponse>;
  IntegrationConfig: ResolverTypeWrapper<IntegrationConfig>;
  IntegrationConfigInput: IntegrationConfigInput;
};

/** Mapping between all available schema types and the resolvers parents */
export type ResolversParentTypes = {
  Query: {};
  GetAlertInput: GetAlertInput;
  ID: Scalars['ID'];
  Int: Scalars['Int'];
  String: Scalars['String'];
  AlertDetails: AlertDetails;
  AWSDateTime: Scalars['AWSDateTime'];
  AWSJSON: Scalars['AWSJSON'];
  ListAlertsInput: ListAlertsInput;
  ListAlertsResponse: ListAlertsResponse;
  AlertSummary: AlertSummary;
  Destination: Destination;
  DestinationTypeEnum: DestinationTypeEnum;
  DestinationConfig: DestinationConfig;
  SlackConfig: SlackConfig;
  SnsConfig: SnsConfig;
  SqsConfig: SqsConfig;
  PagerDutyConfig: PagerDutyConfig;
  GithubConfig: GithubConfig;
  JiraConfig: JiraConfig;
  JiraIssueTypesEnum: JiraIssueTypesEnum;
  OpsgenieConfig: OpsgenieConfig;
  MsTeamsConfig: MsTeamsConfig;
  AsanaConfig: AsanaConfig;
  SeverityEnum: SeverityEnum;
  GeneralSettings: GeneralSettings;
  Boolean: Scalars['Boolean'];
  GetResourceInput: GetResourceInput;
  ResourceDetails: ResourceDetails;
  AccountTypeEnum: AccountTypeEnum;
  ComplianceStatusEnum: ComplianceStatusEnum;
  ListResourcesInput: ListResourcesInput;
  ListResourcesSortFieldsEnum: ListResourcesSortFieldsEnum;
  SortDirEnum: SortDirEnum;
  ListResourcesResponse: ListResourcesResponse;
  PagingData: PagingData;
  ResourceSummary: ResourceSummary;
  ResourcesForPolicyInput: ResourcesForPolicyInput;
  ListComplianceItemsResponse: ListComplianceItemsResponse;
  ComplianceItem: ComplianceItem;
  ActiveSuppressCount: ActiveSuppressCount;
  ComplianceStatusCounts: ComplianceStatusCounts;
  GetPolicyInput: GetPolicyInput;
  PolicyDetails: PolicyDetails;
  PolicyUnitTest: PolicyUnitTest;
  ListPoliciesInput: ListPoliciesInput;
  ListPoliciesSortFieldsEnum: ListPoliciesSortFieldsEnum;
  ListPoliciesResponse: ListPoliciesResponse;
  PolicySummary: PolicySummary;
  PoliciesForResourceInput: PoliciesForResourceInput;
  ListIntegrationsInput: ListIntegrationsInput;
  Integration: Integration;
  OrganizationStatsInput: OrganizationStatsInput;
  OrganizationStatsResponse: OrganizationStatsResponse;
  OrganizationReportBySeverity: OrganizationReportBySeverity;
  ScannedResources: ScannedResources;
  ScannedResourceStats: ScannedResourceStats;
  GetRuleInput: GetRuleInput;
  RuleDetails: RuleDetails;
  ListRulesInput: ListRulesInput;
  ListRulesSortFieldsEnum: ListRulesSortFieldsEnum;
  ListRulesResponse: ListRulesResponse;
  RuleSummary: RuleSummary;
  ListUsersResponse: ListUsersResponse;
  User: User;
  AWSEmail: Scalars['AWSEmail'];
  AWSTimestamp: Scalars['AWSTimestamp'];
  Mutation: {};
  DestinationInput: DestinationInput;
  DestinationConfigInput: DestinationConfigInput;
  SlackConfigInput: SlackConfigInput;
  SnsConfigInput: SnsConfigInput;
  SQSConfigInput: SqsConfigInput;
  PagerDutyConfigInput: PagerDutyConfigInput;
  GithubConfigInput: GithubConfigInput;
  JiraConfigInput: JiraConfigInput;
  OpsgenieConfigInput: OpsgenieConfigInput;
  MsTeamsConfigInput: MsTeamsConfigInput;
  AsanaConfigInput: AsanaConfigInput;
  AddIntegrationInput: AddIntegrationInput;
  AddIntegrationAttributes: AddIntegrationAttributes;
  CreateOrModifyPolicyInput: CreateOrModifyPolicyInput;
  PolicyUnitTestInput: PolicyUnitTestInput;
  CreateOrModifyRuleInput: CreateOrModifyRuleInput;
  DeletePolicyInput: DeletePolicyInput;
  DeletePolicyInputItem: DeletePolicyInputItem;
  InviteUserInput: InviteUserInput;
  InviteUserResponse: InviteUserResponse;
  RemediateResourceInput: RemediateResourceInput;
  SuppressPoliciesInput: SuppressPoliciesInput;
  TestPolicyInput: TestPolicyInput;
  AnalysisTypeEnum: AnalysisTypeEnum;
  TestPolicyResponse: TestPolicyResponse;
  PolicyUnitTestError: PolicyUnitTestError;
  UpdateIntegrationInput: UpdateIntegrationInput;
  UpdateGeneralSettingsInput: UpdateGeneralSettingsInput;
  UpdateUserInput: UpdateUserInput;
  UploadPoliciesInput: UploadPoliciesInput;
  UploadPoliciesResponse: UploadPoliciesResponse;
  IntegrationConfig: IntegrationConfig;
  IntegrationConfigInput: IntegrationConfigInput;
};

export type ActiveSuppressCountResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ActiveSuppressCount'] = ResolversParentTypes['ActiveSuppressCount']
> = {
  active?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  suppressed?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type AlertDetailsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertDetails'] = ResolversParentTypes['AlertDetails']
> = {
  alertId?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  ruleId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  updateTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  eventsMatched?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  events?: Resolver<Array<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  eventsLastEvaluatedKey?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  dedupString?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type AlertSummaryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AlertSummary'] = ResolversParentTypes['AlertSummary']
> = {
  alertId?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  creationTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  eventsMatched?: Resolver<ResolversTypes['Int'], ParentType, ContextType>;
  updateTime?: Resolver<ResolversTypes['AWSDateTime'], ParentType, ContextType>;
  ruleId?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  dedupString?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type AsanaConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['AsanaConfig'] = ResolversParentTypes['AsanaConfig']
> = {
  personalAccessToken?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  projectGids?: Resolver<Array<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ComplianceStatusCountsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ComplianceStatusCounts'] = ResolversParentTypes['ComplianceStatusCounts']
> = {
  error?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  fail?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  pass?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type DestinationConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['DestinationConfig'] = ResolversParentTypes['DestinationConfig']
> = {
  slack?: Resolver<Maybe<ResolversTypes['SlackConfig']>, ParentType, ContextType>;
  sns?: Resolver<Maybe<ResolversTypes['SnsConfig']>, ParentType, ContextType>;
  sqs?: Resolver<Maybe<ResolversTypes['SqsConfig']>, ParentType, ContextType>;
  pagerDuty?: Resolver<Maybe<ResolversTypes['PagerDutyConfig']>, ParentType, ContextType>;
  github?: Resolver<Maybe<ResolversTypes['GithubConfig']>, ParentType, ContextType>;
  jira?: Resolver<Maybe<ResolversTypes['JiraConfig']>, ParentType, ContextType>;
  opsgenie?: Resolver<Maybe<ResolversTypes['OpsgenieConfig']>, ParentType, ContextType>;
  msTeams?: Resolver<Maybe<ResolversTypes['MsTeamsConfig']>, ParentType, ContextType>;
  asana?: Resolver<Maybe<ResolversTypes['AsanaConfig']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type GeneralSettingsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GeneralSettings'] = ResolversParentTypes['GeneralSettings']
> = {
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  email?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  errorReportingConsent?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type GithubConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['GithubConfig'] = ResolversParentTypes['GithubConfig']
> = {
  repoName?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  token?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type IntegrationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Integration'] = ResolversParentTypes['Integration']
> = {
  awsAccountId?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  createdAtTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  integrationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  integrationLabel?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  integrationType?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  scanEnabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  scanIntervalMins?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  scanStatus?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  eventStatus?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  s3Buckets?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  kmsKeys?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  lastScanEndTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastScanErrorMessage?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  lastScanStartTime?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type IntegrationConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['IntegrationConfig'] = ResolversParentTypes['IntegrationConfig']
> = {
  awsRoleArn?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type InviteUserResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['InviteUserResponse'] = ResolversParentTypes['InviteUserResponse']
> = {
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  issueType?: Resolver<Maybe<ResolversTypes['JiraIssueTypesEnum']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ListAlertsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListAlertsResponse'] = ResolversParentTypes['ListAlertsResponse']
> = {
  alertSummaries?: Resolver<Array<Maybe<ResolversTypes['AlertSummary']>>, ParentType, ContextType>;
  lastEvaluatedKey?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ListComplianceItemsResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListComplianceItemsResponse'] = ResolversParentTypes['ListComplianceItemsResponse']
> = {
  items?: Resolver<Maybe<Array<Maybe<ResolversTypes['ComplianceItem']>>>, ParentType, ContextType>;
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  status?: Resolver<Maybe<ResolversTypes['ComplianceStatusEnum']>, ParentType, ContextType>;
  totals?: Resolver<Maybe<ResolversTypes['ActiveSuppressCount']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ListPoliciesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListPoliciesResponse'] = ResolversParentTypes['ListPoliciesResponse']
> = {
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  policies?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['PolicySummary']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ListRulesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListRulesResponse'] = ResolversParentTypes['ListRulesResponse']
> = {
  paging?: Resolver<Maybe<ResolversTypes['PagingData']>, ParentType, ContextType>;
  rules?: Resolver<Maybe<Array<Maybe<ResolversTypes['RuleSummary']>>>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ListUsersResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ListUsersResponse'] = ResolversParentTypes['ListUsersResponse']
> = {
  users?: Resolver<Maybe<Array<Maybe<ResolversTypes['User']>>>, ParentType, ContextType>;
  paginationToken?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type MsTeamsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['MsTeamsConfig'] = ResolversParentTypes['MsTeamsConfig']
> = {
  webhookURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type MutationResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['Mutation'] = ResolversParentTypes['Mutation']
> = {
  addDestination?: Resolver<
    Maybe<ResolversTypes['Destination']>,
    ParentType,
    ContextType,
    RequireFields<MutationAddDestinationArgs, 'input'>
  >;
  addIntegration?: Resolver<
    Maybe<ResolversTypes['Integration']>,
    ParentType,
    ContextType,
    RequireFields<MutationAddIntegrationArgs, 'input'>
  >;
  addPolicy?: Resolver<
    Maybe<ResolversTypes['PolicyDetails']>,
    ParentType,
    ContextType,
    RequireFields<MutationAddPolicyArgs, 'input'>
  >;
  addRule?: Resolver<
    Maybe<ResolversTypes['RuleDetails']>,
    ParentType,
    ContextType,
    RequireFields<MutationAddRuleArgs, 'input'>
  >;
  deleteDestination?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteDestinationArgs, 'id'>
  >;
  deleteIntegration?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteIntegrationArgs, 'id'>
  >;
  deletePolicy?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeletePolicyArgs, 'input'>
  >;
  deleteUser?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationDeleteUserArgs, 'id'>
  >;
  inviteUser?: Resolver<
    Maybe<ResolversTypes['InviteUserResponse']>,
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
  resetUserPassword?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
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
    Maybe<ResolversTypes['TestPolicyResponse']>,
    ParentType,
    ContextType,
    RequireFields<MutationTestPolicyArgs, never>
  >;
  updateDestination?: Resolver<
    Maybe<ResolversTypes['Destination']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateDestinationArgs, 'input'>
  >;
  updateIntegration?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateIntegrationArgs, 'input'>
  >;
  updateGeneralSettings?: Resolver<
    ResolversTypes['GeneralSettings'],
    ParentType,
    ContextType,
    RequireFields<MutationUpdateGeneralSettingsArgs, 'input'>
  >;
  updatePolicy?: Resolver<
    Maybe<ResolversTypes['PolicyDetails']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdatePolicyArgs, 'input'>
  >;
  updateRule?: Resolver<
    Maybe<ResolversTypes['RuleDetails']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateRuleArgs, 'input'>
  >;
  updateUser?: Resolver<
    Maybe<ResolversTypes['Boolean']>,
    ParentType,
    ContextType,
    RequireFields<MutationUpdateUserArgs, 'input'>
  >;
  uploadPolicies?: Resolver<
    Maybe<ResolversTypes['UploadPoliciesResponse']>,
    ParentType,
    ContextType,
    RequireFields<MutationUploadPoliciesArgs, 'input'>
  >;
};

export type OpsgenieConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['OpsgenieConfig'] = ResolversParentTypes['OpsgenieConfig']
> = {
  apiKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  topFailingPolicies?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['PolicySummary']>>>,
    ParentType,
    ContextType
  >;
  topFailingResources?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['ResourceSummary']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PagerDutyConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PagerDutyConfig'] = ResolversParentTypes['PagerDutyConfig']
> = {
  integrationKey?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PagingDataResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PagingData'] = ResolversParentTypes['PagingData']
> = {
  thisPage?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  totalPages?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  totalItems?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PolicyDetailsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PolicyDetails'] = ResolversParentTypes['PolicyDetails']
> = {
  actionDelaySeconds?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  alertSuppressSeconds?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  autoRemediationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  autoRemediationParameters?: Resolver<Maybe<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  body?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  createdAt?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  suppressions?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastModifiedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  resourceTypes?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<Maybe<ResolversTypes['SeverityEnum']>, ParentType, ContextType>;
  tags?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  tests?: Resolver<Maybe<Array<Maybe<ResolversTypes['PolicyUnitTest']>>>, ParentType, ContextType>;
  versionId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PolicySummaryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PolicySummary'] = ResolversParentTypes['PolicySummary']
> = {
  autoRemediationId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  autoRemediationParameters?: Resolver<Maybe<ResolversTypes['AWSJSON']>, ParentType, ContextType>;
  suppressions?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  resourceTypes?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  severity?: Resolver<Maybe<ResolversTypes['SeverityEnum']>, ParentType, ContextType>;
  tags?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PolicyUnitTestResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PolicyUnitTest'] = ResolversParentTypes['PolicyUnitTest']
> = {
  expectedResult?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  name?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  resource?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  resourceType?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type PolicyUnitTestErrorResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['PolicyUnitTestError'] = ResolversParentTypes['PolicyUnitTestError']
> = {
  name?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  errorMessage?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  policy?: Resolver<
    Maybe<ResolversTypes['PolicyDetails']>,
    ParentType,
    ContextType,
    RequireFields<QueryPolicyArgs, 'input'>
  >;
  policies?: Resolver<
    Maybe<ResolversTypes['ListPoliciesResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryPoliciesArgs, never>
  >;
  policiesForResource?: Resolver<
    Maybe<ResolversTypes['ListComplianceItemsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryPoliciesForResourceArgs, never>
  >;
  integrations?: Resolver<
    Maybe<Array<ResolversTypes['Integration']>>,
    ParentType,
    ContextType,
    RequireFields<QueryIntegrationsArgs, never>
  >;
  organizationStats?: Resolver<
    Maybe<ResolversTypes['OrganizationStatsResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryOrganizationStatsArgs, never>
  >;
  rule?: Resolver<
    Maybe<ResolversTypes['RuleDetails']>,
    ParentType,
    ContextType,
    RequireFields<QueryRuleArgs, 'input'>
  >;
  rules?: Resolver<
    Maybe<ResolversTypes['ListRulesResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryRulesArgs, never>
  >;
  users?: Resolver<
    Maybe<ResolversTypes['ListUsersResponse']>,
    ParentType,
    ContextType,
    RequireFields<QueryUsersArgs, never>
  >;
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
  integrationType?: Resolver<Maybe<ResolversTypes['AccountTypeEnum']>, ParentType, ContextType>;
  complianceStatus?: Resolver<
    Maybe<ResolversTypes['ComplianceStatusEnum']>,
    ParentType,
    ContextType
  >;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  integrationType?: Resolver<Maybe<ResolversTypes['AccountTypeEnum']>, ParentType, ContextType>;
  deleted?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type RuleDetailsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['RuleDetails'] = ResolversParentTypes['RuleDetails']
> = {
  body?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  createdAt?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  createdBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  description?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  lastModifiedBy?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  logTypes?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  reference?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  runbook?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  severity?: Resolver<Maybe<ResolversTypes['SeverityEnum']>, ParentType, ContextType>;
  tags?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  tests?: Resolver<Maybe<Array<Maybe<ResolversTypes['PolicyUnitTest']>>>, ParentType, ContextType>;
  versionId?: Resolver<Maybe<ResolversTypes['ID']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type RuleSummaryResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['RuleSummary'] = ResolversParentTypes['RuleSummary']
> = {
  displayName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  enabled?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  lastModified?: Resolver<Maybe<ResolversTypes['AWSDateTime']>, ParentType, ContextType>;
  logTypes?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  severity?: Resolver<Maybe<ResolversTypes['SeverityEnum']>, ParentType, ContextType>;
  tags?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
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
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type ScannedResourceStatsResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['ScannedResourceStats'] = ResolversParentTypes['ScannedResourceStats']
> = {
  count?: Resolver<Maybe<ResolversTypes['ComplianceStatusCounts']>, ParentType, ContextType>;
  type?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type SlackConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SlackConfig'] = ResolversParentTypes['SlackConfig']
> = {
  webhookURL?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type SnsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SnsConfig'] = ResolversParentTypes['SnsConfig']
> = {
  topicArn?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type SqsConfigResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['SqsConfig'] = ResolversParentTypes['SqsConfig']
> = {
  queueUrl?: Resolver<ResolversTypes['String'], ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type TestPolicyResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['TestPolicyResponse'] = ResolversParentTypes['TestPolicyResponse']
> = {
  testSummary?: Resolver<Maybe<ResolversTypes['Boolean']>, ParentType, ContextType>;
  testsPassed?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  testsFailed?: Resolver<Maybe<Array<Maybe<ResolversTypes['String']>>>, ParentType, ContextType>;
  testsErrored?: Resolver<
    Maybe<Array<Maybe<ResolversTypes['PolicyUnitTestError']>>>,
    ParentType,
    ContextType
  >;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type UploadPoliciesResponseResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['UploadPoliciesResponse'] = ResolversParentTypes['UploadPoliciesResponse']
> = {
  totalPolicies?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  newPolicies?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  modifiedPolicies?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  totalRules?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  newRules?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  modifiedRules?: Resolver<Maybe<ResolversTypes['Int']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type UserResolvers<
  ContextType = any,
  ParentType extends ResolversParentTypes['User'] = ResolversParentTypes['User']
> = {
  givenName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  familyName?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  id?: Resolver<ResolversTypes['ID'], ParentType, ContextType>;
  email?: Resolver<Maybe<ResolversTypes['AWSEmail']>, ParentType, ContextType>;
  createdAt?: Resolver<Maybe<ResolversTypes['AWSTimestamp']>, ParentType, ContextType>;
  status?: Resolver<Maybe<ResolversTypes['String']>, ParentType, ContextType>;
  __isTypeOf?: isTypeOfResolverFn<ParentType>;
};

export type Resolvers<ContextType = any> = {
  ActiveSuppressCount?: ActiveSuppressCountResolvers<ContextType>;
  AlertDetails?: AlertDetailsResolvers<ContextType>;
  AlertSummary?: AlertSummaryResolvers<ContextType>;
  AsanaConfig?: AsanaConfigResolvers<ContextType>;
  AWSDateTime?: GraphQLScalarType;
  AWSEmail?: GraphQLScalarType;
  AWSJSON?: GraphQLScalarType;
  AWSTimestamp?: GraphQLScalarType;
  ComplianceItem?: ComplianceItemResolvers<ContextType>;
  ComplianceStatusCounts?: ComplianceStatusCountsResolvers<ContextType>;
  Destination?: DestinationResolvers<ContextType>;
  DestinationConfig?: DestinationConfigResolvers<ContextType>;
  GeneralSettings?: GeneralSettingsResolvers<ContextType>;
  GithubConfig?: GithubConfigResolvers<ContextType>;
  Integration?: IntegrationResolvers<ContextType>;
  IntegrationConfig?: IntegrationConfigResolvers<ContextType>;
  InviteUserResponse?: InviteUserResponseResolvers<ContextType>;
  JiraConfig?: JiraConfigResolvers<ContextType>;
  ListAlertsResponse?: ListAlertsResponseResolvers<ContextType>;
  ListComplianceItemsResponse?: ListComplianceItemsResponseResolvers<ContextType>;
  ListPoliciesResponse?: ListPoliciesResponseResolvers<ContextType>;
  ListResourcesResponse?: ListResourcesResponseResolvers<ContextType>;
  ListRulesResponse?: ListRulesResponseResolvers<ContextType>;
  ListUsersResponse?: ListUsersResponseResolvers<ContextType>;
  MsTeamsConfig?: MsTeamsConfigResolvers<ContextType>;
  Mutation?: MutationResolvers<ContextType>;
  OpsgenieConfig?: OpsgenieConfigResolvers<ContextType>;
  OrganizationReportBySeverity?: OrganizationReportBySeverityResolvers<ContextType>;
  OrganizationStatsResponse?: OrganizationStatsResponseResolvers<ContextType>;
  PagerDutyConfig?: PagerDutyConfigResolvers<ContextType>;
  PagingData?: PagingDataResolvers<ContextType>;
  PolicyDetails?: PolicyDetailsResolvers<ContextType>;
  PolicySummary?: PolicySummaryResolvers<ContextType>;
  PolicyUnitTest?: PolicyUnitTestResolvers<ContextType>;
  PolicyUnitTestError?: PolicyUnitTestErrorResolvers<ContextType>;
  Query?: QueryResolvers<ContextType>;
  ResourceDetails?: ResourceDetailsResolvers<ContextType>;
  ResourceSummary?: ResourceSummaryResolvers<ContextType>;
  RuleDetails?: RuleDetailsResolvers<ContextType>;
  RuleSummary?: RuleSummaryResolvers<ContextType>;
  ScannedResources?: ScannedResourcesResolvers<ContextType>;
  ScannedResourceStats?: ScannedResourceStatsResolvers<ContextType>;
  SlackConfig?: SlackConfigResolvers<ContextType>;
  SnsConfig?: SnsConfigResolvers<ContextType>;
  SqsConfig?: SqsConfigResolvers<ContextType>;
  TestPolicyResponse?: TestPolicyResponseResolvers<ContextType>;
  UploadPoliciesResponse?: UploadPoliciesResponseResolvers<ContextType>;
  User?: UserResolvers<ContextType>;
};

/**
 * @deprecated
 * Use "Resolvers" root object instead. If you wish to get "IResolvers", add "typesPrefix: I" to your config.
 */
export type IResolvers<ContextType = any> = Resolvers<ContextType>;
