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

/* eslint-disable @typescript-eslint/no-use-before-define,@typescript-eslint/no-unused-vars,no-prototype-builtins */
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

export const buildActiveSuppressCount = (
  overrides?: Partial<ActiveSuppressCount>
): ActiveSuppressCount => {
  return {
    __typename: 'ActiveSuppressCount',
    active:
      overrides && overrides.hasOwnProperty('active')
        ? overrides.active!
        : buildComplianceStatusCounts(),
    suppressed:
      overrides && overrides.hasOwnProperty('suppressed')
        ? overrides.suppressed!
        : buildComplianceStatusCounts(),
  };
};

export const buildAddComplianceIntegrationInput = (
  overrides?: Partial<AddComplianceIntegrationInput>
): AddComplianceIntegrationInput => {
  return {
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'quo',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'harum',
    remediationEnabled:
      overrides && overrides.hasOwnProperty('remediationEnabled')
        ? overrides.remediationEnabled!
        : true,
    cweEnabled: overrides && overrides.hasOwnProperty('cweEnabled') ? overrides.cweEnabled! : true,
  };
};

export const buildAddGlobalPythonModuleInput = (
  overrides?: Partial<AddGlobalPythonModuleInput>
): AddGlobalPythonModuleInput => {
  return {
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '7b0f1c64-f650-48e8-bbcf-27c23c6cf854',
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'ut',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'molestiae',
  };
};

export const buildAddPolicyInput = (overrides?: Partial<AddPolicyInput>): AddPolicyInput => {
  return {
    autoRemediationId:
      overrides && overrides.hasOwnProperty('autoRemediationId')
        ? overrides.autoRemediationId!
        : '3ddec795-5cf0-445d-8800-5d02470180f2',
    autoRemediationParameters:
      overrides && overrides.hasOwnProperty('autoRemediationParameters')
        ? overrides.autoRemediationParameters!
        : 'ea reprehenderit voluptatem amet ipsa incidunt reiciendis',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'ab',
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'omnis',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'nihil',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '6612f488-d028-4e4f-804f-17e707ce7bdd',
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['06ca6d99-8a12-404b-8ef5-8e522075db0d'],
    reference:
      overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'voluptatem',
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes')
        ? overrides.resourceTypes!
        : ['labore'],
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'rerum',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    suppressions:
      overrides && overrides.hasOwnProperty('suppressions') ? overrides.suppressions! : ['nobis'],
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['molestiae'],
    tests:
      overrides && overrides.hasOwnProperty('tests')
        ? overrides.tests!
        : [buildPolicyUnitTestInput()],
  };
};

export const buildAddRuleInput = (overrides?: Partial<AddRuleInput>): AddRuleInput => {
  return {
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'qui',
    dedupPeriodMinutes:
      overrides && overrides.hasOwnProperty('dedupPeriodMinutes')
        ? overrides.dedupPeriodMinutes!
        : 4288,
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'adipisci',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'laborum',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : 'e9463be1-5ef2-4950-a272-21540bb0cff3',
    logTypes:
      overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['suscipit'],
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['1f6aac24-95db-4208-9f04-4f9cae908a5b'],
    reference: overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'et',
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'illo',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['praesentium'],
    tests:
      overrides && overrides.hasOwnProperty('tests')
        ? overrides.tests!
        : [buildPolicyUnitTestInput()],
  };
};

export const buildAddS3LogIntegrationInput = (
  overrides?: Partial<AddS3LogIntegrationInput>
): AddS3LogIntegrationInput => {
  return {
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'non',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'et',
    s3Bucket: overrides && overrides.hasOwnProperty('s3Bucket') ? overrides.s3Bucket! : 'illum',
    kmsKey: overrides && overrides.hasOwnProperty('kmsKey') ? overrides.kmsKey! : 'et',
    s3Prefix: overrides && overrides.hasOwnProperty('s3Prefix') ? overrides.s3Prefix! : 'eum',
    logTypes: overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['qui'],
  };
};

export const buildAlertDetails = (overrides?: Partial<AlertDetails>): AlertDetails => {
  return {
    __typename: 'AlertDetails',
    alertId:
      overrides && overrides.hasOwnProperty('alertId')
        ? overrides.alertId!
        : '3c5aa76d-fb43-49f0-b65c-40e4daa756a4',
    ruleId:
      overrides && overrides.hasOwnProperty('ruleId')
        ? overrides.ruleId!
        : '8ad2c6da-517d-414f-b3e5-6959acdeaa9e',
    title: overrides && overrides.hasOwnProperty('title') ? overrides.title! : 'fugit',
    creationTime:
      overrides && overrides.hasOwnProperty('creationTime')
        ? overrides.creationTime!
        : '1978-03-29',
    updateTime:
      overrides && overrides.hasOwnProperty('updateTime') ? overrides.updateTime! : '2009-11-02',
    eventsMatched:
      overrides && overrides.hasOwnProperty('eventsMatched') ? overrides.eventsMatched! : 5163,
    events:
      overrides && overrides.hasOwnProperty('events')
        ? overrides.events!
        : ['ducimus aut rerum accusantium qui cupiditate quasi'],
    eventsLastEvaluatedKey:
      overrides && overrides.hasOwnProperty('eventsLastEvaluatedKey')
        ? overrides.eventsLastEvaluatedKey!
        : 'hic',
    dedupString:
      overrides && overrides.hasOwnProperty('dedupString') ? overrides.dedupString! : 'deserunt',
  };
};

export const buildAlertSummary = (overrides?: Partial<AlertSummary>): AlertSummary => {
  return {
    __typename: 'AlertSummary',
    alertId: overrides && overrides.hasOwnProperty('alertId') ? overrides.alertId! : 'sapiente',
    creationTime:
      overrides && overrides.hasOwnProperty('creationTime')
        ? overrides.creationTime!
        : '1988-06-21',
    eventsMatched:
      overrides && overrides.hasOwnProperty('eventsMatched') ? overrides.eventsMatched! : 6695,
    title: overrides && overrides.hasOwnProperty('title') ? overrides.title! : 'illum',
    updateTime:
      overrides && overrides.hasOwnProperty('updateTime') ? overrides.updateTime! : '1983-05-10',
    ruleId: overrides && overrides.hasOwnProperty('ruleId') ? overrides.ruleId! : 'molestiae',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
  };
};

export const buildAsanaConfig = (overrides?: Partial<AsanaConfig>): AsanaConfig => {
  return {
    __typename: 'AsanaConfig',
    personalAccessToken:
      overrides && overrides.hasOwnProperty('personalAccessToken')
        ? overrides.personalAccessToken!
        : 'et',
    projectGids:
      overrides && overrides.hasOwnProperty('projectGids')
        ? overrides.projectGids!
        : ['necessitatibus'],
  };
};

export const buildAsanaConfigInput = (overrides?: Partial<AsanaConfigInput>): AsanaConfigInput => {
  return {
    personalAccessToken:
      overrides && overrides.hasOwnProperty('personalAccessToken')
        ? overrides.personalAccessToken!
        : 'maxime',
    projectGids:
      overrides && overrides.hasOwnProperty('projectGids') ? overrides.projectGids! : ['maiores'],
  };
};

export const buildComplianceIntegration = (
  overrides?: Partial<ComplianceIntegration>
): ComplianceIntegration => {
  return {
    __typename: 'ComplianceIntegration',
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'molestiae',
    createdAtTime:
      overrides && overrides.hasOwnProperty('createdAtTime')
        ? overrides.createdAtTime!
        : '1974-11-11',
    createdBy:
      overrides && overrides.hasOwnProperty('createdBy')
        ? overrides.createdBy!
        : '560977ce-3de5-408b-9cd9-79796ea9f675',
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : 'c61dbbdd-78fd-4c1d-9a21-408d2115b3d3',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'consequatur',
    cweEnabled: overrides && overrides.hasOwnProperty('cweEnabled') ? overrides.cweEnabled! : false,
    remediationEnabled:
      overrides && overrides.hasOwnProperty('remediationEnabled')
        ? overrides.remediationEnabled!
        : true,
    health:
      overrides && overrides.hasOwnProperty('health')
        ? overrides.health!
        : buildComplianceIntegrationHealth(),
    stackName: overrides && overrides.hasOwnProperty('stackName') ? overrides.stackName! : 'neque',
  };
};

export const buildComplianceIntegrationHealth = (
  overrides?: Partial<ComplianceIntegrationHealth>
): ComplianceIntegrationHealth => {
  return {
    __typename: 'ComplianceIntegrationHealth',
    auditRoleStatus:
      overrides && overrides.hasOwnProperty('auditRoleStatus')
        ? overrides.auditRoleStatus!
        : buildIntegrationItemHealthStatus(),
    cweRoleStatus:
      overrides && overrides.hasOwnProperty('cweRoleStatus')
        ? overrides.cweRoleStatus!
        : buildIntegrationItemHealthStatus(),
    remediationRoleStatus:
      overrides && overrides.hasOwnProperty('remediationRoleStatus')
        ? overrides.remediationRoleStatus!
        : buildIntegrationItemHealthStatus(),
  };
};

export const buildComplianceItem = (overrides?: Partial<ComplianceItem>): ComplianceItem => {
  return {
    __typename: 'ComplianceItem',
    errorMessage:
      overrides && overrides.hasOwnProperty('errorMessage') ? overrides.errorMessage! : 'quia',
    lastUpdated:
      overrides && overrides.hasOwnProperty('lastUpdated') ? overrides.lastUpdated! : '1978-01-15',
    policyId:
      overrides && overrides.hasOwnProperty('policyId')
        ? overrides.policyId!
        : '6704cb04-083c-44c9-8d90-9e66b37d8cb7',
    policySeverity:
      overrides && overrides.hasOwnProperty('policySeverity')
        ? overrides.policySeverity!
        : SeverityEnum.Info,
    resourceId:
      overrides && overrides.hasOwnProperty('resourceId')
        ? overrides.resourceId!
        : '99b815e3-db3b-4df5-8a6e-9f6159ca308a',
    resourceType:
      overrides && overrides.hasOwnProperty('resourceType') ? overrides.resourceType! : 'cum',
    status:
      overrides && overrides.hasOwnProperty('status')
        ? overrides.status!
        : ComplianceStatusEnum.Error,
    suppressed: overrides && overrides.hasOwnProperty('suppressed') ? overrides.suppressed! : false,
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : '1aec2717-e82d-47fc-a2e5-3c2a8cd72160',
  };
};

export const buildComplianceStatusCounts = (
  overrides?: Partial<ComplianceStatusCounts>
): ComplianceStatusCounts => {
  return {
    __typename: 'ComplianceStatusCounts',
    error: overrides && overrides.hasOwnProperty('error') ? overrides.error! : 710,
    fail: overrides && overrides.hasOwnProperty('fail') ? overrides.fail! : 4880,
    pass: overrides && overrides.hasOwnProperty('pass') ? overrides.pass! : 1538,
  };
};

export const buildCustomWebhookConfig = (
  overrides?: Partial<CustomWebhookConfig>
): CustomWebhookConfig => {
  return {
    __typename: 'CustomWebhookConfig',
    webhookURL:
      overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'dignissimos',
  };
};

export const buildCustomWebhookConfigInput = (
  overrides?: Partial<CustomWebhookConfigInput>
): CustomWebhookConfigInput => {
  return {
    webhookURL: overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'est',
  };
};

export const buildDeleteGlobalPythonInputItem = (
  overrides?: Partial<DeleteGlobalPythonInputItem>
): DeleteGlobalPythonInputItem => {
  return {
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '38c248cf-e729-4ac6-af32-ca12f186a8bd',
  };
};

export const buildDeleteGlobalPythonModuleInput = (
  overrides?: Partial<DeleteGlobalPythonModuleInput>
): DeleteGlobalPythonModuleInput => {
  return {
    globals:
      overrides && overrides.hasOwnProperty('globals')
        ? overrides.globals!
        : [buildDeleteGlobalPythonInputItem()],
  };
};

export const buildDeletePolicyInput = (
  overrides?: Partial<DeletePolicyInput>
): DeletePolicyInput => {
  return {
    policies:
      overrides && overrides.hasOwnProperty('policies')
        ? overrides.policies!
        : [buildDeletePolicyInputItem()],
  };
};

export const buildDeletePolicyInputItem = (
  overrides?: Partial<DeletePolicyInputItem>
): DeletePolicyInputItem => {
  return {
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : 'b5304976-c86e-44d0-abe1-802e2565a38b',
  };
};

export const buildDeleteRuleInput = (overrides?: Partial<DeleteRuleInput>): DeleteRuleInput => {
  return {
    rules:
      overrides && overrides.hasOwnProperty('rules')
        ? overrides.rules!
        : [buildDeleteRuleInputItem()],
  };
};

export const buildDeleteRuleInputItem = (
  overrides?: Partial<DeleteRuleInputItem>
): DeleteRuleInputItem => {
  return {
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '8c1a40a6-9106-4f56-82b7-a71d4afc0065',
  };
};

export const buildDestination = (overrides?: Partial<Destination>): Destination => {
  return {
    __typename: 'Destination',
    createdBy: overrides && overrides.hasOwnProperty('createdBy') ? overrides.createdBy! : 'ut',
    creationTime:
      overrides && overrides.hasOwnProperty('creationTime')
        ? overrides.creationTime!
        : '1989-04-27',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'itaque',
    lastModifiedBy:
      overrides && overrides.hasOwnProperty('lastModifiedBy') ? overrides.lastModifiedBy! : 'et',
    lastModifiedTime:
      overrides && overrides.hasOwnProperty('lastModifiedTime')
        ? overrides.lastModifiedTime!
        : '1992-10-26',
    outputId:
      overrides && overrides.hasOwnProperty('outputId')
        ? overrides.outputId!
        : '9c0eb672-a7bb-4ef0-ad96-b2bc1abe94d7',
    outputType:
      overrides && overrides.hasOwnProperty('outputType')
        ? overrides.outputType!
        : DestinationTypeEnum.Slack,
    outputConfig:
      overrides && overrides.hasOwnProperty('outputConfig')
        ? overrides.outputConfig!
        : buildDestinationConfig(),
    verificationStatus:
      overrides && overrides.hasOwnProperty('verificationStatus')
        ? overrides.verificationStatus!
        : 'dicta',
    defaultForSeverity:
      overrides && overrides.hasOwnProperty('defaultForSeverity')
        ? overrides.defaultForSeverity!
        : [SeverityEnum.Info],
  };
};

export const buildDestinationConfig = (
  overrides?: Partial<DestinationConfig>
): DestinationConfig => {
  return {
    __typename: 'DestinationConfig',
    slack: overrides && overrides.hasOwnProperty('slack') ? overrides.slack! : buildSlackConfig(),
    sns: overrides && overrides.hasOwnProperty('sns') ? overrides.sns! : buildSnsConfig(),
    sqs: overrides && overrides.hasOwnProperty('sqs') ? overrides.sqs! : buildSqsConfig(),
    pagerDuty:
      overrides && overrides.hasOwnProperty('pagerDuty')
        ? overrides.pagerDuty!
        : buildPagerDutyConfig(),
    github:
      overrides && overrides.hasOwnProperty('github') ? overrides.github! : buildGithubConfig(),
    jira: overrides && overrides.hasOwnProperty('jira') ? overrides.jira! : buildJiraConfig(),
    opsgenie:
      overrides && overrides.hasOwnProperty('opsgenie')
        ? overrides.opsgenie!
        : buildOpsgenieConfig(),
    msTeams:
      overrides && overrides.hasOwnProperty('msTeams') ? overrides.msTeams! : buildMsTeamsConfig(),
    asana: overrides && overrides.hasOwnProperty('asana') ? overrides.asana! : buildAsanaConfig(),
    customWebhook:
      overrides && overrides.hasOwnProperty('customWebhook')
        ? overrides.customWebhook!
        : buildCustomWebhookConfig(),
  };
};

export const buildDestinationConfigInput = (
  overrides?: Partial<DestinationConfigInput>
): DestinationConfigInput => {
  return {
    slack:
      overrides && overrides.hasOwnProperty('slack') ? overrides.slack! : buildSlackConfigInput(),
    sns: overrides && overrides.hasOwnProperty('sns') ? overrides.sns! : buildSnsConfigInput(),
    sqs: overrides && overrides.hasOwnProperty('sqs') ? overrides.sqs! : buildSqsConfigInput(),
    pagerDuty:
      overrides && overrides.hasOwnProperty('pagerDuty')
        ? overrides.pagerDuty!
        : buildPagerDutyConfigInput(),
    github:
      overrides && overrides.hasOwnProperty('github')
        ? overrides.github!
        : buildGithubConfigInput(),
    jira: overrides && overrides.hasOwnProperty('jira') ? overrides.jira! : buildJiraConfigInput(),
    opsgenie:
      overrides && overrides.hasOwnProperty('opsgenie')
        ? overrides.opsgenie!
        : buildOpsgenieConfigInput(),
    msTeams:
      overrides && overrides.hasOwnProperty('msTeams')
        ? overrides.msTeams!
        : buildMsTeamsConfigInput(),
    asana:
      overrides && overrides.hasOwnProperty('asana') ? overrides.asana! : buildAsanaConfigInput(),
    customWebhook:
      overrides && overrides.hasOwnProperty('customWebhook')
        ? overrides.customWebhook!
        : buildCustomWebhookConfigInput(),
  };
};

export const buildDestinationInput = (overrides?: Partial<DestinationInput>): DestinationInput => {
  return {
    outputId:
      overrides && overrides.hasOwnProperty('outputId')
        ? overrides.outputId!
        : '636c7660-5609-4a00-96fe-3fabc99955d3',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'eum',
    outputConfig:
      overrides && overrides.hasOwnProperty('outputConfig')
        ? overrides.outputConfig!
        : buildDestinationConfigInput(),
    outputType:
      overrides && overrides.hasOwnProperty('outputType') ? overrides.outputType! : 'similique',
    defaultForSeverity:
      overrides && overrides.hasOwnProperty('defaultForSeverity')
        ? overrides.defaultForSeverity!
        : [SeverityEnum.Info],
  };
};

export const buildGeneralSettings = (overrides?: Partial<GeneralSettings>): GeneralSettings => {
  return {
    __typename: 'GeneralSettings',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'explicabo',
    email: overrides && overrides.hasOwnProperty('email') ? overrides.email! : 'nostrum',
    errorReportingConsent:
      overrides && overrides.hasOwnProperty('errorReportingConsent')
        ? overrides.errorReportingConsent!
        : true,
  };
};

export const buildGetAlertInput = (overrides?: Partial<GetAlertInput>): GetAlertInput => {
  return {
    alertId:
      overrides && overrides.hasOwnProperty('alertId')
        ? overrides.alertId!
        : '6dccc616-1ef2-4b9e-87ed-73b936c53e09',
    eventsPageSize:
      overrides && overrides.hasOwnProperty('eventsPageSize') ? overrides.eventsPageSize! : 3854,
    eventsExclusiveStartKey:
      overrides && overrides.hasOwnProperty('eventsExclusiveStartKey')
        ? overrides.eventsExclusiveStartKey!
        : 'vitae',
  };
};

export const buildGetComplianceIntegrationTemplateInput = (
  overrides?: Partial<GetComplianceIntegrationTemplateInput>
): GetComplianceIntegrationTemplateInput => {
  return {
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'autem',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'voluptatem',
    remediationEnabled:
      overrides && overrides.hasOwnProperty('remediationEnabled')
        ? overrides.remediationEnabled!
        : false,
    cweEnabled: overrides && overrides.hasOwnProperty('cweEnabled') ? overrides.cweEnabled! : false,
  };
};

export const buildGetGlobalPythonModuleInput = (
  overrides?: Partial<GetGlobalPythonModuleInput>
): GetGlobalPythonModuleInput => {
  return {
    globalId:
      overrides && overrides.hasOwnProperty('globalId')
        ? overrides.globalId!
        : '1f341f61-8f20-4e1f-98e0-4854a50dc594',
    versionId:
      overrides && overrides.hasOwnProperty('versionId')
        ? overrides.versionId!
        : '8fe39f4b-c18f-4a21-b9a0-feef9b77cb11',
  };
};

export const buildGetPolicyInput = (overrides?: Partial<GetPolicyInput>): GetPolicyInput => {
  return {
    policyId:
      overrides && overrides.hasOwnProperty('policyId')
        ? overrides.policyId!
        : 'e6a78c98-7d80-46bf-99e7-2df8975184a0',
    versionId:
      overrides && overrides.hasOwnProperty('versionId')
        ? overrides.versionId!
        : 'c394a64d-8476-44de-98ab-6f8666cd4c8c',
  };
};

export const buildGetResourceInput = (overrides?: Partial<GetResourceInput>): GetResourceInput => {
  return {
    resourceId:
      overrides && overrides.hasOwnProperty('resourceId')
        ? overrides.resourceId!
        : '813c64fb-d124-4dce-8757-41846aa5f4df',
  };
};

export const buildGetRuleInput = (overrides?: Partial<GetRuleInput>): GetRuleInput => {
  return {
    ruleId:
      overrides && overrides.hasOwnProperty('ruleId')
        ? overrides.ruleId!
        : '2b255df9-9276-4060-9f0c-dca418b158d6',
    versionId:
      overrides && overrides.hasOwnProperty('versionId')
        ? overrides.versionId!
        : '0b6ea7a4-6775-4b65-8315-99b764428571',
  };
};

export const buildGetS3LogIntegrationTemplateInput = (
  overrides?: Partial<GetS3LogIntegrationTemplateInput>
): GetS3LogIntegrationTemplateInput => {
  return {
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'ut',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'voluptatem',
    s3Bucket: overrides && overrides.hasOwnProperty('s3Bucket') ? overrides.s3Bucket! : 'quo',
    s3Prefix:
      overrides && overrides.hasOwnProperty('s3Prefix') ? overrides.s3Prefix! : 'consequatur',
    kmsKey: overrides && overrides.hasOwnProperty('kmsKey') ? overrides.kmsKey! : 'perferendis',
    logTypes:
      overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['molestias'],
  };
};

export const buildGithubConfig = (overrides?: Partial<GithubConfig>): GithubConfig => {
  return {
    __typename: 'GithubConfig',
    repoName: overrides && overrides.hasOwnProperty('repoName') ? overrides.repoName! : 'maxime',
    token: overrides && overrides.hasOwnProperty('token') ? overrides.token! : 'ut',
  };
};

export const buildGithubConfigInput = (
  overrides?: Partial<GithubConfigInput>
): GithubConfigInput => {
  return {
    repoName: overrides && overrides.hasOwnProperty('repoName') ? overrides.repoName! : 'ducimus',
    token: overrides && overrides.hasOwnProperty('token') ? overrides.token! : 'dolorem',
  };
};

export const buildGlobalPythonModule = (
  overrides?: Partial<GlobalPythonModule>
): GlobalPythonModule => {
  return {
    __typename: 'GlobalPythonModule',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'quis',
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'velit',
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '52f3a049-cced-4b20-825c-b8e861b2d2d0',
    createdAt:
      overrides && overrides.hasOwnProperty('createdAt') ? overrides.createdAt! : '2011-09-26',
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '2013-02-24',
  };
};

export const buildIntegrationItemHealthStatus = (
  overrides?: Partial<IntegrationItemHealthStatus>
): IntegrationItemHealthStatus => {
  return {
    __typename: 'IntegrationItemHealthStatus',
    healthy: overrides && overrides.hasOwnProperty('healthy') ? overrides.healthy! : true,
    errorMessage:
      overrides && overrides.hasOwnProperty('errorMessage') ? overrides.errorMessage! : 'in',
  };
};

export const buildIntegrationTemplate = (
  overrides?: Partial<IntegrationTemplate>
): IntegrationTemplate => {
  return {
    __typename: 'IntegrationTemplate',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'impedit',
    stackName: overrides && overrides.hasOwnProperty('stackName') ? overrides.stackName! : 'et',
  };
};

export const buildInviteUserInput = (overrides?: Partial<InviteUserInput>): InviteUserInput => {
  return {
    givenName: overrides && overrides.hasOwnProperty('givenName') ? overrides.givenName! : 'ut',
    familyName:
      overrides && overrides.hasOwnProperty('familyName') ? overrides.familyName! : 'facere',
    email:
      overrides && overrides.hasOwnProperty('email') ? overrides.email! : 'Hoyt.Torphy@Reichel.org',
  };
};

export const buildJiraConfig = (overrides?: Partial<JiraConfig>): JiraConfig => {
  return {
    __typename: 'JiraConfig',
    orgDomain: overrides && overrides.hasOwnProperty('orgDomain') ? overrides.orgDomain! : 'quidem',
    projectKey:
      overrides && overrides.hasOwnProperty('projectKey') ? overrides.projectKey! : 'repudiandae',
    userName:
      overrides && overrides.hasOwnProperty('userName') ? overrides.userName! : 'distinctio',
    apiKey: overrides && overrides.hasOwnProperty('apiKey') ? overrides.apiKey! : 'dolor',
    assigneeId:
      overrides && overrides.hasOwnProperty('assigneeId') ? overrides.assigneeId! : 'suscipit',
    issueType: overrides && overrides.hasOwnProperty('issueType') ? overrides.issueType! : 'sunt',
  };
};

export const buildJiraConfigInput = (overrides?: Partial<JiraConfigInput>): JiraConfigInput => {
  return {
    orgDomain:
      overrides && overrides.hasOwnProperty('orgDomain') ? overrides.orgDomain! : 'impedit',
    projectKey:
      overrides && overrides.hasOwnProperty('projectKey') ? overrides.projectKey! : 'officiis',
    userName: overrides && overrides.hasOwnProperty('userName') ? overrides.userName! : 'eos',
    apiKey: overrides && overrides.hasOwnProperty('apiKey') ? overrides.apiKey! : 'et',
    assigneeId:
      overrides && overrides.hasOwnProperty('assigneeId') ? overrides.assigneeId! : 'cupiditate',
    issueType:
      overrides && overrides.hasOwnProperty('issueType') ? overrides.issueType! : 'aliquid',
  };
};

export const buildListAlertsInput = (overrides?: Partial<ListAlertsInput>): ListAlertsInput => {
  return {
    ruleId:
      overrides && overrides.hasOwnProperty('ruleId')
        ? overrides.ruleId!
        : '5d7dfe6a-46ac-41c2-9fc1-0eaf33c0215a',
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 8273,
    exclusiveStartKey:
      overrides && overrides.hasOwnProperty('exclusiveStartKey')
        ? overrides.exclusiveStartKey!
        : 'rem',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : [SeverityEnum.Info],
    nameContains:
      overrides && overrides.hasOwnProperty('nameContains')
        ? overrides.nameContains!
        : 'praesentium',
    createdAtBefore:
      overrides && overrides.hasOwnProperty('createdAtBefore')
        ? overrides.createdAtBefore!
        : '1998-05-16',
    createdAtAfter:
      overrides && overrides.hasOwnProperty('createdAtAfter')
        ? overrides.createdAtAfter!
        : '2001-09-02',
    ruleIdContains:
      overrides && overrides.hasOwnProperty('ruleIdContains')
        ? overrides.ruleIdContains!
        : 'temporibus',
    alertIdContains:
      overrides && overrides.hasOwnProperty('alertIdContains')
        ? overrides.alertIdContains!
        : 'eaque',
    eventCountMin:
      overrides && overrides.hasOwnProperty('eventCountMin') ? overrides.eventCountMin! : 6934,
    eventCountMax:
      overrides && overrides.hasOwnProperty('eventCountMax') ? overrides.eventCountMax! : 9101,
    sortBy:
      overrides && overrides.hasOwnProperty('sortBy')
        ? overrides.sortBy!
        : ListAlertsSortFieldsEnum.CreatedAt,
    sortDir:
      overrides && overrides.hasOwnProperty('sortDir') ? overrides.sortDir! : SortDirEnum.Ascending,
  };
};

export const buildListAlertsResponse = (
  overrides?: Partial<ListAlertsResponse>
): ListAlertsResponse => {
  return {
    __typename: 'ListAlertsResponse',
    alertSummaries:
      overrides && overrides.hasOwnProperty('alertSummaries')
        ? overrides.alertSummaries!
        : [buildAlertSummary()],
    lastEvaluatedKey:
      overrides && overrides.hasOwnProperty('lastEvaluatedKey')
        ? overrides.lastEvaluatedKey!
        : 'culpa',
  };
};

export const buildListComplianceItemsResponse = (
  overrides?: Partial<ListComplianceItemsResponse>
): ListComplianceItemsResponse => {
  return {
    __typename: 'ListComplianceItemsResponse',
    items:
      overrides && overrides.hasOwnProperty('items') ? overrides.items! : [buildComplianceItem()],
    paging: overrides && overrides.hasOwnProperty('paging') ? overrides.paging! : buildPagingData(),
    status:
      overrides && overrides.hasOwnProperty('status')
        ? overrides.status!
        : ComplianceStatusEnum.Error,
    totals:
      overrides && overrides.hasOwnProperty('totals')
        ? overrides.totals!
        : buildActiveSuppressCount(),
  };
};

export const buildListGlobalPythonModuleInput = (
  overrides?: Partial<ListGlobalPythonModuleInput>
): ListGlobalPythonModuleInput => {
  return {
    nameContains:
      overrides && overrides.hasOwnProperty('nameContains') ? overrides.nameContains! : 'est',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    sortDir:
      overrides && overrides.hasOwnProperty('sortDir') ? overrides.sortDir! : SortDirEnum.Ascending,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 4439,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 4045,
  };
};

export const buildListGlobalPythonModulesResponse = (
  overrides?: Partial<ListGlobalPythonModulesResponse>
): ListGlobalPythonModulesResponse => {
  return {
    __typename: 'ListGlobalPythonModulesResponse',
    paging: overrides && overrides.hasOwnProperty('paging') ? overrides.paging! : buildPagingData(),
    globals:
      overrides && overrides.hasOwnProperty('globals')
        ? overrides.globals!
        : [buildGlobalPythonModule()],
  };
};

export const buildListPoliciesInput = (
  overrides?: Partial<ListPoliciesInput>
): ListPoliciesInput => {
  return {
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    nameContains:
      overrides && overrides.hasOwnProperty('nameContains') ? overrides.nameContains! : 'possimus',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : true,
    hasRemediation:
      overrides && overrides.hasOwnProperty('hasRemediation') ? overrides.hasRemediation! : true,
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes')
        ? overrides.resourceTypes!
        : 'corporis',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : 'ipsum',
    sortBy:
      overrides && overrides.hasOwnProperty('sortBy')
        ? overrides.sortBy!
        : ListPoliciesSortFieldsEnum.ComplianceStatus,
    sortDir:
      overrides && overrides.hasOwnProperty('sortDir') ? overrides.sortDir! : SortDirEnum.Ascending,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 504,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 2538,
  };
};

export const buildListPoliciesResponse = (
  overrides?: Partial<ListPoliciesResponse>
): ListPoliciesResponse => {
  return {
    __typename: 'ListPoliciesResponse',
    paging: overrides && overrides.hasOwnProperty('paging') ? overrides.paging! : buildPagingData(),
    policies:
      overrides && overrides.hasOwnProperty('policies')
        ? overrides.policies!
        : [buildPolicySummary()],
  };
};

export const buildListResourcesInput = (
  overrides?: Partial<ListResourcesInput>
): ListResourcesInput => {
  return {
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    deleted: overrides && overrides.hasOwnProperty('deleted') ? overrides.deleted! : false,
    idContains:
      overrides && overrides.hasOwnProperty('idContains') ? overrides.idContains! : 'atque',
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : 'dcdadc7d-3460-418b-9e63-79d7110ffc5f',
    types: overrides && overrides.hasOwnProperty('types') ? overrides.types! : 'velit',
    sortBy:
      overrides && overrides.hasOwnProperty('sortBy')
        ? overrides.sortBy!
        : ListResourcesSortFieldsEnum.ComplianceStatus,
    sortDir:
      overrides && overrides.hasOwnProperty('sortDir') ? overrides.sortDir! : SortDirEnum.Ascending,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 2280,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 6426,
  };
};

export const buildListResourcesResponse = (
  overrides?: Partial<ListResourcesResponse>
): ListResourcesResponse => {
  return {
    __typename: 'ListResourcesResponse',
    paging: overrides && overrides.hasOwnProperty('paging') ? overrides.paging! : buildPagingData(),
    resources:
      overrides && overrides.hasOwnProperty('resources')
        ? overrides.resources!
        : [buildResourceSummary()],
  };
};

export const buildListRulesInput = (overrides?: Partial<ListRulesInput>): ListRulesInput => {
  return {
    nameContains:
      overrides && overrides.hasOwnProperty('nameContains') ? overrides.nameContains! : 'ratione',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : true,
    logTypes: overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : 'ducimus',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : 'quam',
    sortBy:
      overrides && overrides.hasOwnProperty('sortBy')
        ? overrides.sortBy!
        : ListRulesSortFieldsEnum.Enabled,
    sortDir:
      overrides && overrides.hasOwnProperty('sortDir') ? overrides.sortDir! : SortDirEnum.Ascending,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 193,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 3233,
  };
};

export const buildListRulesResponse = (
  overrides?: Partial<ListRulesResponse>
): ListRulesResponse => {
  return {
    __typename: 'ListRulesResponse',
    paging: overrides && overrides.hasOwnProperty('paging') ? overrides.paging! : buildPagingData(),
    rules: overrides && overrides.hasOwnProperty('rules') ? overrides.rules! : [buildRuleSummary()],
  };
};

export const buildModifyGlobalPythonModuleInput = (
  overrides?: Partial<ModifyGlobalPythonModuleInput>
): ModifyGlobalPythonModuleInput => {
  return {
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'consequatur',
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : 'bf4a9975-bdcf-4efc-9667-e59f6214197c',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'quis',
  };
};

export const buildMsTeamsConfig = (overrides?: Partial<MsTeamsConfig>): MsTeamsConfig => {
  return {
    __typename: 'MsTeamsConfig',
    webhookURL: overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'et',
  };
};

export const buildMsTeamsConfigInput = (
  overrides?: Partial<MsTeamsConfigInput>
): MsTeamsConfigInput => {
  return {
    webhookURL:
      overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'accusamus',
  };
};

export const buildOpsgenieConfig = (overrides?: Partial<OpsgenieConfig>): OpsgenieConfig => {
  return {
    __typename: 'OpsgenieConfig',
    apiKey: overrides && overrides.hasOwnProperty('apiKey') ? overrides.apiKey! : 'eos',
  };
};

export const buildOpsgenieConfigInput = (
  overrides?: Partial<OpsgenieConfigInput>
): OpsgenieConfigInput => {
  return {
    apiKey: overrides && overrides.hasOwnProperty('apiKey') ? overrides.apiKey! : 'fugiat',
  };
};

export const buildOrganizationReportBySeverity = (
  overrides?: Partial<OrganizationReportBySeverity>
): OrganizationReportBySeverity => {
  return {
    __typename: 'OrganizationReportBySeverity',
    info:
      overrides && overrides.hasOwnProperty('info')
        ? overrides.info!
        : buildComplianceStatusCounts(),
    low:
      overrides && overrides.hasOwnProperty('low') ? overrides.low! : buildComplianceStatusCounts(),
    medium:
      overrides && overrides.hasOwnProperty('medium')
        ? overrides.medium!
        : buildComplianceStatusCounts(),
    high:
      overrides && overrides.hasOwnProperty('high')
        ? overrides.high!
        : buildComplianceStatusCounts(),
    critical:
      overrides && overrides.hasOwnProperty('critical')
        ? overrides.critical!
        : buildComplianceStatusCounts(),
  };
};

export const buildOrganizationStatsInput = (
  overrides?: Partial<OrganizationStatsInput>
): OrganizationStatsInput => {
  return {
    limitTopFailing:
      overrides && overrides.hasOwnProperty('limitTopFailing') ? overrides.limitTopFailing! : 8181,
  };
};

export const buildOrganizationStatsResponse = (
  overrides?: Partial<OrganizationStatsResponse>
): OrganizationStatsResponse => {
  return {
    __typename: 'OrganizationStatsResponse',
    appliedPolicies:
      overrides && overrides.hasOwnProperty('appliedPolicies')
        ? overrides.appliedPolicies!
        : buildOrganizationReportBySeverity(),
    scannedResources:
      overrides && overrides.hasOwnProperty('scannedResources')
        ? overrides.scannedResources!
        : buildScannedResources(),
    topFailingPolicies:
      overrides && overrides.hasOwnProperty('topFailingPolicies')
        ? overrides.topFailingPolicies!
        : [buildPolicySummary()],
    topFailingResources:
      overrides && overrides.hasOwnProperty('topFailingResources')
        ? overrides.topFailingResources!
        : [buildResourceSummary()],
  };
};

export const buildPagerDutyConfig = (overrides?: Partial<PagerDutyConfig>): PagerDutyConfig => {
  return {
    __typename: 'PagerDutyConfig',
    integrationKey:
      overrides && overrides.hasOwnProperty('integrationKey') ? overrides.integrationKey! : 'iure',
  };
};

export const buildPagerDutyConfigInput = (
  overrides?: Partial<PagerDutyConfigInput>
): PagerDutyConfigInput => {
  return {
    integrationKey:
      overrides && overrides.hasOwnProperty('integrationKey') ? overrides.integrationKey! : 'qui',
  };
};

export const buildPagingData = (overrides?: Partial<PagingData>): PagingData => {
  return {
    __typename: 'PagingData',
    thisPage: overrides && overrides.hasOwnProperty('thisPage') ? overrides.thisPage! : 2891,
    totalPages: overrides && overrides.hasOwnProperty('totalPages') ? overrides.totalPages! : 8118,
    totalItems: overrides && overrides.hasOwnProperty('totalItems') ? overrides.totalItems! : 3942,
  };
};

export const buildPoliciesForResourceInput = (
  overrides?: Partial<PoliciesForResourceInput>
): PoliciesForResourceInput => {
  return {
    resourceId:
      overrides && overrides.hasOwnProperty('resourceId')
        ? overrides.resourceId!
        : 'e3bd41bd-5265-4a12-b256-43a459c62d5b',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    status:
      overrides && overrides.hasOwnProperty('status')
        ? overrides.status!
        : ComplianceStatusEnum.Error,
    suppressed: overrides && overrides.hasOwnProperty('suppressed') ? overrides.suppressed! : true,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 2820,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 9055,
  };
};

export const buildPolicyDetails = (overrides?: Partial<PolicyDetails>): PolicyDetails => {
  return {
    __typename: 'PolicyDetails',
    autoRemediationId:
      overrides && overrides.hasOwnProperty('autoRemediationId')
        ? overrides.autoRemediationId!
        : '73631269-a304-4865-a222-af96d4b3162c',
    autoRemediationParameters:
      overrides && overrides.hasOwnProperty('autoRemediationParameters')
        ? overrides.autoRemediationParameters!
        : 'et odio non repudiandae blanditiis est dignissimos',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'id',
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    createdAt:
      overrides && overrides.hasOwnProperty('createdAt') ? overrides.createdAt! : '1970-10-15',
    createdBy:
      overrides && overrides.hasOwnProperty('createdBy')
        ? overrides.createdBy!
        : 'dc4acb0d-32fe-4182-929b-932f1f6d7f85',
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'voluptatem',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'dolorem',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '5193e9e6-c55b-48ad-8475-c171d8c2ea89',
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '1999-09-08',
    lastModifiedBy:
      overrides && overrides.hasOwnProperty('lastModifiedBy')
        ? overrides.lastModifiedBy!
        : '9b4fcf01-d8f1-4fbf-9c94-f4f58d04c799',
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['313c2719-eb31-4502-8a8a-bdda432a772a'],
    reference: overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'odio',
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes')
        ? overrides.resourceTypes!
        : ['reiciendis'],
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'quaerat',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    suppressions:
      overrides && overrides.hasOwnProperty('suppressions') ? overrides.suppressions! : ['neque'],
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['nemo'],
    tests:
      overrides && overrides.hasOwnProperty('tests') ? overrides.tests! : [buildPolicyUnitTest()],
    versionId:
      overrides && overrides.hasOwnProperty('versionId')
        ? overrides.versionId!
        : 'da391fc7-e186-4bcb-9717-2e34cb330d83',
  };
};

export const buildPolicySummary = (overrides?: Partial<PolicySummary>): PolicySummary => {
  return {
    __typename: 'PolicySummary',
    autoRemediationId:
      overrides && overrides.hasOwnProperty('autoRemediationId')
        ? overrides.autoRemediationId!
        : '53a2278e-77bf-4941-81f8-6fbe8503562c',
    autoRemediationParameters:
      overrides && overrides.hasOwnProperty('autoRemediationParameters')
        ? overrides.autoRemediationParameters!
        : 'sunt eaque eligendi excepturi mollitia ipsum recusandae',
    suppressions:
      overrides && overrides.hasOwnProperty('suppressions')
        ? overrides.suppressions!
        : ['repudiandae'],
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'quia',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : true,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '360cad31-ff71-4eb6-8ac1-0ca1d0da39c7',
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '1984-03-17',
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes') ? overrides.resourceTypes! : ['rerum'],
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['dolorem'],
  };
};

export const buildPolicyUnitTest = (overrides?: Partial<PolicyUnitTest>): PolicyUnitTest => {
  return {
    __typename: 'PolicyUnitTest',
    expectedResult:
      overrides && overrides.hasOwnProperty('expectedResult') ? overrides.expectedResult! : false,
    name: overrides && overrides.hasOwnProperty('name') ? overrides.name! : 'ipsum',
    resource: overrides && overrides.hasOwnProperty('resource') ? overrides.resource! : 'quidem',
  };
};

export const buildPolicyUnitTestError = (
  overrides?: Partial<PolicyUnitTestError>
): PolicyUnitTestError => {
  return {
    __typename: 'PolicyUnitTestError',
    name: overrides && overrides.hasOwnProperty('name') ? overrides.name! : 'facere',
    errorMessage:
      overrides && overrides.hasOwnProperty('errorMessage') ? overrides.errorMessage! : 'dolores',
  };
};

export const buildPolicyUnitTestInput = (
  overrides?: Partial<PolicyUnitTestInput>
): PolicyUnitTestInput => {
  return {
    expectedResult:
      overrides && overrides.hasOwnProperty('expectedResult') ? overrides.expectedResult! : true,
    name: overrides && overrides.hasOwnProperty('name') ? overrides.name! : 'qui',
    resource: overrides && overrides.hasOwnProperty('resource') ? overrides.resource! : 'dolore',
  };
};

export const buildRemediateResourceInput = (
  overrides?: Partial<RemediateResourceInput>
): RemediateResourceInput => {
  return {
    policyId:
      overrides && overrides.hasOwnProperty('policyId')
        ? overrides.policyId!
        : '8f991f1d-ccc4-4ce1-a490-235f34dd4da9',
    resourceId:
      overrides && overrides.hasOwnProperty('resourceId')
        ? overrides.resourceId!
        : '07cb94ba-5961-439a-bcbf-d305e26019da',
  };
};

export const buildResourceDetails = (overrides?: Partial<ResourceDetails>): ResourceDetails => {
  return {
    __typename: 'ResourceDetails',
    attributes:
      overrides && overrides.hasOwnProperty('attributes')
        ? overrides.attributes!
        : 'qui qui dolore eveniet qui repellendus ut',
    deleted: overrides && overrides.hasOwnProperty('deleted') ? overrides.deleted! : true,
    expiresAt: overrides && overrides.hasOwnProperty('expiresAt') ? overrides.expiresAt! : 9684,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '48de615f-3645-4b97-aa31-6cab72afe085',
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : 'd3876057-7d75-4af9-a160-b51a16359574',
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '2002-03-06',
    type: overrides && overrides.hasOwnProperty('type') ? overrides.type! : 'dolorem',
  };
};

export const buildResourcesForPolicyInput = (
  overrides?: Partial<ResourcesForPolicyInput>
): ResourcesForPolicyInput => {
  return {
    policyId:
      overrides && overrides.hasOwnProperty('policyId')
        ? overrides.policyId!
        : 'bcd9a6a4-6c52-43d2-acd6-29bd74eb973f',
    status:
      overrides && overrides.hasOwnProperty('status')
        ? overrides.status!
        : ComplianceStatusEnum.Error,
    suppressed: overrides && overrides.hasOwnProperty('suppressed') ? overrides.suppressed! : false,
    pageSize: overrides && overrides.hasOwnProperty('pageSize') ? overrides.pageSize! : 1373,
    page: overrides && overrides.hasOwnProperty('page') ? overrides.page! : 3539,
  };
};

export const buildResourceSummary = (overrides?: Partial<ResourceSummary>): ResourceSummary => {
  return {
    __typename: 'ResourceSummary',
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '8642570b-2380-417d-b139-7e9d3e887b08',
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : 'ab97638e-e07d-4ca1-96f6-306967b7c092',
    complianceStatus:
      overrides && overrides.hasOwnProperty('complianceStatus')
        ? overrides.complianceStatus!
        : ComplianceStatusEnum.Error,
    deleted: overrides && overrides.hasOwnProperty('deleted') ? overrides.deleted! : true,
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '1982-01-23',
    type: overrides && overrides.hasOwnProperty('type') ? overrides.type! : 'similique',
  };
};

export const buildRuleDetails = (overrides?: Partial<RuleDetails>): RuleDetails => {
  return {
    __typename: 'RuleDetails',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'voluptatem',
    createdAt:
      overrides && overrides.hasOwnProperty('createdAt') ? overrides.createdAt! : '1989-02-20',
    createdBy:
      overrides && overrides.hasOwnProperty('createdBy')
        ? overrides.createdBy!
        : '7c3e570b-d621-4e3a-9ab1-9a21e9aa4d17',
    dedupPeriodMinutes:
      overrides && overrides.hasOwnProperty('dedupPeriodMinutes')
        ? overrides.dedupPeriodMinutes!
        : 348,
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'accusamus',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'quaerat',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : true,
    id: overrides && overrides.hasOwnProperty('id') ? overrides.id! : 'magni',
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '2012-07-07',
    lastModifiedBy:
      overrides && overrides.hasOwnProperty('lastModifiedBy')
        ? overrides.lastModifiedBy!
        : '4c381f6d-e9c9-4de8-8d6f-cc274dc6b1e0',
    logTypes:
      overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['mollitia'],
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['0460c173-040b-433a-9f75-b657c342f229'],
    reference: overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'vel',
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'harum',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['temporibus'],
    tests:
      overrides && overrides.hasOwnProperty('tests') ? overrides.tests! : [buildPolicyUnitTest()],
    versionId:
      overrides && overrides.hasOwnProperty('versionId')
        ? overrides.versionId!
        : 'dd730243-f772-446f-9820-ef796b83a51f',
  };
};

export const buildRuleSummary = (overrides?: Partial<RuleSummary>): RuleSummary => {
  return {
    __typename: 'RuleSummary',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'porro',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : true,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '5ce135b7-105f-4a98-9a69-8b9d3b372bdb',
    lastModified:
      overrides && overrides.hasOwnProperty('lastModified')
        ? overrides.lastModified!
        : '1980-04-15',
    logTypes: overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['vero'],
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['culpa'],
  };
};

export const buildS3LogIntegration = (overrides?: Partial<S3LogIntegration>): S3LogIntegration => {
  return {
    __typename: 'S3LogIntegration',
    awsAccountId:
      overrides && overrides.hasOwnProperty('awsAccountId') ? overrides.awsAccountId! : 'dolores',
    createdAtTime:
      overrides && overrides.hasOwnProperty('createdAtTime')
        ? overrides.createdAtTime!
        : '1993-01-23',
    createdBy:
      overrides && overrides.hasOwnProperty('createdBy')
        ? overrides.createdBy!
        : 'e135f3dc-8654-4752-91a9-d20f98d87e48',
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : '63041328-828c-4ff9-8396-16b9b769900d',
    integrationType:
      overrides && overrides.hasOwnProperty('integrationType') ? overrides.integrationType! : 'sit',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'quo',
    lastEventReceived:
      overrides && overrides.hasOwnProperty('lastEventReceived')
        ? overrides.lastEventReceived!
        : '1998-01-03',
    s3Bucket: overrides && overrides.hasOwnProperty('s3Bucket') ? overrides.s3Bucket! : 'illum',
    s3Prefix: overrides && overrides.hasOwnProperty('s3Prefix') ? overrides.s3Prefix! : 'vero',
    kmsKey: overrides && overrides.hasOwnProperty('kmsKey') ? overrides.kmsKey! : 'aliquid',
    logTypes: overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['iure'],
    health:
      overrides && overrides.hasOwnProperty('health')
        ? overrides.health!
        : buildS3LogIntegrationHealth(),
    stackName: overrides && overrides.hasOwnProperty('stackName') ? overrides.stackName! : 'totam',
  };
};

export const buildS3LogIntegrationHealth = (
  overrides?: Partial<S3LogIntegrationHealth>
): S3LogIntegrationHealth => {
  return {
    __typename: 'S3LogIntegrationHealth',
    processingRoleStatus:
      overrides && overrides.hasOwnProperty('processingRoleStatus')
        ? overrides.processingRoleStatus!
        : buildIntegrationItemHealthStatus(),
    s3BucketStatus:
      overrides && overrides.hasOwnProperty('s3BucketStatus')
        ? overrides.s3BucketStatus!
        : buildIntegrationItemHealthStatus(),
    kmsKeyStatus:
      overrides && overrides.hasOwnProperty('kmsKeyStatus')
        ? overrides.kmsKeyStatus!
        : buildIntegrationItemHealthStatus(),
  };
};

export const buildScannedResources = (overrides?: Partial<ScannedResources>): ScannedResources => {
  return {
    __typename: 'ScannedResources',
    byType:
      overrides && overrides.hasOwnProperty('byType')
        ? overrides.byType!
        : [buildScannedResourceStats()],
  };
};

export const buildScannedResourceStats = (
  overrides?: Partial<ScannedResourceStats>
): ScannedResourceStats => {
  return {
    __typename: 'ScannedResourceStats',
    count:
      overrides && overrides.hasOwnProperty('count')
        ? overrides.count!
        : buildComplianceStatusCounts(),
    type: overrides && overrides.hasOwnProperty('type') ? overrides.type! : 'ut',
  };
};

export const buildSlackConfig = (overrides?: Partial<SlackConfig>): SlackConfig => {
  return {
    __typename: 'SlackConfig',
    webhookURL:
      overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'nobis',
  };
};

export const buildSlackConfigInput = (overrides?: Partial<SlackConfigInput>): SlackConfigInput => {
  return {
    webhookURL:
      overrides && overrides.hasOwnProperty('webhookURL') ? overrides.webhookURL! : 'praesentium',
  };
};

export const buildSnsConfig = (overrides?: Partial<SnsConfig>): SnsConfig => {
  return {
    __typename: 'SnsConfig',
    topicArn: overrides && overrides.hasOwnProperty('topicArn') ? overrides.topicArn! : 'aut',
  };
};

export const buildSnsConfigInput = (overrides?: Partial<SnsConfigInput>): SnsConfigInput => {
  return {
    topicArn: overrides && overrides.hasOwnProperty('topicArn') ? overrides.topicArn! : 'voluptas',
  };
};

export const buildSqsConfig = (overrides?: Partial<SqsConfig>): SqsConfig => {
  return {
    __typename: 'SqsConfig',
    queueUrl: overrides && overrides.hasOwnProperty('queueUrl') ? overrides.queueUrl! : 'maiores',
  };
};

export const buildSqsConfigInput = (overrides?: Partial<SqsConfigInput>): SqsConfigInput => {
  return {
    queueUrl: overrides && overrides.hasOwnProperty('queueUrl') ? overrides.queueUrl! : 'et',
  };
};

export const buildSuppressPoliciesInput = (
  overrides?: Partial<SuppressPoliciesInput>
): SuppressPoliciesInput => {
  return {
    policyIds:
      overrides && overrides.hasOwnProperty('policyIds')
        ? overrides.policyIds!
        : ['a2796f03-3f72-4717-a45b-fea5c8b2943f'],
    resourcePatterns:
      overrides && overrides.hasOwnProperty('resourcePatterns')
        ? overrides.resourcePatterns!
        : ['nobis'],
  };
};

export const buildTestPolicyInput = (overrides?: Partial<TestPolicyInput>): TestPolicyInput => {
  return {
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'et',
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes')
        ? overrides.resourceTypes!
        : ['accusantium'],
    analysisType:
      overrides && overrides.hasOwnProperty('analysisType')
        ? overrides.analysisType!
        : AnalysisTypeEnum.Rule,
    tests:
      overrides && overrides.hasOwnProperty('tests')
        ? overrides.tests!
        : [buildPolicyUnitTestInput()],
  };
};

export const buildTestPolicyResponse = (
  overrides?: Partial<TestPolicyResponse>
): TestPolicyResponse => {
  return {
    __typename: 'TestPolicyResponse',
    testSummary:
      overrides && overrides.hasOwnProperty('testSummary') ? overrides.testSummary! : true,
    testsPassed:
      overrides && overrides.hasOwnProperty('testsPassed') ? overrides.testsPassed! : ['maiores'],
    testsFailed:
      overrides && overrides.hasOwnProperty('testsFailed') ? overrides.testsFailed! : ['sed'],
    testsErrored:
      overrides && overrides.hasOwnProperty('testsErrored')
        ? overrides.testsErrored!
        : [buildPolicyUnitTestError()],
  };
};

export const buildUpdateComplianceIntegrationInput = (
  overrides?: Partial<UpdateComplianceIntegrationInput>
): UpdateComplianceIntegrationInput => {
  return {
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId')
        ? overrides.integrationId!
        : 'corporis',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'nisi',
    cweEnabled: overrides && overrides.hasOwnProperty('cweEnabled') ? overrides.cweEnabled! : true,
    remediationEnabled:
      overrides && overrides.hasOwnProperty('remediationEnabled')
        ? overrides.remediationEnabled!
        : true,
  };
};

export const buildUpdateGeneralSettingsInput = (
  overrides?: Partial<UpdateGeneralSettingsInput>
): UpdateGeneralSettingsInput => {
  return {
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'sint',
    email: overrides && overrides.hasOwnProperty('email') ? overrides.email! : 'non',
    errorReportingConsent:
      overrides && overrides.hasOwnProperty('errorReportingConsent')
        ? overrides.errorReportingConsent!
        : false,
  };
};

export const buildUpdatePolicyInput = (
  overrides?: Partial<UpdatePolicyInput>
): UpdatePolicyInput => {
  return {
    autoRemediationId:
      overrides && overrides.hasOwnProperty('autoRemediationId')
        ? overrides.autoRemediationId!
        : '2ec80d46-eb82-458d-9293-dcefffe7eeaa',
    autoRemediationParameters:
      overrides && overrides.hasOwnProperty('autoRemediationParameters')
        ? overrides.autoRemediationParameters!
        : 'odit quisquam rerum esse eligendi qui sed',
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'incidunt',
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'commodi',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'harum',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : 'ddf83cf0-7494-413a-b723-cdfd28c60cc7',
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['82126800-bfab-49cc-b6fb-c7d45589f268'],
    reference:
      overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'dolorem',
    resourceTypes:
      overrides && overrides.hasOwnProperty('resourceTypes')
        ? overrides.resourceTypes!
        : ['excepturi'],
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'ea',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    suppressions:
      overrides && overrides.hasOwnProperty('suppressions') ? overrides.suppressions! : ['numquam'],
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['assumenda'],
    tests:
      overrides && overrides.hasOwnProperty('tests')
        ? overrides.tests!
        : [buildPolicyUnitTestInput()],
  };
};

export const buildUpdateRuleInput = (overrides?: Partial<UpdateRuleInput>): UpdateRuleInput => {
  return {
    body: overrides && overrides.hasOwnProperty('body') ? overrides.body! : 'nihil',
    dedupPeriodMinutes:
      overrides && overrides.hasOwnProperty('dedupPeriodMinutes')
        ? overrides.dedupPeriodMinutes!
        : 7481,
    description:
      overrides && overrides.hasOwnProperty('description') ? overrides.description! : 'officia',
    displayName:
      overrides && overrides.hasOwnProperty('displayName') ? overrides.displayName! : 'et',
    enabled: overrides && overrides.hasOwnProperty('enabled') ? overrides.enabled! : false,
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '08acb268-462c-44de-b424-38c46a166088',
    logTypes: overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['quam'],
    outputIds:
      overrides && overrides.hasOwnProperty('outputIds')
        ? overrides.outputIds!
        : ['ce925222-cb76-43b8-a891-a7b6f90d8180'],
    reference: overrides && overrides.hasOwnProperty('reference') ? overrides.reference! : 'iusto',
    runbook: overrides && overrides.hasOwnProperty('runbook') ? overrides.runbook! : 'sed',
    severity:
      overrides && overrides.hasOwnProperty('severity') ? overrides.severity! : SeverityEnum.Info,
    tags: overrides && overrides.hasOwnProperty('tags') ? overrides.tags! : ['ut'],
    tests:
      overrides && overrides.hasOwnProperty('tests')
        ? overrides.tests!
        : [buildPolicyUnitTestInput()],
  };
};

export const buildUpdateS3LogIntegrationInput = (
  overrides?: Partial<UpdateS3LogIntegrationInput>
): UpdateS3LogIntegrationInput => {
  return {
    integrationId:
      overrides && overrides.hasOwnProperty('integrationId') ? overrides.integrationId! : 'qui',
    integrationLabel:
      overrides && overrides.hasOwnProperty('integrationLabel')
        ? overrides.integrationLabel!
        : 'quos',
    s3Bucket: overrides && overrides.hasOwnProperty('s3Bucket') ? overrides.s3Bucket! : 'numquam',
    kmsKey: overrides && overrides.hasOwnProperty('kmsKey') ? overrides.kmsKey! : 'distinctio',
    s3Prefix: overrides && overrides.hasOwnProperty('s3Prefix') ? overrides.s3Prefix! : 'sit',
    logTypes:
      overrides && overrides.hasOwnProperty('logTypes') ? overrides.logTypes! : ['repudiandae'],
  };
};

export const buildUpdateUserInput = (overrides?: Partial<UpdateUserInput>): UpdateUserInput => {
  return {
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : '1d6a9360-c92b-4660-8e5f-04155047bddc',
    givenName:
      overrides && overrides.hasOwnProperty('givenName') ? overrides.givenName! : 'dolorum',
    familyName: overrides && overrides.hasOwnProperty('familyName') ? overrides.familyName! : 'qui',
    email:
      overrides && overrides.hasOwnProperty('email')
        ? overrides.email!
        : 'Elisa.Lindgren@gmail.com',
  };
};

export const buildUploadPoliciesInput = (
  overrides?: Partial<UploadPoliciesInput>
): UploadPoliciesInput => {
  return {
    data: overrides && overrides.hasOwnProperty('data') ? overrides.data! : 'autem',
  };
};

export const buildUploadPoliciesResponse = (
  overrides?: Partial<UploadPoliciesResponse>
): UploadPoliciesResponse => {
  return {
    __typename: 'UploadPoliciesResponse',
    totalPolicies:
      overrides && overrides.hasOwnProperty('totalPolicies') ? overrides.totalPolicies! : 1020,
    newPolicies:
      overrides && overrides.hasOwnProperty('newPolicies') ? overrides.newPolicies! : 9703,
    modifiedPolicies:
      overrides && overrides.hasOwnProperty('modifiedPolicies')
        ? overrides.modifiedPolicies!
        : 8285,
    totalRules: overrides && overrides.hasOwnProperty('totalRules') ? overrides.totalRules! : 9150,
    newRules: overrides && overrides.hasOwnProperty('newRules') ? overrides.newRules! : 8972,
    modifiedRules:
      overrides && overrides.hasOwnProperty('modifiedRules') ? overrides.modifiedRules! : 4628,
  };
};

export const buildUser = (overrides?: Partial<User>): User => {
  return {
    __typename: 'User',
    givenName:
      overrides && overrides.hasOwnProperty('givenName') ? overrides.givenName! : 'voluptas',
    familyName:
      overrides && overrides.hasOwnProperty('familyName') ? overrides.familyName! : 'incidunt',
    id:
      overrides && overrides.hasOwnProperty('id')
        ? overrides.id!
        : 'a5756f00-41a6-422a-8a7d-d13ee6a63750',
    email:
      overrides && overrides.hasOwnProperty('email') ? overrides.email! : 'Trinity_Ferry@gmail.com',
    createdAt:
      overrides && overrides.hasOwnProperty('createdAt') ? overrides.createdAt! : 1458071232,
    status: overrides && overrides.hasOwnProperty('status') ? overrides.status! : 'iusto',
  };
};
