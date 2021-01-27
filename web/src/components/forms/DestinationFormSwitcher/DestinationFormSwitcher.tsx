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

import React from 'react';
import pick from 'lodash/pick';
import { DestinationInput, DestinationTypeEnum } from 'Generated/schema';
import PagerDutyDestinationForm from '../PagerdutyDestinationForm';
import GithubDestinationForm from '../GithubDestinationForm';
import JiraDestinationForm from '../JiraDestinationForm';
import OpsgenieDestinationForm from '../OpsgenieDestinationForm';
import MicrosoftTeamsDestinationForm from '../MicrosoftTeamsDestinationForm';
import SNSDestinationForm from '../SnsDestinationForm/SnsDestinationForm';
import SQSDestinationForm from '../SqsDestinationForm/SqsDestinationForm';
import SlackDestinationForm from '../SlackDestinationForm';
import AsanaDestinationForm from '../AsanaDestinationForm';
import CustomWebhookDestinationForm from '../CustomWebhookDestinationForm';

interface DestinationFormSwitcherProps {
  initialValues: DestinationInput;
  onSubmit: (values: DestinationInput) => Promise<void> | void;
}

const DestinationFormSwitcher: React.FC<DestinationFormSwitcherProps> = ({
  initialValues,
  onSubmit,
}) => {
  // Normally we would want to perform a single `pick` operation per switch-case and not extend the
  // commonInitialValues that are defined here. Unfortunately, if you do deep picking (i.e. x.w.y)
  // on  lodash's pick, it messes typings and TS fails cause it thinks it doesn't have all the
  // fields it needs. We use `commonInitialValues` to satisfy this exact constraint that was set by
  // the `initialValues` prop of each form.
  const commonInitialValues = pick(initialValues, [
    'outputId',
    'displayName',
    'defaultForSeverity',
    'alertTypes',
  ]);

  switch (initialValues.outputType) {
    case DestinationTypeEnum.Pagerduty:
      return (
        <PagerDutyDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'pagerDuty.integrationKey'),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Github:
      return (
        <GithubDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, ['github.repoName', 'github.token']),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Jira:
      return (
        <JiraDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, [
              'jira.orgDomain',
              'jira.projectKey',
              'jira.userName',
              'jira.apiKey',
              'jira.assigneeId',
              'jira.issueType',
              'jira.labels',
            ]),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Opsgenie:
      return (
        <OpsgenieDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, [
              'opsgenie.apiKey',
              'opsgenie.serviceRegion',
            ]),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Msteams:
      return (
        <MicrosoftTeamsDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'msTeams.webhookURL'),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Sns:
      return (
        <SNSDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'sns.topicArn'),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Sqs:
      return (
        <SQSDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'sqs.queueUrl'),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Slack:
      return (
        <SlackDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'slack.webhookURL'),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Asana:
      return (
        <AsanaDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, [
              'asana.personalAccessToken',
              'asana.projectGids',
            ]),
          }}
          onSubmit={onSubmit}
        />
      );
    case DestinationTypeEnum.Customwebhook:
      return (
        <CustomWebhookDestinationForm
          initialValues={{
            ...commonInitialValues,
            outputConfig: pick(initialValues.outputConfig, 'customWebhook.webhookURL'),
          }}
          onSubmit={onSubmit}
        />
      );
    default:
      return null;
  }
};

export default DestinationFormSwitcher;
