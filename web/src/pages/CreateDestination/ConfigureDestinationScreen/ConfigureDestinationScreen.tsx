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
import { useSnackbar } from 'pouncejs';
import { DestinationConfigInput, DestinationTypeEnum } from 'Generated/schema';
import { BaseDestinationFormValues } from 'Components/forms/BaseDestinationForm';

import SNSDestinationForm from 'Components/forms/SnsDestinationForm';
import SQSDestinationForm from 'Components/forms/SqsDestinationForm';
import SlackDestinationForm from 'Components/forms/SlackDestinationForm';
import PagerDutyDestinationForm from 'Components/forms/PagerdutyDestinationForm';
import OpsgenieDestinationForm from 'Components/forms/OpsgenieDestinationForm';
import MicrosoftTeamsDestinationForm from 'Components/forms/MicrosoftTeamsDestinationForm';
import JiraDestinationForm from 'Components/forms/JiraDestinationForm';
import GithubDestinationForm from 'Components/forms/GithubDestinationForm';
import AsanaDestinationForm from 'Components/forms/AsanaDestinationForm';
import CustomWebhookDestinationForm from 'Components/forms/CustomWebhookDestinationForm';
import { capitalize, extractErrorMessage } from 'Helpers/utils';
import { useWizardContext, WizardPanelWrapper } from 'Components/Wizard';
import { useAddDestination } from './graphql/addDestination.generated';
import { WizardData } from '../CreateDestination';

const ConfigureDestinationScreen: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const {
    goToNextStep,
    data: { selectedDestinationType },
    updateData,
  } = useWizardContext<WizardData>();

  // If destination object doesn't exist, handleSubmit should call addDestination to create a new destination and use default initial values
  const [addDestination] = useAddDestination({
    onCompleted: data => {
      updateData({ destination: data.addDestination });
      goToNextStep();
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          "An unknown error occurred and we couldn't add your new destination",
      });
    },
  });

  // The typescript on `values` simply says that we expect to have DestinationFormValues with an
  // `outputType` that partially implements the DestinationConfigInput (we say partially since each
  // integration will add each own config). Ideally we would want to say "exactly 1". We can't
  // specify the exact one since `const` are not allowed to have generics and `useCallback` can only
  // be assigned to a const
  const handleSubmit = React.useCallback(
    async (values: BaseDestinationFormValues<Partial<DestinationConfigInput>>) => {
      const { displayName, defaultForSeverity, outputConfig } = values;
      await addDestination({
        variables: {
          input: {
            // form values that are present in all Destinations
            displayName,
            defaultForSeverity,

            // dynamic form values that depend on the selected destination
            outputType: selectedDestinationType,
            outputConfig,
          },
        },
        update: (cache, { data: { addDestination: newDestination } }) => {
          cache.modify('ROOT_QUERY', {
            destinations: (queryData, { toReference }) => {
              const addDestinationRef = toReference(newDestination);
              return queryData ? [addDestinationRef, ...queryData] : [addDestinationRef];
            },
          });
        },
      });
    },
    []
  );

  const commonInitialValues = {
    displayName: '',
    defaultForSeverity: [],
  };

  const renderFullDestinationForm = () => {
    switch (selectedDestinationType) {
      case DestinationTypeEnum.Pagerduty:
        return (
          <PagerDutyDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: { pagerDuty: { integrationKey: '' } },
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Github:
        return (
          <GithubDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: { github: { repoName: '', token: '' } },
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Jira:
        return (
          <JiraDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: {
                jira: {
                  orgDomain: '',
                  projectKey: '',
                  userName: '',
                  apiKey: '',
                  assigneeId: '',
                  issueType: null,
                },
              },
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Opsgenie:
        return (
          <OpsgenieDestinationForm
            initialValues={{ ...commonInitialValues, outputConfig: { opsgenie: { apiKey: '' } } }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Msteams:
        return (
          <MicrosoftTeamsDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: { msTeams: { webhookURL: '' } },
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Slack:
        return (
          <SlackDestinationForm
            initialValues={{ ...commonInitialValues, outputConfig: { slack: { webhookURL: '' } } }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Sns:
        return (
          <SNSDestinationForm
            initialValues={{ ...commonInitialValues, outputConfig: { sns: { topicArn: '' } } }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Sqs:
        return (
          <SQSDestinationForm
            initialValues={{ ...commonInitialValues, outputConfig: { sqs: { queueUrl: '' } } }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Asana:
        return (
          <AsanaDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: { asana: { personalAccessToken: '', projectGids: [] } },
            }}
            onSubmit={handleSubmit}
          />
        );
      case DestinationTypeEnum.Customwebhook:
        return (
          <CustomWebhookDestinationForm
            initialValues={{
              ...commonInitialValues,
              outputConfig: { customWebhook: { webhookURL: '' } },
            }}
            onSubmit={handleSubmit}
          />
        );
      default:
        return null;
    }
  };

  const destinationDisplayName = capitalize(
    selectedDestinationType === DestinationTypeEnum.Customwebhook
      ? 'Webhook'
      : selectedDestinationType
  );
  return (
    <React.Fragment>
      <WizardPanelWrapper.Heading
        title={`Configure Your ${destinationDisplayName} Destination`}
        subtitle="Fill out the form below to configure your Destination"
      />
      {renderFullDestinationForm()}
    </React.Fragment>
  );
};

export default React.memo(ConfigureDestinationScreen);
