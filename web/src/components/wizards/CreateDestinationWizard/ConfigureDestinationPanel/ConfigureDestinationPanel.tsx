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
import { Box, useSnackbar } from 'pouncejs';
import { DestinationConfigInput, DestinationInput, DestinationTypeEnum } from 'Generated/schema';
import { BaseDestinationFormValues } from 'Components/forms/BaseDestinationForm';
import DestinationFormSwitcher from 'Components/forms/DestinationFormSwitcher';
import { capitalize, extractErrorMessage } from 'Helpers/utils';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { useAddDestination } from './graphql/addDestination.generated';
import { WizardData } from '../CreateDestinationWizard';

const initialValues: Omit<DestinationInput, 'outputType'> = {
  displayName: '',
  defaultForSeverity: [],
  outputConfig: {
    pagerDuty: { integrationKey: null },
    github: { repoName: '', token: null },
    jira: {
      orgDomain: '',
      projectKey: '',
      userName: '',
      apiKey: null,
      assigneeId: '',
      issueType: null,
    },
    opsgenie: { apiKey: null },
    slack: { webhookURL: null },
    msTeams: { webhookURL: null },
    sns: { topicArn: '' },
    sqs: { queueUrl: '' },
    asana: { personalAccessToken: null, projectGids: [] },
    customWebhook: {
      webhookURL: null,
    },
  },
};

const ConfigureDestinationPanel: React.FC = () => {
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

  const destinationDisplayName = capitalize(
    selectedDestinationType === DestinationTypeEnum.Customwebhook
      ? 'Webhook'
      : selectedDestinationType
  );
  return (
    <Box maxWidth={700} mx="auto">
      <WizardPanel.Heading
        title={`Configure Your ${destinationDisplayName} Destination`}
        subtitle="Fill out the form below to configure your Destination"
      />
      <DestinationFormSwitcher
        initialValues={{ ...initialValues, outputType: selectedDestinationType }}
        onSubmit={handleSubmit}
      />
    </Box>
  );
};

export default React.memo(ConfigureDestinationPanel);
