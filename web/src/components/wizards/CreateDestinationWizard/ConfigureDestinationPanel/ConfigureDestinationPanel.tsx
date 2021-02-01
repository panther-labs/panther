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
import {
  AlertTypesEnum,
  DestinationConfigInput,
  DestinationInput,
  DestinationTypeEnum,
  OpsgenieServiceRegionEnum,
} from 'Generated/schema';
import { BaseDestinationFormValues } from 'Components/forms/BaseDestinationForm';
import { DESTINATIONS } from 'Source/constants';
import DestinationFormSwitcher from 'Components/forms/DestinationFormSwitcher';
import { capitalize, extractErrorMessage } from 'Helpers/utils';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useAddDestination } from './graphql/addDestination.generated';
import { WizardData } from '../CreateDestinationWizard';

const initialValues: Omit<DestinationInput, 'outputType'> = {
  displayName: '',
  defaultForSeverity: [],
  alertTypes: [AlertTypesEnum.Rule, AlertTypesEnum.RuleError, AlertTypesEnum.Policy],
  outputConfig: {
    pagerDuty: { integrationKey: '' },
    github: { repoName: '', token: '' },
    jira: {
      orgDomain: '',
      projectKey: '',
      userName: '',
      apiKey: '',
      assigneeId: '',
      issueType: '',
      labels: [],
    },
    opsgenie: { apiKey: '', serviceRegion: OpsgenieServiceRegionEnum.Us },
    slack: { webhookURL: '' },
    msTeams: { webhookURL: '' },
    sns: { topicArn: '' },
    sqs: { queueUrl: '' },
    asana: { personalAccessToken: '', projectGids: [] },
    customWebhook: {
      webhookURL: '',
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
      trackEvent({ event: EventEnum.AddedDestination, src: SrcEnum.Destinations, ctx: selectedDestinationType }); // prettier-ignore
      goToNextStep();
    },
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedToAddDestination, src: SrcEnum.Destinations, ctx: selectedDestinationType }); // prettier-ignore
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
      const { displayName, defaultForSeverity, alertTypes, outputConfig } = values;
      await addDestination({
        variables: {
          input: {
            // form values that are present in all Destinations
            displayName,
            defaultForSeverity,
            alertTypes,

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
    <Box maxWidth={800} mx="auto">
      <WizardPanel.Heading
        title={`Configure Your ${destinationDisplayName} Destination`}
        subtitle="Fill out the form below to configure your Destination"
        logo={DESTINATIONS[selectedDestinationType].logo}
      />
      <DestinationFormSwitcher
        initialValues={{ ...initialValues, outputType: selectedDestinationType }}
        onSubmit={handleSubmit}
      />
    </Box>
  );
};

export default React.memo(ConfigureDestinationPanel);
