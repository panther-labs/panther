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
import { DESTINATIONS } from 'Source/constants';
import { DestinationConfigInput, DestinationTypeEnum } from 'Generated/schema';
import { BaseDestinationFormValues } from 'Components/forms/BaseDestinationForm';
import { capitalize, extractErrorMessage } from 'Helpers/utils';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import DestinationFormSwitcher from 'Components/forms/DestinationFormSwitcher';
import useRouter from 'Hooks/useRouter';
import { useUpdateDestination } from './graphql/updateDestination.generated';
import { useGetDestinationDetails } from './graphql/getDestinationDetails.generated';
import { WizardData } from '../EditDestination';
import Skeleton from './Skeleton';

const ConfigureDestinationPanel: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match: { params: { id } } } = useRouter<{ id: string }>(); // prettier-ignore
  const { updateData, goToNextStep } = useWizardContext<WizardData>();

  // If destination object exist, handleSubmit should call updateDestination and use attributes from the destination object for form initial values
  const { data: destinationData, loading } = useGetDestinationDetails({
    variables: {
      id,
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'An unknown error has occurred while trying to update your destination',
      });
    },
  });

  // If destination object exist, handleSubmit should call updateDestination and use attributes from the destination object for form initial values
  const [updateDestination] = useUpdateDestination({
    onCompleted: data => {
      updateData({ destination: data.updateDestination });
      goToNextStep();
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'An unknown error has occurred while trying to update your destination',
      });
    },
  });

  const destination = destinationData?.destination;
  const handleSubmit = React.useCallback(
    async (values: BaseDestinationFormValues<Partial<DestinationConfigInput>>) => {
      const { displayName, defaultForSeverity, alertTypes, outputConfig } = values;

      await updateDestination({
        variables: {
          input: {
            // static form values that are present on all Destinations
            displayName,
            defaultForSeverity,
            alertTypes,

            // needed fields from the server in order to update the selected destination
            outputId: destination.outputId,
            outputType: destination.outputType,

            // dynamic form values that depend on the selected destination
            outputConfig,
          },
        },
      });
    },
    [destination]
  );

  if (loading) {
    return <Skeleton />;
  }

  const destinationDisplayName = capitalize(
    destination.outputType === DestinationTypeEnum.Customwebhook
      ? 'Webhook'
      : destination.outputType
  );

  return (
    <Box maxWidth={800} mx="auto">
      <WizardPanel.Heading
        title={`Update Your ${destinationDisplayName} Destination`}
        subtitle="Make changes to the form below in order to update your Destination"
        logo={DESTINATIONS[destination.outputType].logo}
      />
      <DestinationFormSwitcher initialValues={destination} onSubmit={handleSubmit} />
    </Box>
  );
};

export default React.memo(ConfigureDestinationPanel);
