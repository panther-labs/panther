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
import {
  Dropdown,
  DropdownButton,
  DropdownItem,
  DropdownMenu,
  DropdownLink,
  useSnackbar,
  Text,
} from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import GenericItemCard from 'Components/GenericItemCard';
import urls from 'Source/urls';
import { useSendTestAlertLazyQuery } from 'Source/graphql/queries';
import { extractErrorMessage } from 'Helpers/utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';

interface DestinationCardOptionsProps {
  destination: DestinationFull;
}

const DestinationCardOptions: React.FC<DestinationCardOptionsProps> = ({ destination }) => {
  const { showModal } = useModal();
  const { pushSnackbar } = useSnackbar();

  const [sendTestAlert] = useSendTestAlertLazyQuery({
    fetchPolicy: 'network-only', // Don't use cache
    variables: {
      input: {
        outputIds: [destination.outputId],
      },
    },
    // Failed deliveries will also trigger onCompleted as we don't return exceptions
    onCompleted: data => {
      data.sendTestAlert.forEach(sendTestAlertResp => {
        const { success, statusCode, message } = sendTestAlertResp;
        if (success === true) {
          trackEvent({ event: EventEnum.TestedDestinationSuccessfully, src: SrcEnum.Destinations, ctx: destination.outputType }) // prettier-ignore
          pushSnackbar({
            variant: 'success',
            title: `Successfully sent test alert for: ${destination.displayName}`,
          });
        } else {
          trackEvent({ event: EventEnum.TestedDestinationFailure, src: SrcEnum.Destinations, ctx: destination.outputType }) // prettier-ignore
          pushSnackbar({
            variant: 'error',
            title: `Failed to send a test alert with status ${statusCode}: ${destination.displayName}`,
            description: [
              <Text key={destination.outputId} maxWidth={540} wordBreak="break-word">
                {message}
              </Text>,
            ],
          });
        }
      });
    },
    // This will be fired if there was a network issue or other unknown internal exception
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedDestinationTest, src: SrcEnum.Destinations, ctx: destination.outputType}) // prettier-ignore
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(error) || `Failed to attempt sending a test alert.`,
      });
    },
  });

  const handleTestAlertClick = React.useCallback(() => {
    sendTestAlert();
  }, []);

  return (
    <Dropdown>
      <DropdownButton as={GenericItemCard.OptionsButton} />
      <DropdownMenu>
        <DropdownItem onSelect={handleTestAlertClick}>Send Test Alert</DropdownItem>
        <DropdownLink as={RRLink} to={urls.integrations.destinations.edit(destination.outputId)}>
          Edit
        </DropdownLink>
        <DropdownItem
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_DESTINATION,
              props: { destination },
            })
          }
        >
          Delete
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default React.memo(DestinationCardOptions);
