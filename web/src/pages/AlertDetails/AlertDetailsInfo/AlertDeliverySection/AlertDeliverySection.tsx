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
import { Text, Flex, Icon, AbstractButton, Box, Collapse, useSnackbar } from 'pouncejs';
import { AlertDetails, ListDestinations } from 'Pages/AlertDetails';
import last from 'lodash/last';
import { DeliveryResponseFull } from 'Source/graphql/fragments/DeliveryResponseFull.generated';
import AlertDeliveryTable from './AlertDeliveryTable';
import { useRetryAlertDelivery } from './graphql/retryAlertDelivery.generated';

interface AlertDeliverySectionProps {
  alert: AlertDetails['alert'];
  alertDestinations: ListDestinations['destinations'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({
  alert,
  alertDestinations,
}) => {
  const [isHistoryVisible, setHistoryVisibility] = React.useState(false);

  const { pushSnackbar } = useSnackbar();
  const [retryAlertDelivery] = useRetryAlertDelivery({
    update: (cache, { data }) => {
      const dataId = cache.identify({
        __typename: 'AlertDetails',
        alertId: data.deliverAlert.alertId,
      });

      cache.modify(dataId, {
        deliveryResponses: () => data.deliverAlert.deliveryResponses,
      });
    },
    onError: () => pushSnackbar({ variant: 'error', title: 'Failed to deliver alert' }),
    onCompleted: data => {
      const attemptedDelivery = last(data.deliverAlert.deliveryResponses);
      if (attemptedDelivery.success) {
        pushSnackbar({ variant: 'success', title: 'Successfully delivered alert' });
      } else {
        pushSnackbar({ variant: 'error', title: 'Failed to deliver alert' });
      }
    },
  });

  const onAlertDeliveryRetry = React.useCallback(
    (outputId: string) => {
      retryAlertDelivery({
        variables: {
          input: {
            alertId: alert.alertId,
            outputIds: [outputId],
          },
        },
      });
    },
    [retryAlertDelivery, alert]
  );

  // FIXME: `alertDestinations` should be part of Alert & coming directly from GraphQL
  //  Someday...
  const { deliveryResponses } = alert;
  const enhancedAndSortedAlertDeliveries = React.useMemo(() => {
    return deliveryResponses
      .reduce((acc, dr) => {
        const dest = alertDestinations.find(d => d.outputId === dr.outputId);
        if (dest) {
          acc.push({
            ...dr,
            ...dest,
          });
        }
        return acc;
      }, [])
      .reverse();
  }, [deliveryResponses, alertDestinations]);

  if (!deliveryResponses.length || !enhancedAndSortedAlertDeliveries.length) {
    return (
      <Flex align="warning" spacing={4}>
        <Icon type="info" size="medium" color="blue-400" />
        <Text fontWeight="medium">Delivery information could not be retrieved</Text>
      </Flex>
    );
  }
  // Need to determine success for each destination (group by destination).
  const deliveryStatusByDestination = React.useMemo(() => {
    return enhancedAndSortedAlertDeliveries.reduce((acc, dest: DeliveryResponseFull) => {
      if (!acc[dest.outputId]) {
        acc[dest.outputId] = [dest];
        return acc;
      }
      acc[dest.outputId] = [...acc[dest.outputId], dest];
      return acc;
    }, {});
  }, [enhancedAndSortedAlertDeliveries]);

  // Next, we sort each status inside each group by dispatchedAt and determine if it was successful
  // This is all or nothing. The most recent status for ALL destinations should be successful, otherwise
  // notify the user of a failure.
  const allDestinationDeliveryStatuesSuccessful = React.useMemo(() => {
    return Object.values(deliveryStatusByDestination).every((dest: Array<DeliveryResponseFull>) => {
      // We cant convert to date and compare because it would truncate
      // dispatchedAt to milliseconds, but they're often dispatched within
      // a few nano seconds. Therefore, we define a comparator on strings
      const sorted = dest.sort((a, b) => {
        if (a.dispatchedAt > b.dispatchedAt) {
          return -1;
        }
        if (b.dispatchedAt < a.dispatchedAt) {
          return 1;
        }
        return 0;
      });
      return sorted[0].success;
    });
  }, [deliveryStatusByDestination]);

  return (
    <Box>
      <Flex justify="space-between">
        {allDestinationDeliveryStatuesSuccessful ? (
          <Flex align="center" spacing={4}>
            <Icon type="check-circle" size="medium" color="green-400" />
            <Text fontWeight="medium">Alert was delivered successfully</Text>
          </Flex>
        ) : (
          <Flex align="center" spacing={4}>
            <Icon type="alert-circle" size="medium" color="red-300" />
            <Text fontWeight="medium" color="red-300">
              Alert delivery failed
            </Text>
          </Flex>
        )}
        <AbstractButton
          fontSize="medium"
          color="teal-400"
          _hover={{ color: 'teal-300' }}
          onClick={() => setHistoryVisibility(!isHistoryVisible)}
        >
          {isHistoryVisible ? 'Hide History' : 'Show History'}
        </AbstractButton>
      </Flex>
      <Collapse open={isHistoryVisible}>
        <Box backgroundColor="navyblue-400" mt={6}>
          <AlertDeliveryTable
            alertDeliveries={enhancedAndSortedAlertDeliveries}
            onAlertDeliveryRetry={onAlertDeliveryRetry}
          />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
