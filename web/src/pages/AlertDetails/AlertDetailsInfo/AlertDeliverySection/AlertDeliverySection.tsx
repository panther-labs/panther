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
import groupBy from 'lodash/groupBy';
import orderBy from 'lodash/orderBy';
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
  const [retryAlertDelivery, { loading }] = useRetryAlertDelivery({
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
        <Text fontWeight="medium">No delivery information could be found for this alert</Text>
      </Flex>
    );
  }

  const allDestinationDeliveryStatuesSuccessful = React.useMemo(() => {
    // Need to determine success for each destination (group by destination).
    const deliveryStatusByDestination = groupBy(
      enhancedAndSortedAlertDeliveries,
      (d: DeliveryResponseFull) => d.outputId
    );

    // Next, we sort each status inside each group by dispatchedAt and determine if it was successful
    // This is all or nothing. The most recent status for ALL destinations should be successful, otherwise
    // notify the user of a failure.
    return Object.values(deliveryStatusByDestination).every((dest: Array<DeliveryResponseFull>) => {
      // We cant convert to date and compare because it would truncate
      // dispatchedAt to milliseconds, but they're often dispatched within
      // a few nano seconds. Therefore, we compare on strings.
      const sorted = orderBy(dest, ['dispatchedAt'], ['desc']);
      // Now that we've sorted the statues, the most recent status
      // should indicate success or failure to the user.
      return sorted[0].success;
    });
  }, [enhancedAndSortedAlertDeliveries]);

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
            isResending={loading}
          />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
