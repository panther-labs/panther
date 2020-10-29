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
import groupBy from 'lodash/groupBy';
import { DeliveryResponseFull } from 'Source/graphql/fragments/DeliveryResponseFull.generated';
import orderBy from 'lodash/orderBy';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import useAlertDestinations from 'Hooks/useAlertDestinations';

interface UseAlertDestinationsDeliverySuccessProps {
  alert: AlertSummaryFull;
}

interface UseAlertDestinationsDeliverySuccessResponse {
  allDestinationDeliveredSuccessfully: boolean;
  enhancedAndSortedAlertDeliveries: any[];
  loading: boolean;
}

const useAlertDestinationsDeliverySuccess = ({
  alert,
}: UseAlertDestinationsDeliverySuccessProps): UseAlertDestinationsDeliverySuccessResponse => {
  const { deliveryResponses } = alert;
  // FIXME: `alertDestinations` should be part of Alert & coming directly from GraphQL
  //  Someday...
  const { alertDestinations, loading } = useAlertDestinations({ alert });
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

  const allDestinationDeliveredSuccessfully = React.useMemo(() => {
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

  return React.useMemo(
    () => ({
      allDestinationDeliveredSuccessfully,
      enhancedAndSortedAlertDeliveries,
      loading,
    }),
    [allDestinationDeliveredSuccessfully, enhancedAndSortedAlertDeliveries, loading]
  );
};

export default useAlertDestinationsDeliverySuccess;
