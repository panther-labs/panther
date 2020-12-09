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
import { useListDestinationsAndDefaults } from 'Pages/ListDestinations';
import { extractErrorMessage } from 'Helpers/utils';
import { useSnackbar } from 'pouncejs';

const useListAvailableDestinations = ({ outputIds }) => {
  const { pushSnackbar } = useSnackbar();

  const { error, data, loading } = useListDestinationsAndDefaults({
    onError: err =>
      pushSnackbar({
        variant: 'error',
        title: 'Could not fetch your destinations',
        description: extractErrorMessage(err),
      }),
  });

  // All destinations
  const destinations = data?.destinations || [];

  // Create a Map from id => display name
  const mapIdsToDisplayNames = new Map<string, string>();
  destinations.forEach(({ outputId, displayName }) =>
    mapIdsToDisplayNames.set(outputId, displayName)
  );

  // Lookup an ID and get the corresponding display name
  const destinationIdToDisplayName = (outputId: string) =>
    mapIdsToDisplayNames.has(outputId) ? mapIdsToDisplayNames.get(outputId) : outputId;

  // Create an array of just the Ids
  const destinationOutputIds = destinations.map(({ outputId }) => outputId);

  // Computes the intersection of two arrays O(m + n)
  const findIntersection = (listA: string[], listB: string[]) =>
    listA.filter((set => (outputId: string) => set.has(outputId))(new Set(listB)));

  // Create an array of valid outputIds
  // The user could have deleted a destination that was assigned to a policy/rule
  // which needs to be filtered out and not shown to the user. The data is not
  // overwritten (cleaned) until the user updates the respective field; however, there is
  // no side-effects of having an invalid ID stored in the backend as it is simply
  // ignored.
  const validOutputIds = findIntersection(destinationOutputIds, outputIds);

  // Flag to inform that the field should be disabled
  const disabled = error || (!loading && !destinationOutputIds.length);

  return React.useMemo(
    () => ({
      error,
      destinations,
      destinationOutputIds,
      validOutputIds,
      loading,
      destinationIdToDisplayName,
      disabled,
    }),
    [
      error,
      destinations,
      destinationOutputIds,
      validOutputIds,
      loading,
      destinationIdToDisplayName,
      disabled,
    ]
  );
};

export default useListAvailableDestinations;
