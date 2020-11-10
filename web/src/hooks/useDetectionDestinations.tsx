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
import { Destination, RuleDetails, RuleSummary } from 'Generated/schema';
import { useListDestinations } from 'Source/graphql/queries';

interface UseDetectionDestinationsProps {
  rule: RuleSummary | RuleDetails;
}

interface UseDetectionDestinationsResponse {
  loading: boolean;
  detectionDestinations: Pick<
    Destination,
    'outputType' | 'outputId' | 'displayName' | 'defaultForSeverity'
  >[];
}

const useDetectionDestinations = ({
  rule,
}: UseDetectionDestinationsProps): UseDetectionDestinationsResponse => {
  const { data: destinations, loading } = useListDestinations();

  const detectionDestinations = React.useMemo(() => {
    if (!rule || !destinations?.destinations) {
      return [];
    }

    if (rule.outputIds.length) {
      return rule.outputIds.map(outputId => {
        return destinations.destinations.find(dest => dest.outputId === outputId);
      });
    }
    return destinations.destinations.filter(dest => {
      return dest.defaultForSeverity.some(sev => sev === rule.severity);
    });
  }, [rule, destinations]);

  return React.useMemo(
    () => ({
      detectionDestinations,
      loading,
    }),
    [detectionDestinations, loading]
  );
};

export default useDetectionDestinations;
