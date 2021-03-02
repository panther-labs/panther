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
import sortBy from 'lodash/sortBy';
import { Flex, Img, Text, Spinner, Box } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import { Destination } from 'Generated/schema';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import LimitItemDisplay from 'Components/LimitItemDisplay';

const LOGO_SIZE = 18;

const getLogo = ({
  outputType,
  outputId,
  displayName,
}: Pick<Destination, 'outputType' | 'outputId' | 'displayName'>) => {
  const { logo } = DESTINATIONS[outputType];
  return (
    <Img
      key={outputId}
      alt={`${outputType} logo`}
      src={logo}
      title={displayName}
      nativeWidth={LOGO_SIZE}
      nativeHeight={LOGO_SIZE}
    />
  );
};

interface RelatedDestinationsSectionProps {
  destinations: Pick<Destination, 'outputType' | 'outputId' | 'displayName'>[];
  loading: boolean;
  verbose?: boolean;
  limit?: number;
}
const RelatedDestinations: React.FC<RelatedDestinationsSectionProps> = ({
  destinations,
  loading,
  verbose = false,
  limit = 3,
}) => {
  const sortedDestinations = React.useMemo(() => sortBy(destinations, d => d.outputType), [
    destinations,
  ]);

  if (loading) {
    return (
      <Box height={LOGO_SIZE}>
        <Spinner size="small" />
      </Box>
    );
  }

  if (!sortedDestinations.length) {
    return (
      <Text fontSize="small" opacity={0.3}>
        Not configured
      </Text>
    );
  }

  // If component is verbose, we should render all destinations as row with the name of destination displayed
  if (verbose) {
    return (
      <RRLink to={urls.integrations.destinations.list()}>
        <Flex inline direction="column" spacing={2}>
          <LimitItemDisplay limit={limit}>
            {sortedDestinations.map(destination => (
              <Flex key={destination.outputId} align="center" spacing={2}>
                {getLogo(destination)}
                <Box as="span">{destination.displayName}</Box>
              </Flex>
            ))}
          </LimitItemDisplay>
        </Flex>
      </RRLink>
    );
  }

  return (
    <Flex align="center" spacing={2}>
      <LimitItemDisplay limit={limit}>{sortedDestinations.map(getLogo)}</LimitItemDisplay>
    </Flex>
  );
};

export default React.memo(RelatedDestinations);
