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
import uniqBy from 'lodash/uniqBy';
import sortBy from 'lodash/sortBy';
import { Flex, Img, Text, Spinner, Box } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import { Destination } from 'Generated/schema';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';

const size = 18;

const getLogo = ({ outputType, outputId }) => {
  const { logo } = DESTINATIONS[outputType];
  return (
    <Img
      key={outputId}
      alt={`${outputType} logo`}
      src={logo}
      nativeWidth={size}
      nativeHeight={size}
      mr={2}
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
  if (loading) {
    return (
      <Box height={size}>
        <Spinner size="small" />
      </Box>
    );
  }

  // If component is verbose, we should render all destinations as row with the name of destination displayed
  if (verbose) {
    return (
      <RRLink to={urls.settings.destinations.list()}>
        {destinations.map(destination => (
          <Flex key={destination.outputId} align="center" mb={2}>
            {getLogo(destination)}
            {destination.displayName}
          </Flex>
        ))}
      </RRLink>
    );
  }

  // Else we should render destinations based if they are unique, in a column without the display name
  // Identifying unique destinations by outputType
  const uniqueDestinations = sortBy(uniqBy(destinations, 'outputType'), d => d.outputType);

  /*
   * Using unique destinations here so we dont render multiple logo of the same type.
   *  i.e. If an alerts has only 2 different slack destinations will render Slack logo once
   */
  if (destinations.length - uniqueDestinations.length > 0) {
    // Limiting rendered destinations logos to 3
    const renderedDestinations = uniqueDestinations.slice(0, limit);
    // Showcasing how many additional destinations exist for this alert
    const numberOfExtraDestinations = destinations.length - renderedDestinations.length;
    return (
      <Flex align="center" minWidth={85} spacing={2}>
        {renderedDestinations.map(getLogo)}
        <Text textAlign="center">+ {numberOfExtraDestinations}</Text>
      </Flex>
    );
  }

  return (
    <Flex align="center" minWidth={85} spacing={2}>
      {destinations.length ? (
        destinations.map(getLogo)
      ) : (
        <Text fontSize="small">Not configured</Text>
      )}
    </Flex>
  );
};

export default RelatedDestinations;
