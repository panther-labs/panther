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
import { Flex, Img, Text, Spinner } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import GenericItemCard from 'Components/GenericItemCard';
import { AlertSummary } from 'Generated/schema';
import { useListDestinations } from 'Pages/AlertDetails';
import useAlertDestinations from 'Hooks/useAlertDestinations';

const getLogo = ({ outputType, outputId }) => {
  const { logo } = DESTINATIONS[outputType];
  return <GenericItemCard.Logo key={outputId} src={logo} />;
};

interface AlertDestinationsSectionProps {
  alert: AlertSummary;
  verbose?: boolean;
}
const AlertDestinationsSection: React.FC<AlertDestinationsSectionProps> = ({
  alert,
  verbose = false,
}) => {
  const { data: destinationData, loading } = useListDestinations();

  const { alertDestinations } = useAlertDestinations({
    destinations: destinationData?.destinations,
    alert,
  });

  if (loading) {
    return <Spinner size="small" mr={2} />;
  }

  // If component is verbose, we should render all destinations as row with the name of destination displayed
  if (verbose) {
    return (
      <React.Fragment>
        {alertDestinations.map(destination => (
          <Flex key={destination.outputId} align="center" mb={2}>
            <Img
              alt={`${destination.outputType} logo`}
              src={DESTINATIONS[destination.outputType].logo}
              nativeWidth={18}
              nativeHeight={18}
              mr={2}
            />
            {destination.displayName}
          </Flex>
        ))}
      </React.Fragment>
    );
  }

  // Else we should render destinations based if they are unique, in a column without the display name
  // Identifying unique destinations by outputType
  const uniqueDestinations = sortBy(uniqBy(alertDestinations, 'outputType'), d => d.outputType);

  /*
   * Using unique destinations here so we dont render multiple logo of the same type.
   *  i.e. If an alerts has only 2 different slack destinations will render Slack logo once
   */
  if (alertDestinations.length - uniqueDestinations.length > 0) {
    // Limiting rendered destinations logos to 3
    const renderedDestinations = uniqueDestinations.slice(0, 3);
    // Showcasing how many additional destinations exist for this alert
    const numberOfExtraDestinations = alertDestinations.length - renderedDestinations.length;
    return (
      <Flex align="center" spacing={2} mt={1}>
        {renderedDestinations.map(getLogo)}
        <Text textAlign="center">{`+ ${numberOfExtraDestinations}`}</Text>
      </Flex>
    );
  }

  return (
    <Flex align="center" spacing={2} mt={1}>
      {alertDestinations.map(getLogo)}
    </Flex>
  );
};

export default AlertDestinationsSection;
