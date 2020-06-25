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
import { Box, Flex, Heading, SideSheet, SideSheetProps, Text } from 'pouncejs';
import { DESTINATIONS } from 'Source/constants';
import DestinationCard from 'Components/DestinationCard';
import useSidesheet from 'Hooks/useSidesheet';

import { SIDESHEETS } from 'Components/utils/Sidesheet';

const destinationConfigs = Object.values(DESTINATIONS);

export const SelectDestinationSidesheet: React.FC<SideSheetProps> = props => {
  const { showSidesheet } = useSidesheet();

  return (
    <SideSheet
      aria-labelledby="sidesheet-title"
      aria-describedby="sidesheet-description"
      {...props}
    >
      <Box width={465}>
        <Box mb={8}>
          <Heading mb={8} id="sidesheet-title">
            Select an Alert Destination
          </Heading>
          <Text size="large" color="gray-300" id="sidesheet-description">
            Add a new destination below to deliver alerts to a specific application for further
            triage
          </Text>
        </Box>
        <Flex justify="space-between" flexWrap="wrap">
          {destinationConfigs.map(destinationConfig => (
            <Box width={224} mb={4} key={destinationConfig.title}>
              <DestinationCard
                logo={destinationConfig.logo}
                title={destinationConfig.title}
                onClick={() =>
                  showSidesheet({
                    sidesheet: SIDESHEETS.ADD_DESTINATION,
                    props: {
                      destinationType: destinationConfig.type,
                    },
                  })
                }
              />
            </Box>
          ))}
        </Flex>
      </Box>
    </SideSheet>
  );
};

export default SelectDestinationSidesheet;
