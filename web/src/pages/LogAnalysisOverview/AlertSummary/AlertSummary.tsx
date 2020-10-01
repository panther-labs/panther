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
import { Box, Flex, Heading, Text } from 'pouncejs';
import { slugify } from 'Helpers/utils';
import { SingleValue } from 'Generated/schema';
import DifferenceText from './DifferenceText';

interface AlertSummaryProps {
  data: SingleValue[];
}

const getText = diff => {
  if (diff === 0) {
    return 'No change';
  }
  if (diff > 0) {
    return 'Decreased by';
  }
  return 'Increased by';
};

const AlertSummary: React.FC<AlertSummaryProps> = ({ data }) => {
  const alertsCurrentPeriod = data.find(d => d.label === 'Current Period').value;
  const alertPreviousPeriod = data.find(d => d.label === 'Previous Period').value;

  const diff = alertPreviousPeriod - alertsCurrentPeriod;
  return (
    <Flex
      direction="column"
      backgroundColor="navyblue-500"
      width="25%"
      align="center"
      justify="space-between"
      p={0}
      pt={10}
      pb={4}
    >
      <Box textAlign="center">
        <Heading
          as="h2"
          size="3x-large"
          color="red-400"
          fontWeight="bold"
          aria-describedby={slugify('title')}
        >
          {alertsCurrentPeriod}
        </Heading>
        <Box id={slugify('Total Alerts')} fontWeight="bold" fontSize="medium">
          Total Alerts
        </Box>
      </Box>
      <Box width="100%" pl={4} pr={6}>
        <Flex mt={4} minWidth="80%" justify="space-between">
          <Box>
            <Text fontSize="small" color="gray-300">
              Last period
            </Text>
            <Text fontSize="small" pt={1} color="gray-300">
              Current period
            </Text>
            <Text fontSize="small" pt={4}>
              {getText(diff)}
            </Text>
          </Box>
          <Box textAlign="end">
            <Text color="gray-300">{alertPreviousPeriod}</Text>

            <Text color="gray-300">{alertsCurrentPeriod}</Text>
            <DifferenceText diff={diff} />
          </Box>
        </Flex>
      </Box>
    </Flex>
  );
};

export default AlertSummary;
