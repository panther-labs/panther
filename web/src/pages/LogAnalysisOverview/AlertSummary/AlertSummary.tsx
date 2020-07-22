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

const AlertSummary: React.FC<AlertSummaryProps> = ({ data }) => {
  const alertsCurrentPeriod = data.find(d => d.label === 'Current Period').value;
  const alertPreviousPeriod = data.find(d => d.label === 'Previous Period').value;

  const diff = alertPreviousPeriod - alertsCurrentPeriod;
  return (
    <Flex
      direction="column"
      backgroundColor="navyblue-700"
      width="20%"
      align="center"
      justify="center"
      p={0}
    >
      <Heading
        as="h2"
        size="3x-large"
        color="red-700"
        fontWeight="bold"
        aria-describedby={slugify('title')}
      >
        {alertsCurrentPeriod}
      </Heading>
      <Box id={slugify('Total Alerts')} fontWeight="bold" fontSize="medium">
        Total Alerts
      </Box>
      <Flex my={2} width="60%" justify="space-between">
        <Text fontSize="small" color="gray-300">
          Last period
        </Text>
        <Text fontSize="small" color="gray-300">
          {alertPreviousPeriod}
        </Text>
      </Flex>
      <Flex width="60%" justify="space-between">
        <DifferenceText diff={diff} />
      </Flex>
    </Flex>
  );
};

export default AlertSummary;
