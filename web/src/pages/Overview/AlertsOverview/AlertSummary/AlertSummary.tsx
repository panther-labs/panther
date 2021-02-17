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
import { Box, Flex, Heading } from 'pouncejs';
import { slugify } from 'Helpers/utils';
import NoDataFound from 'Components/NoDataFound';
import { SingleValue } from 'Generated/schema';
import DifferenceText from './DifferenceText';
import PercentageBarChart from './PercentageBarChart';

interface AlertSummaryProps {
  data: SingleValue[];
}

const AlertSummary: React.FC<AlertSummaryProps> = ({ data }) => {
  if (!data) {
    return <NoDataFound title="No alerts are present in the system" />;
  }
  const alertsCurrentPeriod = data.find(d => d.label === 'Current Period').value;
  const alertPreviousPeriod = data.find(d => d.label === 'Previous Period').value;

  const diff = alertPreviousPeriod - alertsCurrentPeriod;

  const alertsChartData = data.map(d => ({
    title: d.label,
    value: d.value,
    color: d.label === 'Current Period' ? ('red-300' as const) : ('navyblue-200' as const),
  }));

  return (
    <Box>
      <Flex direction="column" align="center" justify="space-between">
        <Box width="100%" textAlign="center">
          <Box id={slugify('Total Alerts')} fontWeight="bold" fontSize="medium">
            Total Alerts
          </Box>
          <Flex
            direction="column"
            align="center"
            justify="center"
            borderRadius="medium"
            my={3}
            pb={2}
            backgroundColor="navyblue-600"
          >
            <Heading
              as="h2"
              size="3x-large"
              color="red-300"
              fontWeight="bold"
              aria-describedby={slugify('title')}
            >
              {alertsCurrentPeriod}
            </Heading>
            <DifferenceText diff={diff} />
          </Flex>
        </Box>
        <Box width="100%">
          <PercentageBarChart data={alertsChartData} barHeight={24} />
        </Box>
      </Flex>
    </Box>
  );
};

export default AlertSummary;
