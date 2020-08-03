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
import { Box, Flex } from 'pouncejs';
import TimeSeriesChart from 'Components/charts/TimeSeriesChart';
import { capitalize } from 'Helpers/utils';

interface AlertsBySeverityProps {
  alerts: any;
}

const AlertsBySeverity: React.FC<AlertsBySeverityProps> = ({ alerts }) => {
  const transformedSeries = alerts.series.map(serie => ({
    ...serie,
    label: capitalize(serie.label.toLowerCase()),
  }));

  return (
    <Box mx={2} px={4} py={4} height={200} width="80%" backgroundColor="navyblue-500">
      <Flex
        data-testid="alert-by-severity-chart"
        height="100%"
        pt={4}
        px={4}
        backgroundColor="navyblue-500"
      >
        <TimeSeriesChart data={{ ...alerts, series: transformedSeries }} />
      </Flex>
    </Box>
  );
};

export default React.memo(AlertsBySeverity);
