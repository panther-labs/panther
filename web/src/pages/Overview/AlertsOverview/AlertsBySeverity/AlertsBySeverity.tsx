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
import { LongSeriesData } from 'Generated/schema';
import NoDataFound from 'Components/NoDataFound';

interface AlertsBySeverityProps {
  alerts: LongSeriesData;
}

const AlertsBySeverity: React.FC<AlertsBySeverityProps> = ({ alerts: { series, timestamps } }) => {
  const timeseriesData = React.useMemo(
    () => ({
      timestamps,
      series: series.map(serie => ({ ...serie, label: capitalize(serie.label.toLowerCase()) })),
    }),
    [series, timestamps]
  );

  if (!timeseriesData.series.length) {
    return <NoDataFound title="No alerts are present in the system" />;
  }

  return (
    <Box ml={2} py={6} pl={6} width="80%" backgroundColor="navyblue-500">
      <Flex data-testid="alert-by-severity-chart" height="100%" position="relative">
        <TimeSeriesChart data={timeseriesData} zoomable title="Alert Severity" />
      </Flex>
    </Box>
  );
};

export default React.memo(AlertsBySeverity);
