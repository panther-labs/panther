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
import { Flex } from 'pouncejs';
import TimeSeriesChart from 'Components/charts/TimeSeriesChart';
import { FloatSeriesData } from 'Generated/schema';

interface EventsByLatencyProps {
  events: FloatSeriesData;
}

const EventsByLatency: React.FC<EventsByLatencyProps> = ({ events: { timestamps, series } }) => {
  // Transforming milliseconds to seconds
  const timeseriesData = React.useMemo(
    () => ({
      timestamps,
      series: series.map(serie => ({ ...serie, values: serie.values.map(value => value / 1000) })),
    }),
    [timestamps, series]
  );
  return (
    <Flex data-testid="events-by-latency" height="100%" position="relative">
      <TimeSeriesChart data={timeseriesData} units="sec" zoomable />
    </Flex>
  );
};

export default React.memo(EventsByLatency);
