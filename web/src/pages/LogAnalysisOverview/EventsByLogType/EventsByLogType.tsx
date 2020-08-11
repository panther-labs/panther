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
import { SeriesData } from 'Generated/schema';

interface EventsByLogTypesProps {
  events: SeriesData;
}

const EventsByLogTypes: React.FC<EventsByLogTypesProps> = ({ events }) => {
  return (
    <Flex
      data-testid="events-by-log-type-chart"
      height="100%"
      pt={4}
      px={4}
      backgroundColor="navyblue-500"
    >
      <TimeSeriesChart data={events} zoomable />
    </Flex>
  );
};

export default React.memo(EventsByLogTypes);
