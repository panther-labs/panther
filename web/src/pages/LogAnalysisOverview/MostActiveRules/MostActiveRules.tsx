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
import { Box, Theme } from 'pouncejs';
import { SingleValue } from 'Generated/schema';
import BarChart from 'Components/charts/BarChart';
import NoDataFound from 'Components/NoDataFound';

// Default color values for alertsByRuleID
const barColors: (keyof Theme['colors'])[] = [
  'cyan-400',
  'magenta-500',
  'yellow-500',
  'red-300',
  'blue-500',
];

interface MostActiveRulesProps {
  alertsByRuleID: SingleValue[];
}

const gridPosition = { left: '20%', bottom: 0, top: 0, right: 200 };
const barWidth = 24;
const barGap = '-100%';

const MostActiveRules: React.FC<MostActiveRulesProps> = ({ alertsByRuleID }) => {
  const reversedData = React.useMemo(
    () =>
      alertsByRuleID
        // Displaying only 5 bars, this list is sorted so top alertsByRuleID should first
        .slice(0, 5)
        // Adding fixed colors to bars for visual reasons
        .map((bar, i) => ({ ...bar, color: barColors[i] }))
        // need to reverse order for echarts to display bigger first
        .reverse(),
    [alertsByRuleID, barColors]
  );
  return (
    <Box
      data-testid="most-active-rules-chart"
      height={217}
      p={6}
      pr={0}
      backgroundColor="navyblue-500"
    >
      {reversedData.length ? (
        <BarChart
          gridPosition={gridPosition}
          barGap={barGap}
          barWidth={barWidth}
          data={reversedData}
          formatSeriesLabel={params => `${params.value} Alerts`}
          alignment="horizontal"
        />
      ) : (
        <NoDataFound title="Your logs haven't matched any rule yet" />
      )}
    </Box>
  );
};

export default React.memo(MostActiveRules);
