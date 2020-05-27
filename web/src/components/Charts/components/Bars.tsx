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
import echarts from 'echarts';
import { Box, theme as Theme } from 'pouncejs';

interface Data {
  value: number;
  label: string;
  color?: keyof typeof Theme['colors'];
}

interface BarsProps {
  data: Data[];
  horizontal?: boolean;
}

const Bars: React.FC<BarsProps> = ({ data, horizontal }) => {
  const container = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    // We are not allowed to put async function directly in useEffect. Instead, we should define
    // our own async function and call it within useEffect
    (async () => {
      /*
       * 'legendData' must be an array of values that matches 'series.name'in order
       * to display them in correct order and color
       * e.g. [AWS.ALB]
       */
      const legendData = data.map(e => e.label);

      /*
       * 'series' must be an array of objects that includes some graph options
       * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
       * is an array of values for all datapoints
       * Must be ordered
       */
      const series = data.map((e, seriesIndex) => {
        return {
          name: e.label,
          type: 'bar',
          barWidth: 30,
          barGap: horizontal ? '100%' : '-100%',
          label: {
            show: true,
            position: horizontal ? 'right' : 'top',
            color: 'black',
          },
          itemStyle: {
            color: Theme.colors[e.color],
            barBorderRadius: 16,
          },
          data: data.map((d, i) => (i === seriesIndex ? d.value : '-')),
        };
      });

      const valueAxis = {
        show: false,
        type: 'value',
      };

      const categoryAxis = {
        show: false,
        type: 'category',
        boundaryGap: true,
        data: data.map((e, i) => i),
      };

      const [yAxis, xAxis] = horizontal ? [categoryAxis, valueAxis] : [valueAxis, categoryAxis];

      const options = {
        grid: {
          left: 100,
          right: 20,
          bottom: 20,
          top: horizontal ? 0 : 30,
        },
        tooltip: {
          position: pt => [pt[0], '100%'],
          formatter: params => {
            return `${params.seriesName} : ${params.value}`;
          },
        },
        legend: {
          type: 'scroll',
          orient: 'vertical',
          left: 'left',
          icon: 'circle',
          data: legendData,
        },
        xAxis,
        yAxis,
        series,
      };

      // load the bar chart
      const barChart = echarts.init(container.current);
      // @ts-ignore
      barChart.setOption(options);
    })();
  }, []);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(Bars);
