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
import { Box, useTheme } from 'pouncejs';
import { formatTime } from 'Helpers/utils';
import { SeriesData } from 'Generated/schema';
import { LineColors } from '../constants';

interface TimeSeriesLinesProps {
  data: SeriesData;
}

const createFormat = (format: string): any => formatTime(format);
const hourFormat = createFormat('HH:mm');
const dateFormat = createFormat('DD/MM');
const fullDateFormat = createFormat('HH:mm DD/MM/YYYY');

function formatDateString(timestamp) {
  return `  ${hourFormat(timestamp)}
  ${dateFormat(timestamp)}`;
}

const TimeSeriesChart: React.FC<TimeSeriesLinesProps> = ({ data }) => {
  const theme = useTheme();
  const container = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    (async () => {
      // load the pie chart
      const [echarts] = await Promise.all([
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/echarts'),
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/chart/line'),
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/tooltip'),
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/legendScroll'),
      ]);
      /*
       *  Timestamps are common for all series since everything has the same interval
       *  and the same time frame
       */
      const { timestamps, series } = data;
      /*
       * 'legendData' must be an array of values that matches 'series.name'in order
       * to display them in correct order and color
       * e.g. [AWS.ALB, AWS.S3, ...etc]
       */
      const legendData = series.map(({ label }) => label);

      /*
       * 'series' must be an array of objects that includes some graph options
       * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
       * is an array of values for all datapoints
       * Must be ordered
       */
      const seriesData = series.map(({ label, values }) => {
        return {
          name: label,
          type: 'line',
          smooth: true,
          symbol: 'none',
          itemStyle: {
            color: LineColors[label],
          },
          data: values.map((v, i) => {
            return {
              name: label,
              value: [timestamps[i], v],
            };
          }),
        };
      });

      const options = {
        grid: {
          left: 180,
          right: 20,
          bottom: 20,
          top: 10,
          containLabel: true,
        },
        tooltip: {
          trigger: 'axis' as const,
          position: pt => [pt[0], '100%'],
          formatter: params => {
            let tooltip = '';
            if (params.length) {
              const [
                {
                  value: [date],
                },
              ] = params;
              tooltip += fullDateFormat(date);
              const seriesTooltips = params.map(seriesTooltip => {
                return `<br/>${seriesTooltip.marker} ${
                  seriesTooltip.seriesName
                }: ${seriesTooltip.value[1].toLocaleString('en')}`;
              });
              tooltip += seriesTooltips;
            }
            return tooltip;
          },
        },
        legend: {
          type: 'scroll' as const,
          orient: 'vertical' as const,
          left: 'auto',
          right: 'auto',
          icon: 'circle',
          data: legendData,
          textStyle: {
            color: theme.colors['gray-50'],
          },
        },
        xAxis: {
          type: 'time' as const,
          splitLine: {
            show: false,
          },
          axisLabel: {
            show: true,
            formatter: value => formatDateString(value),
            textStyle: {
              color: () => {
                return theme.colors['gray-50'];
              },
            },
          },
        },
        yAxis: {
          type: 'value' as const,
          splitNumber: 4,
          axisLabel: {
            padding: [0, 20, 0, 0],
            interval: 1,
            show: true,
            textStyle: {
              color: () => {
                return theme.colors['gray-50'];
              },
            },
          },
          axisLine: {
            show: true,
          },
          splitLine: {
            lineStyle: {
              color: theme.colors['gray-50'],
              opacity: 0.15,
              type: 'dashed' as const,
            },
          },
        },
        series: seriesData,
      };

      // load the timeSeriesChart
      const timeSeriesChart = echarts.init(container.current);
      timeSeriesChart.setOption(options);
    })();
  }, [data]);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(TimeSeriesChart);
