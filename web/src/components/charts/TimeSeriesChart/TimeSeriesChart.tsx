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
import ReactDOM from 'react-dom';
import { Box, Flex, Text, useTheme } from 'pouncejs';
import { formatTime, formatDatetime, remToPx, capitalize } from 'Helpers/utils';
import { SeriesData } from 'Generated/schema';
import { EChartOption } from 'echarts';
import mapKeys from 'lodash/mapKeys';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { stringToPaleColor } from 'Helpers/colors';

interface TimeSeriesLinesProps {
  /** The data for the time series */
  data: SeriesData;

  /**
   * The number of segments that the X-axis is split into
   * @default 12
   */
  segments?: number;

  /**
   * Whether the chart will allow zooming
   * @default false
   */
  zoomable?: boolean;

  /**
   * If defined, the chart will be zoomable and will zoom up to a range specified in `ms` by this
   * value. This range will occupy the entirety of the X-axis (end-to-end).
   * For example, a value of 3600 * 1000 * 24 would allow the chart to zoom until the entirety
   * of the zoomed-in chart shows 1 full day.
   * @default 3600 * 1000 * 24
   */
  maxZoomPeriod?: number;
}

const severityColors = mapKeys(SEVERITY_COLOR_MAP, (val, key) => capitalize(key.toLowerCase()));

const hourFormat = formatTime('HH:mm');
const dateFormat = formatTime('MMM DD');

function formatDateString(timestamp) {
  return `${hourFormat(timestamp)}\n${dateFormat(timestamp).toUpperCase()}`;
}

const TimeSeriesChart: React.FC<TimeSeriesLinesProps> = ({
  data,
  zoomable = false,
  segments = 12,
  maxZoomPeriod = 3600 * 1000 * 24,
}) => {
  const theme = useTheme();
  const container = React.useRef<HTMLDivElement>(null);
  const tooltip = React.useRef<HTMLDivElement>(document.createElement('div'));

  React.useEffect(() => {
    (async () => {
      // load the pie chart
      const [echarts] = await Promise.all(
        [
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/echarts'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/chart/line'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/tooltip'),
          zoomable && import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/dataZoom'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/legendScroll'),
        ].filter(Boolean)
      );
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
          symbol: 'none',
          itemStyle: {
            color: theme.colors[severityColors[label]] || stringToPaleColor(label),
          },
          data: values.map((v, i) => {
            return {
              name: label,
              value: [timestamps[i], v],
            };
          }),
        };
      });

      const options: EChartOption = {
        grid: {
          left: 180,
          right: 20,
          bottom: 20,
          top: 10,
          containLabel: true,
        },
        ...(zoomable && {
          dataZoom: [
            {
              type: 'inside',
              orient: 'horizontal',
              minValueSpan: maxZoomPeriod,
            },
          ],
        }),
        tooltip: {
          trigger: 'axis' as const,
          backgroundColor: theme.colors['navyblue-300'],
          formatter: (params: EChartOption.Tooltip.Format[]) => {
            if (!params || !params.length) {
              return '';
            }

            const component = (
              <Box font="primary" minWidth={200} boxShadow="dark250" p={2} borderRadius="medium">
                <Text fontSize="small-medium" mb={3}>
                  {formatDatetime(params[0].value[0], true)}
                </Text>
                <Flex as="dl" direction="column" spacing={2} fontSize="x-small">
                  {params.map(seriesTooltip => (
                    <Flex key={seriesTooltip.seriesName} justify="space-between">
                      <Box as="dt">
                        <span dangerouslySetInnerHTML={{ __html: seriesTooltip.marker }} />
                        {seriesTooltip.seriesName}
                      </Box>
                      <Box as="dd" font="mono" fontWeight="bold">
                        {seriesTooltip.value[1].toLocaleString('en')}
                      </Box>
                    </Flex>
                  ))}
                </Flex>
              </Box>
            );

            ReactDOM.render(component, tooltip.current);
            return tooltip.current.innerHTML;
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
            fontFamily: theme.fonts.primary,
            fontSize: remToPx(theme.fontSizes['x-small']),
          },
          pageIcons: {
            vertical: ['M7 10L12 15L17 10H7Z', 'M7 14L12 9L17 14H7Z'],
          },
          pageIconColor: theme.colors['gray-50'],
          pageIconInactiveColor: theme.colors['navyblue-300'],
          pageIconSize: 12,
          pageTextStyle: {
            fontFamily: theme.fonts.primary,
            color: theme.colors['gray-50'],
            fontWeight: theme.fontWeights.bold as any,
            fontSize: remToPx(theme.fontSizes['x-small']),
          },
          pageButtonGap: theme.space[3] as number,
        },
        xAxis: {
          type: 'time' as const,
          splitNumber: segments,
          splitLine: {
            show: false,
          },
          axisLine: {
            lineStyle: {
              color: 'transparent',
            },
          },
          axisLabel: {
            formatter: value => formatDateString(value),
            fontWeight: theme.fontWeights.medium as any,
            fontSize: remToPx(theme.fontSizes['x-small']),
            fontFamily: theme.fonts.primary,
            color: theme.colors['gray-50'],
          },
          splitArea: { show: false }, // remove the grid area
        },
        yAxis: {
          type: 'value' as const,
          axisLine: {
            lineStyle: {
              color: 'transparent',
            },
          },
          axisLabel: {
            padding: [0, theme.space[2] as number, 0, 0],
            fontSize: remToPx(theme.fontSizes['x-small']),
            fontWeight: theme.fontWeights.medium as any,
            fontFamily: theme.fonts.primary,
            color: theme.colors['gray-50'],
          },
          minorSplitLine: {
            show: false,
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
