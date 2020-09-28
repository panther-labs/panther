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
import ScaleControls from '../ScaleControls';

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
   * Whether the chart will allow to change scale type
   * @default true
   */
  scaleControls?: boolean;

  /**
   * If defined, the chart will be zoomable and will zoom up to a range specified in `ms` by this
   * value. This range will occupy the entirety of the X-axis (end-to-end).
   * For example, a value of 3600 * 1000 * 24 would allow the chart to zoom until the entirety
   * of the zoomed-in chart shows 1 full day.
   * @default 3600 * 1000 * 24
   */
  maxZoomPeriod?: number;

  /**
   * This is parameter determines if we need to display the values with an appropriate suffix
   */
  units?: string;

  /**
   * This is an optional parameter that will render the text provided above legend if defined
   */
  title?: string;
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
  scaleControls = true,
  segments = 12,
  maxZoomPeriod = 3600 * 1000 * 24,
  units,
  title,
}) => {
  const [scaleType, setScaleType] = React.useState('value');
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
          zoomable && import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/toolbox'),
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
          right: 50,
          bottom: 50,
          containLabel: true,
        },
        toolbox: {
          show: true,
          right: 50,
          iconStyle: {
            color: '#FFFFFF',
          },
          feature: {
            dataZoom: {
              yAxisIndex: 'none',
              icon: {
                zoom:
                  'M7,0 C10.8659932,0 14,3.13400675 14,7 C14,8.66283733 13.4202012,10.1902554 12.4517398,11.3911181 L16.0303301,14.9696699 L14.9696699,16.0303301 L11.3911181,12.4517398 C10.1902554,13.4202012 8.66283733,14 7,14 C3.13400675,14 0,10.8659932 0,7 C0,3.13400675 3.13400675,0 7,0 Z M7,1.5 C3.96243388,1.5 1.5,3.96243388 1.5,7 C1.5,10.0375661 3.96243388,12.5 7,12.5 C10.0375661,12.5 12.5,10.0375661 12.5,7 C12.5,3.96243388 10.0375661,1.5 7,1.5 Z M7.75,4.25 L7.75,6.25 L9.75,6.25 L9.75,7.75 L7.75,7.75 L7.75,9.75 L6.25,9.75 L6.25,7.75 L4.25,7.75 L4.25,6.25 L6.25,6.25 L6.25,4.25 L7.75,4.25 Z',
                back:
                  'M11.9155597,0.5 C13.9198189,0.5 15.5568334,2.07236105 15.6603617,4.05084143 L15.6655597,4.25 L15.6655597,9.37367275 C15.6655597,11.3779319 14.0931986,13.0149465 12.1147183,13.1184747 L11.9155597,13.1236727 L4.08444032,13.1236727 C2.08018115,13.1236727 0.443166576,11.5513117 0.33963833,9.57283132 L0.334440321,9.37367275 L0.334440321,4.82102515 L1.83444032,4.82102515 L1.83444032,9.37367275 C1.83444032,10.5645367 2.75960191,11.5393177 3.93039151,11.6184819 L4.08444032,11.6236727 L11.9155597,11.6236727 C13.1064237,11.6236727 14.0812046,10.6985112 14.1603689,9.52772156 L14.1655597,9.37367275 L14.1655597,4.25 C14.1655597,3.05913601 13.2403981,2.08435508 12.0696085,2.00519081 L11.9155597,2 L2.17129777,2 L2.17129777,0.5 L11.9155597,0.5 Z',
              },
              title: '',
            },
          },
        },
        ...(zoomable && {
          dataZoom: [
            {
              show: true,
              type: 'slider',
              xAxisIndex: 0,
              minValueSpan: maxZoomPeriod,
              handleIcon: 'M 25, 50 a 25,25 0 1,1 50,0 a 25,25 0 1,1 -50,0',
              handleStyle: {
                color: theme.colors['navyblue-200'],
              },
              handleSize: 12,
              dataBackground: {
                areaStyle: {
                  color: theme.colors['navyblue-200'],
                },
              },

              borderColor: theme.colors['navyblue-200'],
              // + 33 is opacity at 20%, what's the best way to do this?
              fillerColor: theme.colors['navyblue-200'] + 33,
              textStyle: {
                color: theme.colors['gray-50'],
                fontSize: remToPx(theme.fontSizes['x-small']),
              },
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
                        {units ? ` ${units}` : ''}
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
          // Pushing down legend to fit title
          top: title ? 30 : 'auto',
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
          type: scaleType as EChartOption.BasicComponents.CartesianAxis.Type,
          logBase: 10,
          min: scaleType === 'log' ? 1 : 0,
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
            formatter: `{value}${units ? ` ${units}` : ''}`,
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
  }, [data, scaleType]);

  return (
    <React.Fragment>
      <Box position="absolute" ml={1} fontWeight="bold">
        {title}
      </Box>
      {scaleControls && <ScaleControls scaleType={scaleType} onSelection={setScaleType} />}
      <Box ref={container} width="100%" height="100%" />
    </React.Fragment>
  );
};

export default React.memo(TimeSeriesChart);
