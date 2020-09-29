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
   * Whether the chart will display zoom controls toolbox
   * @default true
   */
  zoomControls?: boolean;

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
  zoomControls = true,
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
          zoomControls && import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/toolbox'),
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
          smooth: true,
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
        ...(zoomControls && {
          toolbox: {
            show: true,
            right: 50,
            iconStyle: {
              color: theme.colors.white,
            },
            feature: {
              dataZoom: {
                yAxisIndex: 'none',
                iconStyle: {
                  color: theme.colors.white,
                  borderWidth: 0.5,
                  borderColor: theme.colors.white,
                },
                icon: {
                  zoom:
                    'M7,0 C10.8659932,0 14,3.13400675 14,7 C14,8.66283733 13.4202012,10.1902554 12.4517398,11.3911181 L16.0303301,14.9696699 L14.9696699,16.0303301 L11.3911181,12.4517398 C10.1902554,13.4202012 8.66283733,14 7,14 C3.13400675,14 0,10.8659932 0,7 C0,3.13400675 3.13400675,0 7,0 Z M7,1.5 C3.96243388,1.5 1.5,3.96243388 1.5,7 C1.5,10.0375661 3.96243388,12.5 7,12.5 C10.0375661,12.5 12.5,10.0375661 12.5,7 C12.5,3.96243388 10.0375661,1.5 7,1.5 Z M7.75,4.25 L7.75,6.25 L9.75,6.25 L9.75,7.75 L7.75,7.75 L7.75,9.75 L6.25,9.75 L6.25,7.75 L4.25,7.75 L4.25,6.25 L6.25,6.25 L6.25,4.25 L7.75,4.25 Z',
                  back:
                    'M13.7435054,1.25 L13.7435054,8.36513992 L13.7383074,8.56429849 C13.6347792,10.5427789 11.9977646,12.1151399 9.99350544,12.1151399 L9.99350544,12.1151399 L5.10249456,12.115 L6.67591195,13.6893398 L5.61525178,14.75 L2.25649456,11.3912428 L5.61525178,8.03248558 L6.67591195,9.09314575 L5.15249456,10.615 L9.99350544,10.6151399 L10.1475542,10.6099491 C11.3183438,10.5307848 12.2435054,9.55600391 12.2435054,8.36513992 L12.2435054,8.36513992 L12.2435054,1.25 L12.2435054,1.25 L13.7435054,1.25 Z',
                },
                title: '',
              },
              restore: {
                iconStyle: {
                  color: theme.colors.white,
                  borderWidth: 0.5,
                  borderColor: theme.colors.white,
                },
                icon:
                  'M8.44995646,1.53927764 C12.0181149,1.53927764 14.9106788,4.43184157 14.9106788,8 C14.9106788,11.4922402 12.1398933,14.3373287 8.67677239,14.4568154 L8.44995646,14.4607224 L8.44995646,13.0250063 C11.2251908,13.0250063 13.4749627,10.7752343 13.4749627,8 C13.4749627,5.22476566 11.2251908,2.97499372 8.44995646,2.97499372 C7.70164195,2.97499372 6.97787869,3.13820882 6.31642193,3.44891204 C4.74395282,4.18754113 3.66310947,5.68398014 3.45972717,7.40740116 L4.93752431,6.29534746 L5.71955998,7.33314384 L2.47644628,9.77700531 L-2.22044605e-14,6.49065009 L1.02414117,5.71890437 L2.05370112,7.08637716 C2.35948084,4.93510009 3.73142984,3.07693159 5.70601612,2.14941775 C6.55747933,1.74946363 7.48953092,1.53927764 8.44995646,1.53927764 Z',
                // Note: the empty space in title is sadly necessary to override default title
                title: ' ',
              },
            },
          },
        }),
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
              labelFormatter: value => formatDateString(value),
              borderColor: theme.colors['navyblue-200'],
              // + 33 is opacity at 40%, what's the best way to do this?
              fillerColor: `${theme.colors['navyblue-200']}4D`,
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

      /*
       * Overriding default behaviour for legend selection. With this functionality,
       * when user select an specific series, we isolate this series only, subsequent clicks on
       * other series will show them up too. When all series are enabled again this behaviour is reseted
       */
      let allSelected = true;
      // eslint-disable-next-line func-names
      timeSeriesChart.on('legendselectchanged', function (obj) {
        const { selected, name } = obj;
        if (allSelected && selected) {
          Object.keys(selected).forEach(key => {
            selected[key] = key === name;
          });
          allSelected = false;
        } else {
          const open = selected[name];
          selected[name] = open;
          // With this we check if every series is selected so we can reset behaviour
          allSelected = Object.keys(selected).every(key => selected[key]);
        }
        options.legend.selected = selected;
        this.setOption(options);
      });

      /*
       * Overriding default behaviour for restore functionality. With this functionality,
       * we reset all legend selections, zooms and scaleType
       */
      // eslint-disable-next-line func-names
      timeSeriesChart.on('restore', function () {
        allSelected = true;
        if (options.legend.selected) {
          options.legend.selected = Object.keys(options.legend.selected).reduce((acc, cur) => {
            acc[cur] = true;
            return acc;
          }, {});
        }
        setScaleType('value');
        this.setOption(options);
      });

      timeSeriesChart.setOption(options);
    })();
  }, [data, scaleType]);

  return (
    <React.Fragment>
      <Box position="absolute" width="200px" ml={1} fontWeight="bold">
        {title}
      </Box>
      {scaleControls && (
        <Box position="absolute" ml="210px" zIndex={5}>
          <ScaleControls scaleType={scaleType} onSelection={setScaleType} />
        </Box>
      )}
      <Box ref={container} width="100%" height="100%" />
    </React.Fragment>
  );
};

export default React.memo(TimeSeriesChart);
