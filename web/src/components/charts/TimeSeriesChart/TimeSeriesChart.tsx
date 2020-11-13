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
import { EChartOption, ECharts } from 'echarts';
import mapKeys from 'lodash/mapKeys';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { stringToPaleColor } from 'Helpers/colors';
import ResetButton from '../ResetButton';
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
  const timeSeriesChart = React.useRef<ECharts>(null);
  const container = React.useRef<HTMLDivElement>(null);
  const tooltip = React.useRef<HTMLDivElement>(document.createElement('div'));

  /*
   * Defining ChartOptions
   */
  const chartOptions = React.useMemo(() => {
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
        data: values
          .map((v, i) => {
            return {
              name: label,
              value: [timestamps[i], v],
            };
          })
          /* This reverse is needed cause data provided by API are coming by descending timestamp.
           * Although data are displayed correctly on the graph because are ordered by timestamp,
           * echarts dont seem to apply the same logic when displaying the mini-chart, this reverse only
           * affects that feature
           */
          .reverse(),
      };
    });

    const options: EChartOption = {
      grid: {
        left: 180,
        right: 50,
        bottom: 50,
        containLabel: true,
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
        inactiveColor: theme.colors['gray-400'],
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

    return options;
  }, [data, scaleType]);

  // initialize and load the timeSeriesChart
  React.useEffect(() => {
    (async () => {
      const [echarts] = await Promise.all(
        [
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/echarts'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/chart/line'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/tooltip'),
          zoomable && import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/dataZoom'),
          // This is needed for reset functionality
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/toolbox'),
          import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/legendScroll'),
        ].filter(Boolean)
      );
      const newChart = echarts.init(container.current);
      /*
       * Overriding default behaviour for legend selection. With this functionality,
       * when user select an specific series, we isolate this series only, subsequent clicks on
       * other series will show them up too. When all series are enabled again this behaviour is reseted
       * We need to disable listeners before enabling them to avoid generating multiple listeners
       */
      newChart.off('legendselectchanged');
      // eslint-disable-next-line func-names
      newChart.on('legendselectchanged', function (obj) {
        const { selected, name } = obj;
        const currentSelected = chartOptions.legend.selected;
        // On first selection currentSelected is 'undefined'
        if (!currentSelected || Object.keys(currentSelected).every(key => currentSelected[key])) {
          chartOptions.legend.selected = Object.keys(selected).reduce((acc, key) => {
            acc[key] = key === name;
            return acc;
          }, {});
          // This checks if everything is going to deselected, if yes we enable all series
        } else if (!Object.keys(selected).some(key => selected[key])) {
          chartOptions.legend.selected = Object.keys(selected).reduce((acc, key) => {
            acc[key] = true;
            return acc;
          }, {});
        } else {
          chartOptions.legend.selected = selected;
        }
        this.setOption(chartOptions);
      });

      /*
       * Overriding default behaviour for restore functionality. With this functionality,
       * we reset all legend selections, zooms and scaleType. We need to disable listeners
       * before enabling them to avoid generating multiple listeners
       */
      newChart.off('restore');
      // eslint-disable-next-line func-names
      newChart.on('restore', function () {
        const options = chartOptions;
        if (options.legend.selected) {
          options.legend.selected = Object.keys(options.legend.selected).reduce((acc, cur) => {
            acc[cur] = true;
            return acc;
          }, {});
        }
        setScaleType('value');

        this.setOption(options);
      });
      newChart.setOption(chartOptions);
      timeSeriesChart.current = newChart;
    })();
  }, [chartOptions]);

  // useEffect to apply changes from chartOptions
  React.useEffect(() => {
    if (timeSeriesChart.current) {
      timeSeriesChart.current.setOption(chartOptions);
    }
  }, [chartOptions]);

  return (
    <React.Fragment>
      <Box position="absolute" width="200px" ml={1} fontWeight="bold">
        {title}
      </Box>

      <Box position="absolute" pl="210px" pr="50px" width={1}>
        <Flex align="center" justify="space-between">
          {scaleControls && <ScaleControls scaleType={scaleType} onSelect={setScaleType} />}
          <Box zIndex={5}>
            <ResetButton
              onReset={() =>
                timeSeriesChart.current.dispatchAction({
                  type: 'restore',
                })
              }
            />
          </Box>
        </Flex>
      </Box>
      <Box ref={container} width="100%" height="100%" />
    </React.Fragment>
  );
};

export default React.memo(TimeSeriesChart);
