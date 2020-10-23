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
import { Box, Theme, useTheme } from 'pouncejs';
import useBarChartSpacing from 'Components/charts/BarChart/useBarChartSpacing';

interface Data {
  value: number;
  label: string;
  color?: keyof Theme['colors'];
}

/**
 * `GridPosition` properties defines spaces between chart
 * container and other elements,including legend
 * @default {
 *    left: 100,
 *    right: 20,
 *    bottom: 20,
 *    top: isHorizontal ? 0 : 30,
 * }
 */
export interface GridPosition {
  left?: string | number;
  right?: string | number;
  bottom?: string | number;
  top?: string | number;
}

/**
 * `BarConfig` properties defines how bars are displayed currently support `barWidth`,
 * and `barGap` which defines the gap between bars
 * @default {
 *    barWidth: 30,
 *    barGap: isHorizontal ? '-20%' : '-110%',
 *  }
 */

export interface Spacing {
  grid?: GridPosition;
  barGap?: string | number;
  barWidth?: number;
}

interface FormatterParams {
  seriesName: string;
  value: number;
}

type FormatSeriesLabelFunc = (params: FormatterParams) => string;

export type CardWidthType = 'half' | 'full';

interface BarChartProps {
  /**
   * The `data` property is required for displaying the BarChart
   */
  data: Data[];
  /**
   * `formatSeriesLabel` is a function that should change how the label for series
   * are displayed
   */
  formatSeriesLabel?: FormatSeriesLabelFunc;
  /**
   * `alignment` property is string that can take the values of 'horizontal'
   * and 'vertical'. It defines how the bars will be displayed
   * @default 'vertical'
   */
  alignment?: 'horizontal' | 'vertical';
  /**
   * `gridPosition` property is an object that defines spaces between chart
   * container and other elements,including legend
   */
  gridPosition?: GridPosition;
  /**
   * `barWidth` property is the size number of bars in the chart
   * @default 30
   */
  barWidth?: number;
  /**
   * `barGap` property represents the distance between bars related to the barWidth.
   * This is not as clean as it sounds you can find how this should be used here:
   * https://echarts.apache.org/en/option.html#series-bar.barGap
   */
  barGap?: string | number;
}

const BarChart: React.FC<BarChartProps> = ({
  formatSeriesLabel,
  data,
  alignment = 'vertical',
  gridPosition,
  barWidth = 30,
  barGap,
}) => {
  const container = React.useRef<HTMLDivElement>(null);
  const isHorizontal = alignment === 'horizontal';
  const theme = useTheme();
  const chartSpacing = useBarChartSpacing({ gridPosition, barWidth, barGap, isHorizontal });

  React.useEffect(() => {
    // We are not allowed to put async function directly in useEffect. Instead, we should define
    // our own async function and call it within useEffect
    (async () => {
      // load the pie chart
      const [echarts] = await Promise.all([
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/echarts'),
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/chart/bar'),
        import(/* webpackChunkName: "echarts" */ 'echarts/lib/component/legendScroll'),
      ]);

      /*
       * 'legendData' must be an array of values that matches 'series.name'in order
       * to display them in correct order and color.
       * For horizontal charts we shall reverse the order as we want the legend data to
       * match the chart series.
       * e.g. [AWS.ALB]
       */
      const labels = data.map(e => e.label);
      const legendData = isHorizontal ? [...labels].reverse() : [...labels];

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
          barWidth: chartSpacing.barWidth,
          barGap: chartSpacing.barGap,
          label: {
            show: true,
            position: isHorizontal ? 'right' : 'top',
            color: theme.colors['gray-50'],
            // if seriesLabelFormatter is undefined, echarts resolves to default
            formatter: formatSeriesLabel,
          },
          itemStyle: {
            color: theme.colors[e.color],
            barBorderRadius: 16,
          },
          barMinHeight: 5,
          data: data.map((d, i) => (i === seriesIndex ? d.value : null)),
        };
      });

      const valueAxis = {
        show: false,
        type: 'value' as const,
      };

      const categoryAxis = {
        show: false,
        type: 'category' as const,
        boundaryGap: true,
        data: data.map((e, i) => i),
      };

      const [yAxis, xAxis] = isHorizontal ? [categoryAxis, valueAxis] : [valueAxis, categoryAxis];

      const options = {
        grid: chartSpacing.grid,
        tooltip: {
          position: pt => [pt[0], '100%'],
          formatter: params => {
            return `${params.seriesName} : ${params.value}`;
          },
        },
        legend: {
          type: 'scroll' as const,
          orient: 'vertical' as const,
          left: 'left',
          icon: 'circle',
          data: legendData,
          /*
           * This formatter attempts to wrap the text of a legend label
           * that currently is not supported by echarts.
           */
          formatter: name => {
            if (name.length > 25) {
              return `${name.slice(0, 25)}\n${name.slice(25, 48)}...`;
            }
            return name;
          },
          textStyle: {
            color: theme.colors['gray-50'],
          },
        },
        xAxis,
        yAxis,
        series,
      };

      // load the bar chart
      const barChart = echarts.init(container.current);
      barChart.setOption(options);
    })();
  }, [data]);

  return <Box ref={container} width="100%" height="100%" />;
};

export default React.memo(BarChart);
