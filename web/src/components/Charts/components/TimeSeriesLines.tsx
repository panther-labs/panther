import React from 'react';
import ReactEcharts from 'echarts-for-react';
import { ChartThemeType, LineColors } from '../constants';

interface TimeSeriesLinesProps {
  theme: ChartThemeType;
  data: any;
  height?: number | string;
  width?: number | string;
  loading?: boolean;
}

const TimeSeriesLines: React.FC<TimeSeriesLinesProps> = ({
  data,
  theme,
  height,
  width,
  loading,
}) => {
  /*
   * 'xAxisData' must be an array of values that is common for all series
   * Must be ordered
   * e.g. [05/14, 05/15, [04,16]
   */
  const xAxisData = data[Object.keys(data)[0]].points.map(p => p.timestamp);

  /*
   * 'legendData' must be an array of values that matches 'series.name'in order
   * to display them in correct order and color
   * e.g. [AWS.ALB]
   */
  const legendData = Object.keys(data);

  /*
   * 'series' must be an array of objects that includes some graph options
   * like 'type', 'symbol' and 'itemStyle' and most importantly 'data' which
   * is an array of values for all datapoints
   * Must be ordered
   */
  const series = Object.keys(data).map(key => {
    const dataPoints = data[key].points.map(point => point.count);
    return {
      name: key,
      type: 'line',
      smooth: true,
      // symbol: 'none',
      sampling: 'average',
      itemStyle: {
        color: LineColors[key],
      },
      data: dataPoints,
    };
  });

  const options = {
    grid: {
      left: 200,
      right: '3%',
      bottom: '3%',
      top: '3%',
      containLabel: true,
    },
    tooltip: {
      trigger: 'axis',
      position: pt => [pt[0], '100%'],
    },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      left: 'left',
      icon: 'circle',
      data: legendData,
    },
    xAxis: {
      // FIXME: This probably need to change to 'time' value with real data
      type: 'category',
      boundaryGap: 0,
      data: xAxisData,
    },
    yAxis: {
      type: 'value',
      boundaryGap: 0,
    },
    series,
  };

  /*
   * 'loadingOption' sets up an out-of-box loading component 'echarts' is offering
   * to show a spinning loading animation
   */
  const loadingOption = {
    text: 'Loading',
    color: '#4413c2',
    textColor: '#270240',
    maskColor: 'rgba(176,175,175,0.3)',
  };

  return (
    <ReactEcharts
      // @ts-ignore
      option={options}
      theme={theme}
      loadingOption={loadingOption}
      style={{ width, height }}
      showLoading={loading}
    />
  );
};

export default TimeSeriesLines;
