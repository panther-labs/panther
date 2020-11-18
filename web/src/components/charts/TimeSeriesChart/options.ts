import { remToPx } from 'Helpers/utils';
import { FloatSeries, LongSeries } from 'Generated/schema';

type GetLegendProps = {
  theme: any;
  series: (LongSeries | FloatSeries)[];
  title?: string;
};

type GetLegendFunc = (props: GetLegendProps) => any;

export const getLegend: GetLegendFunc = ({ theme, series, title }) => {
  /*
   * 'legendData' must be an array of values that matches 'series.name' in order
   * to display them in correct order and color
   * e.g. [AWS.ALB, AWS.S3, ...etc]
   */
  const legendData = series.map(({ label }) => label);
  return {
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
  };
};
