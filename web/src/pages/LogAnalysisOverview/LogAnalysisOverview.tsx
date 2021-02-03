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
import { Alert, Box, SimpleGrid } from 'pouncejs';
import withSEO from 'Hoc/withSEO';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage, getGraphqlSafeDateRange } from 'Helpers/utils';
import { PageViewEnum } from 'Helpers/analytics';
import useTrackPageView from 'Hooks/useTrackPageView';
import AlertsCharts from 'Pages/LogAnalysisOverview/AlertsCharts';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { AlertStatusesEnum, LogAnalysisMetricsInput } from 'Generated/schema';
import AlertsSection from 'Pages/LogAnalysisOverview/AlertsSection';
import LogAnalysisOverviewBreadcrumbFilters from './LogAnalysisOverviewBreadcrumbFilters';
import { useGetOverviewAlerts } from './graphql/getOverviewAlerts.generated';
import LogTypeCharts from './LogTypeCharts';
import { useGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';
import LogAnalysisOverviewPageSkeleton from './Skeleton';

export const DEFAULT_INTERVAL = 180;
export const DEFAULT_PAST_DAYS = 3;

const LogAnalysisOverview: React.FC = () => {
  useTrackPageView(PageViewEnum.LogAnalysisOverview);

  const {
    requestParams: { fromDate, toDate, intervalMinutes },
  } = useRequestParamsWithoutPagination<LogAnalysisMetricsInput>();

  const initialValues = React.useMemo(() => {
    const [utcDaysAgo, utcNow] = getGraphqlSafeDateRange({ days: DEFAULT_PAST_DAYS });
    return {
      intervalMinutes: intervalMinutes ?? DEFAULT_INTERVAL,
      fromDate: fromDate ?? utcDaysAgo,
      toDate: toDate ?? utcNow,
    };
  }, [intervalMinutes, fromDate, toDate]);

  const { data, loading, error } = useGetLogAnalysisMetrics({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        metricNames: [
          'eventsProcessed',
          'totalAlertsDelta',
          'alertsBySeverity',
          // TODO: uncomment when event latency data are fixed (PR #2509, Ticket #2492)
          // 'eventsLatency',
          'alertsByRuleID',
        ],
        ...initialValues,
      },
    },
  });

  const { loading: loadingAlerts, data: alertsData } = useGetOverviewAlerts({
    fetchPolicy: 'cache-and-network',
    variables: {
      recentAlertsInput: {
        pageSize: 10,
        status: [AlertStatusesEnum.Open, AlertStatusesEnum.Triaged],
      },
    },
  });

  if ((loading || loadingAlerts) && (!data || !alertsData)) {
    return <LogAnalysisOverviewPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="We can't display this content right now"
        description={extractErrorMessage(error)}
      />
    );
  }
  // TODO: uncomment when event latency data are fixed (PR #2509, Ticket #2492)
  const { alertsBySeverity, totalAlertsDelta, eventsProcessed,/* eventsLatency, */ alertsByRuleID } = data.getLogAnalysisMetrics; // prettier-ignore
  const topAlertSummaries = alertsData?.topAlerts?.alertSummaries || [];
  const recentAlertSummaries = alertsData?.recentAlerts?.alertSummaries || [];

  return (
    <Box as="article" mb={6}>
      <LogAnalysisOverviewBreadcrumbFilters initialValues={initialValues} />
      <SimpleGrid columns={1} spacingX={3} spacingY={2} as="section" mb={5}>
        <AlertsCharts
          totalAlertsDelta={totalAlertsDelta}
          alertsBySeverity={alertsBySeverity}
          alertsByRuleID={alertsByRuleID}
        />
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2} my={5}>
        <LogTypeCharts eventsProcessed={eventsProcessed} /* eventsLatency={eventsLatency} */ />
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2}>
        {loadingAlerts ? (
          <TablePlaceholder />
        ) : (
          <AlertsSection topAlerts={topAlertSummaries} recentAlerts={recentAlertSummaries} />
        )}
      </SimpleGrid>
    </Box>
  );
};

export default withSEO({ title: 'Log Analysis Overview' })(LogAnalysisOverview);
