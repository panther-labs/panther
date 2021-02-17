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
import { Alert, Box, Flex, SimpleGrid } from 'pouncejs';
import { extractErrorMessage, getGraphqlSafeDateRange } from 'Helpers/utils';
import { PageViewEnum } from 'Helpers/analytics';
import useTrackPageView from 'Hooks/useTrackPageView';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { LogAnalysisMetricsInput } from 'Generated/schema';
import AlertCard from 'Components/cards/AlertCard';
import NoResultsFound from 'Components/NoResultsFound';
import Panel from 'Components/Panel';
import AlertSummary from './AlertSummary';
import AlertsOverviewBreadcrumbFilters from './AlertsOverviewBreadcrumbFilters';
import LogAnalysisOverviewPageSkeleton from './Skeleton';
import { useGetOverviewAlerts } from './graphql/getOverviewAlerts.generated';
import { useGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';
import AlertsBySeverity from './AlertsBySeverity';
import MostActiveRules from './MostActiveRules';

export const DEFAULT_INTERVAL = 180;
export const DEFAULT_PAST_DAYS = 3;

const AlertsOverview: React.FC = () => {
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

  const { loading: loadingAlerts, data: alertsData } = useGetOverviewAlerts({
    fetchPolicy: 'cache-and-network',
  });

  const { loading, data, error } = useGetLogAnalysisMetrics({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        metricNames: ['eventsProcessed', 'totalAlertsDelta', 'alertsBySeverity', 'alertsByRuleID'],
        ...initialValues,
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

  const topAlertSummaries = alertsData?.alerts?.alertSummaries || [];
  const { alertsBySeverity, totalAlertsDelta, alertsByRuleID } = data.getLogAnalysisMetrics;

  return (
    <Box as="article" mb={6}>
      <AlertsOverviewBreadcrumbFilters initialValues={initialValues} />
      <SimpleGrid columns={1} spacingY={4}>
        <Panel title="Alerts Overview">
          <Flex>
            <AlertSummary data={totalAlertsDelta} />
            <AlertsBySeverity alerts={alertsBySeverity} />
          </Flex>
        </Panel>
        <Panel title="Top 5 High Priority Alerts">
          <Flex direction="column" spacing={2}>
            {topAlertSummaries.length ? (
              topAlertSummaries.map(alert => <AlertCard key={alert.alertId} alert={alert} />)
            ) : (
              <Box my={6}>
                <NoResultsFound />
              </Box>
            )}
          </Flex>
        </Panel>
        <Panel title="Most Active Detections">
          <MostActiveRules alertsByRuleID={alertsByRuleID} />
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default AlertsOverview;
