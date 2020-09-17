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
import withSEO from 'Hoc/withSEO';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage, getCurrentDate, subtractDays } from 'Helpers/utils';
import Panel from 'Components/Panel';
import AlertCard from 'Components/cards/AlertCard/AlertCard';
import LogAnalysisOverviewPageSkeleton from './Skeleton';
import { useGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';
import AlertsBySeverity from './AlertsBySeverity';
import AlertSummary from './AlertSummary';
import LogTypeCharts from './LogTypeCharts';
import { useGetTopAlerts } from './graphql/getTopAlerts.generated';

export const intervalMinutes = 60;
export const defaultPastDays = 3;

const LogAnalysisOverview: React.FC = () => {
  const [fromDate, toDate] = React.useMemo(() => {
    const utcnow = getCurrentDate();
    return [subtractDays(utcnow, defaultPastDays), utcnow];
  }, []);

  const { data, loading, error } = useGetLogAnalysisMetrics({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        metricNames: ['eventsProcessed', 'totalAlertsDelta', 'alertsBySeverity', 'eventsLatency'],
        fromDate,
        toDate,
        intervalMinutes,
      },
    },
  });

  const { loading: loadingAlerts, data: alerts } = useGetTopAlerts({
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
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

  const { alertsBySeverity, totalAlertsDelta, eventsProcessed, eventsLatency } = data.getLogAnalysisMetrics; // prettier-ignore
  const alertItems = alerts?.alerts.alertSummaries || [];

  return (
    <Box as="article" mb={6}>
      <SimpleGrid columns={1} spacingX={3} spacingY={2} as="section" mb={5}>
        <Panel title="Real-time Alerts">
          <Box height={200}>
            <Flex direction="row" width="100%">
              <AlertSummary data={totalAlertsDelta} />
              <AlertsBySeverity alerts={alertsBySeverity} />
            </Flex>
          </Box>
        </Panel>
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2} my={5}>
        <LogTypeCharts eventsProcessed={eventsProcessed} eventsLatency={eventsLatency} />
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2}>
        <Panel title="Recent High Severity Alerts">
          {loadingAlerts ? (
            <TablePlaceholder />
          ) : (
            <Flex direction="column" spacing={2}>
              {alertItems.map(alert => (
                <AlertCard key={alert.alertId} alert={alert} />
              ))}
            </Flex>
          )}
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default withSEO({ title: 'Log Analysis Overview' })(LogAnalysisOverview);
