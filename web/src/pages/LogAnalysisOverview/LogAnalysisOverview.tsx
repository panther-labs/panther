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
import { extractErrorMessage } from 'Helpers/utils';
import Panel from 'Components/Panel';
import EventsByLogType from 'Pages/LogAnalysisOverview/EventsByLogType';
import { SeverityEnum } from 'Generated/schema';
import { useListAlerts } from 'Pages/ListAlerts/graphql/listAlerts.generated';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import AlertsTable from 'Pages/LogAnalysisOverview/AlertsTable';
import LogAnalysisOverviewPageSkeleton from './Skeleton';
import { useGetLogAnalysisMetrics } from './graphql/getLogAnalysisMetrics.generated';
import AlertsBySeverity from './AlertsBySeverity';
import AlertSummary from './AlertSummary';

function getDates() {
  const pastDays = 3;
  const toDate = new Date();
  const fromDate = new Date(toDate);
  fromDate.setDate(toDate.getDate() - pastDays);

  return {
    // split is used to cut out milliseconds since they trigger an infinite loop for some reason
    fromDate: `${fromDate.toISOString().split('.')[0]}Z`,
    toDate: `${toDate.toISOString().split('.')[0]}Z`,
  };
}

const LogAnalysisOverview: React.FC = () => {
  const intervalMinutes = 6 * 60;
  const { fromDate, toDate } = getDates();
  const { data, loading, error } = useGetLogAnalysisMetrics({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        metricNames: ['eventsProcessed', 'totalAlertsDelta', 'alertsBySeverity'],
        fromDate,
        toDate,
        intervalMinutes,
      },
    },
  });

  const { loading: loadingAlerts, data: alerts } = useListAlerts({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        severity: [SeverityEnum.Critical, SeverityEnum.High],
        pageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
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

  const { alertsBySeverity, totalAlertsDelta, eventsProcessed } = data.getLogAnalysisMetrics;
  const alertItems = alerts?.alerts.alertSummaries || [];

  return (
    <Box as="article" mb={6}>
      <SimpleGrid columns={1} spacingX={3} spacingY={2} as="section" mb={3}>
        <Panel title="Real-time Alerts">
          <Box height={200}>
            <Flex direction="row" width="100%">
              <AlertSummary data={totalAlertsDelta} />
              <AlertsBySeverity alerts={alertsBySeverity} />
            </Flex>
          </Box>
        </Panel>
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2} my={3}>
        <Panel title="Events by Log Type">
          <Box height={200}>
            <EventsByLogType events={eventsProcessed} />
          </Box>
        </Panel>
      </SimpleGrid>
      <SimpleGrid columns={1} spacingX={3} spacingY={2}>
        <Panel title="Recent High Severity Alerts">
          {loadingAlerts ? <TablePlaceholder /> : <AlertsTable items={alertItems} />}
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default withSEO({ title: 'Log Analysis Overview' })(LogAnalysisOverview);
