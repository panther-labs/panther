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
import { Box, Alert, SimpleGrid } from 'pouncejs';
import Panel from 'Components/Panel';
import ErrorBoundary from 'Components/ErrorBoundary';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetOrganizationStats } from './graphql/getOrganizationStats.generated';
import PoliciesBySeverityChart from './PoliciesBySeverityChart';
import PoliciesByStatusChart from './PoliciesByStatusChart';
import ResourcesByPlatformChart from './ResourcesByPlatformChart';
import ResourcesByStatusChart from './ResourcesByStatusChart';
import DonutChartWrapper from './DonutChartWrapper';
import ComplianceOverviewPageEmptyDataFallback from './EmptyDataFallback';
import ComplianceOverviewPageSkeleton from './Skeleton';
import TopFailingPoliciesTable from './TopFailingPoliciesTable';
import TopFailingResourcesTable from './TopFailingResourcesTable';

const ComplianceOverview: React.FC = () => {
  const { data, loading, error } = useGetOrganizationStats({
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
    return <ComplianceOverviewPageSkeleton />;
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

  if (!data.listComplianceIntegrations.length) {
    return <ComplianceOverviewPageEmptyDataFallback />;
  }

  return (
    <Box as="article" mb={6}>
      <SimpleGrid columns={4} spacing={3} as="section" mb={3}>
        <DonutChartWrapper title="Policy Severity" icon="policy">
          <PoliciesBySeverityChart policies={data.organizationStats.appliedPolicies} />
        </DonutChartWrapper>
        <DonutChartWrapper title="Policy Failure" icon="policy">
          <PoliciesByStatusChart policies={data.organizationStats.appliedPolicies} />
        </DonutChartWrapper>
        <DonutChartWrapper title="Resource Type" icon="resource">
          <ResourcesByPlatformChart resources={data.organizationStats.scannedResources} />
        </DonutChartWrapper>
        <DonutChartWrapper title="Resource Health" icon="resource">
          <ResourcesByStatusChart resources={data.organizationStats.scannedResources} />
        </DonutChartWrapper>
      </SimpleGrid>
      <SimpleGrid columns={2} spacingX={3} spacingY={2}>
        <Panel title="Top Failing Policies" size="small">
          <Box m={-6}>
            <ErrorBoundary>
              <TopFailingPoliciesTable policies={data.organizationStats.topFailingPolicies} />
            </ErrorBoundary>
          </Box>
        </Panel>
        <Panel title="Top Failing Resources" size="small">
          <Box m={-6}>
            <ErrorBoundary>
              <TopFailingResourcesTable resources={data.organizationStats.topFailingResources} />
            </ErrorBoundary>
          </Box>
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default ComplianceOverview;
