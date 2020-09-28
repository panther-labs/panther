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
import withSEO from 'Hoc/withSEO';
import { extractErrorMessage } from 'Helpers/utils';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import { useGetOrganizationStats } from './graphql/getOrganizationStats.generated';
import PoliciesBySeverityChart from './PoliciesBySeverityChart';
import PoliciesByStatusChart from './PoliciesByStatusChart';
import ResourcesByStatusChart from './ResourcesByStatusChart';
import PoliciesOverviewChart from './PoliciesOverviewChart';
import ComplianceOverviewPageEmptyDataFallback from './EmptyDataFallback';
import ComplianceOverviewPageSkeleton from './Skeleton';
import TopFailingPoliciesTable from './TopFailingPoliciesTable';
import TopFailingResourcesTable from './TopFailingResourcesTable';

const ComplianceOverview: React.FC = () => {
  useTrackPageView(PageViewEnum.ComplianceOverview);

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
      <SimpleGrid columns={2} spacing={3} as="section" mb={3}>
        <Panel title="Policy Health">
          <Box height={150}>
            <PoliciesOverviewChart policies={data.organizationStats.appliedPolicies} />
          </Box>
        </Panel>
        <Panel title="Failing Policies">
          <Box height={150}>
            <PoliciesByStatusChart policies={data.organizationStats.appliedPolicies} />
          </Box>
        </Panel>
        <Panel title="Resource Health">
          <Box height={150}>
            <ResourcesByStatusChart resources={data.organizationStats.scannedResources} />
          </Box>
        </Panel>
        <Panel title="Enabled Policies">
          <Box height={150}>
            <PoliciesBySeverityChart policies={data.organizationStats.appliedPolicies} />
          </Box>
        </Panel>
      </SimpleGrid>
      <SimpleGrid columns={2} spacingX={3} spacingY={2}>
        <Panel title="Top Failing Policies">
          <Box my={-6}>
            <ErrorBoundary>
              <TopFailingPoliciesTable policies={data.organizationStats.topFailingPolicies} />
            </ErrorBoundary>
          </Box>
        </Panel>
        <Panel title="Top Failing Resources">
          <Box my={-6}>
            <ErrorBoundary>
              <TopFailingResourcesTable resources={data.organizationStats.topFailingResources} />
            </ErrorBoundary>
          </Box>
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default withSEO({ title: 'Cloud Security Overview' })(ComplianceOverview);
