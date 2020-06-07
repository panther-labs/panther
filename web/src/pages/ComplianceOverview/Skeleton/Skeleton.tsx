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
import { Box, Flex, SimpleGrid } from 'pouncejs';
import Panel from 'Components/Panel';
import TablePlaceholder from 'Components/TablePlaceholder';
import CirclePlaceholder from 'Components/CirclePlaceholder';
import BarChartWrapper from '../BarChartWrapper';

const ChartPlaceholder: React.FC = () => (
  <Flex height="100%" align="center" justify="center">
    <CirclePlaceholder size={100} />
  </Flex>
);

const ComplianceOverviewPageSkeleton: React.FC = () => {
  return (
    <Box as="article" mb={6}>
      <SimpleGrid columns={3} spacing={3} as="section" mb={3}>
        <BarChartWrapper title="Policy Severity" icon="policy">
          <ChartPlaceholder />
        </BarChartWrapper>
        <BarChartWrapper title="Policy Failure" icon="policy">
          <ChartPlaceholder />
        </BarChartWrapper>
        <BarChartWrapper title="Resource Type" icon="resource">
          <ChartPlaceholder />
        </BarChartWrapper>
      </SimpleGrid>
      <SimpleGrid columns={2} spacingX={3} spacingY={2}>
        <Panel title="Top Failing Policies" size="small">
          <TablePlaceholder />
        </Panel>
        <Panel title="Top Failing Resources" size="small">
          <TablePlaceholder />
        </Panel>
      </SimpleGrid>
    </Box>
  );
};

export default ComplianceOverviewPageSkeleton;
