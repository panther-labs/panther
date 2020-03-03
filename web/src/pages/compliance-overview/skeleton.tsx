/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Box, Grid, Flex } from 'pouncejs';
import Panel from 'Components/panel';
import TablePlaceholder from 'Components/table-placeholder';
import CirclePlaceholder from 'Components/CirclePlaceholder';
import DonutChartWrapper from 'Pages/compliance-overview/subcomponents/donut-chart-wrapper';

const ChartPlaceholder: React.FC = () => (
  <Flex height="100%" alignItems="center" justifyContent="center">
    <CirclePlaceholder size={150} />
  </Flex>
);

const ComplianceOverviewPageSkeleton: React.FC = () => {
  return (
    <Box is="article" mb={6}>
      <Grid
        gridTemplateColumns="repeat(4, 1fr)"
        gridRowGap={3}
        gridColumnGap={3}
        is="section"
        mb={3}
      >
        <DonutChartWrapper title="Policy Severity" icon="policy">
          <ChartPlaceholder />
        </DonutChartWrapper>
        <DonutChartWrapper title="Policy Failure" icon="policy">
          <ChartPlaceholder />
        </DonutChartWrapper>
        <DonutChartWrapper title="Resource Type" icon="resource">
          <ChartPlaceholder />
        </DonutChartWrapper>
        <DonutChartWrapper title="Resource Health" icon="resource">
          <ChartPlaceholder />
        </DonutChartWrapper>
      </Grid>
      <Grid gridTemplateColumns="1fr 1fr" gridRowGap={2} gridColumnGap={3}>
        <Panel title="Top Failing Policies" size="small">
          <TablePlaceholder />
        </Panel>
        <Panel title="Top Failing Resources" size="small">
          <TablePlaceholder />
        </Panel>
      </Grid>
    </Box>
  );
};

export default ComplianceOverviewPageSkeleton;
