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
import { Box, FadeIn, SimpleGrid } from 'pouncejs';
import Panel from 'Components/Panel';
import TablePlaceholder from 'Components/TablePlaceholder';

const ComplianceOverviewPageSkeleton: React.FC = () => {
  return (
    <Box as="article" mb={6}>
      <FadeIn duration={400}>
        <SimpleGrid columns={2} spacing={3} as="section" mb={3}>
          <Panel title="Policy Health">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
          <Panel title="Failing Policies">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
          <Panel title="Resource Health">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
          <Panel title="Enabled Policies">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
        </SimpleGrid>
        <SimpleGrid columns={2} spacingX={3} spacingY={2}>
          <Panel title="Top Failing Policies">
            <TablePlaceholder />
          </Panel>
          <Panel title="Top Failing Resources">
            <TablePlaceholder />
          </Panel>
        </SimpleGrid>
      </FadeIn>
    </Box>
  );
};

export default ComplianceOverviewPageSkeleton;
