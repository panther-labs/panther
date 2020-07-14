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
          <Panel title="Real-time Alerts">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
          <Panel title="Most Active Rules">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
        </SimpleGrid>
        <SimpleGrid columns={1} spacingX={3} spacingY={2} mb={3}>
          <Panel title="Events by Log Type">
            <Box height={150}>
              <TablePlaceholder />
            </Box>
          </Panel>
        </SimpleGrid>
        <SimpleGrid columns={1} spacingX={3} spacingY={2}>
          <Panel title="Recent Alerts | High Severity Alerts">
            <TablePlaceholder />
          </Panel>
        </SimpleGrid>
      </FadeIn>
    </Box>
  );
};

export default ComplianceOverviewPageSkeleton;
