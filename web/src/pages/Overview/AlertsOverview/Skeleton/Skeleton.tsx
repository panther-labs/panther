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
import TablePlaceholder from 'Components/TablePlaceholder';
import Panel from 'Components/Panel';

const AlertsOverviewSkeleton: React.FC = () => {
  return (
    <Box as="article">
      <FadeIn duration={400}>
        <SimpleGrid columns={1} spacingY={4}>
          <Panel title="Alerts Overview">
            <TablePlaceholder rowCount={1} rowHeight={110} />
          </Panel>
          <Panel title="Top 5 High Priority Alerts">
            <TablePlaceholder rowHeight={36} />
          </Panel>
          <Panel title="Most Active Detections">
            <TablePlaceholder rowCount={1} rowHeight={80} />
          </Panel>
        </SimpleGrid>
      </FadeIn>
    </Box>
  );
};

export default AlertsOverviewSkeleton;
