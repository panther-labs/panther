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
import TablePlaceholder from 'Components/TablePlaceholder';
import { Box, Card, FadeIn } from 'pouncejs';
import Panel from 'Components/Panel';

const PolicyDetailsPageSkeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <TablePlaceholder rowCount={1} rowHeight={15} />

      <Card p={6}>
        <TablePlaceholder rowCount={2} rowHeight={10} />
      </Card>
      <Box mt={5}>
        <Panel title="Resources">
          <TablePlaceholder />
        </Panel>
      </Box>
    </FadeIn>
  );
};

export default PolicyDetailsPageSkeleton;
