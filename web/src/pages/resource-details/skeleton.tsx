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
import TablePlaceholder from 'Components/table-placeholder';
import { Box, Card } from 'pouncejs';
import Panel from 'Components/panel';
import ContentLoader from 'react-content-loader';

const ResourceDetailsPageSkeleton: React.FC = () => {
  return (
    <React.Fragment>
      <Box mb={2}>
        <Card p={6} mb={2}>
          <ContentLoader height={30}>
            <rect x="0" y={0} rx="1" ry="1" width="100%" height="10" />
            <rect x="0" y={15} rx="1" ry="1" width="100%" height="10" />
          </ContentLoader>
        </Card>
        <Card p={6} mb={2}>
          <ContentLoader height={30}>
            <rect x="0" y={0} rx="1" ry="1" width="100%" height="10" />
            <rect x="0" y={15} rx="1" ry="1" width="100%" height="10" />
          </ContentLoader>
        </Card>
      </Box>
      <Panel size="large" title="Policies">
        <Box mt={6}>
          <TablePlaceholder />
        </Box>
      </Panel>
    </React.Fragment>
  );
};

export default ResourceDetailsPageSkeleton;
