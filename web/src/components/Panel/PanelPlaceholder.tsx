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
import ContentLoader from 'react-content-loader';
import { Box, Card } from 'pouncejs';

interface PanelPlaceholderProps {
  /** The number of rows that the placeholder component should render. Defaults to 5 */
  rowCount?: number;

  /** The height of each row. Defaults to 15px */
  rowHeight?: number;
}

const PanelPlaceholder: React.FC<PanelPlaceholderProps> = ({ rowCount = 4, rowHeight = 15 }) => (
  <Card
    width={1}
    borderBottom="1px solid"
    borderColor="grey100"
    py={8}
    px={8}
    backgroundColor="white"
  >
    <Box pb={8} borderBottom="1px solid" borderColor="grey100">
      <ContentLoader height={10}>
        <rect x="0" y="0" rx="1" ry="1" width="30%" height="10" />
      </ContentLoader>
    </Box>
    <Box mt={8}>
      <ContentLoader height={rowCount * rowHeight}>
        {[...Array(rowCount)].map((__, index) => (
          <rect key={index} x="0" y={index * rowHeight} rx="1" ry="1" width="40%" height="10" />
        ))}
      </ContentLoader>
    </Box>
  </Card>
);

export default PanelPlaceholder;
