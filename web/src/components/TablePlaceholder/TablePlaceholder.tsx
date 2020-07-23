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
import ContentLoader from 'react-content-loader';
import { useTheme } from 'pouncejs';

interface TablePlaceholderProps {
  /** The number of rows that the placeholder component should render. Defaults to 5 */
  rowCount?: number;

  /** The height of each row. Defaults to 10px */
  rowHeight?: number;

  /** The vertical gap between each row. Defaults to 5px */
  rowGap?: number;
}

const TablePlaceholder: React.FC<TablePlaceholderProps> = ({
  rowCount = 5,
  rowHeight = 10,
  rowGap = 5,
}) => {
  const theme = useTheme();
  return (
    <ContentLoader
      height={rowCount * (rowHeight + rowGap)}
      primaryColor={theme.colors['navyblue-500']}
      secondaryColor={theme.colors['navyblue-600']}
    >
      {[...Array(rowCount)].map((__, index) => (
        <rect
          key={index}
          x="0"
          y={index * (rowHeight + rowGap)}
          rx="1"
          ry="1"
          width="100%"
          height={rowHeight}
        />
      ))}
    </ContentLoader>
  );
};

export default TablePlaceholder;
