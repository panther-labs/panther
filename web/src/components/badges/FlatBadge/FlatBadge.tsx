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
import { Box, Theme } from 'pouncejs';

interface FlatBadgeProps {
  children: React.ReactNode;
  backgroundColor?: keyof Theme['colors'];
  color?: keyof Theme['colors'];
}

const FlatBadge: React.FC<FlatBadgeProps> = ({
  backgroundColor = 'navyblue-700',
  color = 'white',
  children,
}) => {
  return (
    <Box
      backgroundColor={backgroundColor}
      borderRadius="small"
      px={1}
      py={1}
      fontWeight="bold"
      fontSize="x-small"
      color={color}
    >
      {children}
    </Box>
  );
};

export default FlatBadge;
