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
import { Box, Flex, Heading, theme } from 'pouncejs';
import { slugify } from 'Helpers/utils';

interface ChartSummaryProps {
  total: number;
  title: string;
  color?: keyof typeof theme['colors'];
}

const ChartSummary: React.FC<ChartSummaryProps> = ({ total, title, color }) => {
  return (
    <Flex width="50%" direction="column" align="center" justify="center" mb={10}>
      <Heading
        as="h2"
        size="3x-large"
        color={color}
        fontWeight="bold"
        aria-describedby={slugify(title)}
      >
        {total}
      </Heading>
      <Box id={slugify(title)} fontSize="medium">
        {title}
      </Box>
    </Flex>
  );
};

export default ChartSummary;
