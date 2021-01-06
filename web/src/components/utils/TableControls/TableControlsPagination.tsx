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
import { Box, Flex, IconButton } from 'pouncejs';

interface TableControlsPagination {
  page: number;
  onPageChange: (page: number) => void;
  totalPages: number;
}

const TableControlsPagination: React.FC<TableControlsPagination> = ({
  page,
  onPageChange,
  totalPages,
}) => {
  return (
    <Flex align="center" justify="center">
      <Flex align="center">
        <IconButton
          variantColor="navyblue"
          aria-label="Go to previous page"
          variant="ghost"
          variantBorderStyle="circle"
          icon="chevron-left"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        />
        <Box mx={2} fontSize="medium">
          {page} of {totalPages}
        </Box>
        <IconButton
          variantColor="navyblue"
          aria-label="Go to next page"
          variant="ghost"
          variantBorderStyle="circle"
          icon="chevron-right"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        />
      </Flex>
    </Flex>
  );
};

export default React.memo(TableControlsPagination);
