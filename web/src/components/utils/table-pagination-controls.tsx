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
import { Flex, Icon, IconButton, Label } from 'pouncejs';

interface TablePaginationControls {
  page: number;
  onPageChange: (page: number) => void;
  totalPages: number;
}

const TablePaginationControls: React.FC<TablePaginationControls> = ({
  page,
  onPageChange,
  totalPages,
}) => {
  return (
    <Flex alignItems="center" justifyContent="center">
      <Flex mr={9} alignItems="center">
        <IconButton variant="default" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          <Icon size="large" type="chevron-left" />
        </IconButton>
        <Label size="large" mx={4} color="grey400">
          {page} of {totalPages}
        </Label>
        <IconButton
          variant="default"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        >
          <Icon size="large" type="chevron-right" />
        </IconButton>
      </Flex>
    </Flex>
  );
};

export default React.memo(TablePaginationControls);
