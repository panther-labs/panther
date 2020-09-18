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
import { SimpleGrid, Text } from 'pouncejs';

interface RowProps {
  newItems: number;
  modifiedItems: number;
  totalItems: number;
}

const Rows: React.FC<RowProps> = ({ newItems = 0, modifiedItems = 0, totalItems = 0 }) => (
  <>
    <SimpleGrid columns={2} mb={2}>
      <Text color="gray-300">New</Text>
      <Text fontWeight="bold" textAlign="right">
        {newItems}
      </Text>
    </SimpleGrid>
    <SimpleGrid columns={2} mb={2}>
      <Text color="gray-300">Modified</Text>
      <Text fontWeight="bold" textAlign="right">
        {modifiedItems}
      </Text>
    </SimpleGrid>
    <SimpleGrid columns={2}>
      <Text color="gray-300">Total</Text>
      <Text fontWeight="bold" textAlign="right">
        {totalItems}
      </Text>
    </SimpleGrid>
  </>
);

export default React.memo(Rows);
