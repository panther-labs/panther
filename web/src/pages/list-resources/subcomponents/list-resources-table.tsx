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
import {
  ListResourcesSortFieldsEnum,
  ListResourcesInput,
  ResourceSummary,
  SortDirEnum,
  Integration,
} from 'Generated/schema';
import { generateEnumerationColumn } from 'Helpers/utils';
import { Table } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import columns from '../columns';

interface ListResourcesTableProps {
  items?: ResourceSummary[];
  sortBy: ListResourcesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListResourcesInput>) => void;
  enumerationStartIndex: number;
}

const ListResourcesTable: React.FC<ListResourcesTableProps> = ({
  items,
  onSort,
  sortBy,
  sortDir,
  enumerationStartIndex,
}) => {
  const { history } = useRouter();

  const handleSort = (selectedKey: ListResourcesSortFieldsEnum) => {
    if (sortBy === selectedKey) {
      onSort({
        sortBy,
        sortDir: sortDir === SortDirEnum.Ascending ? SortDirEnum.Descending : SortDirEnum.Ascending,
      });
    } else {
      onSort({ sortBy: selectedKey, sortDir: SortDirEnum.Ascending });
    }
  };

  const enumeratedColumns = [generateEnumerationColumn(enumerationStartIndex), ...columns];

  return (
    <Table<ResourceSummary & Pick<Integration, 'integrationLabel'>>
      columns={enumeratedColumns}
      getItemKey={resource => resource.id}
      items={items}
      onSort={handleSort}
      sortDir={sortDir}
      sortKey={sortBy}
      onSelect={resource => history.push(urls.resources.details(resource.id))}
    />
  );
};

export default React.memo(ListResourcesTable);
