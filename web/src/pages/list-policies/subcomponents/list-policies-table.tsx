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
  ListPoliciesInput,
  ListPoliciesSortFieldsEnum,
  PolicySummary,
  SortDirEnum,
} from 'Generated/schema';
import { generateEnumerationColumn } from 'Helpers/utils';
import { Table } from 'pouncejs';
import columns from 'Pages/list-policies/columns';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';

interface ListPoliciesTableProps {
  items?: PolicySummary[];
  sortBy: ListPoliciesSortFieldsEnum;
  sortDir: SortDirEnum;
  onSort: (params: Partial<ListPoliciesInput>) => void;
  enumerationStartIndex: number;
}

const ListPoliciesTable: React.FC<ListPoliciesTableProps> = ({
  items,
  onSort,
  sortBy,
  sortDir,
  enumerationStartIndex,
}) => {
  const { history } = useRouter();

  const handleSort = (selectedKey: ListPoliciesSortFieldsEnum) => {
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
    <Table<PolicySummary>
      columns={enumeratedColumns}
      getItemKey={policy => policy.id}
      items={items}
      onSort={handleSort}
      sortDir={sortDir}
      sortKey={sortBy}
      onSelect={policy => history.push(urls.policies.details(policy.id))}
    />
  );
};

export default React.memo(ListPoliciesTable);
