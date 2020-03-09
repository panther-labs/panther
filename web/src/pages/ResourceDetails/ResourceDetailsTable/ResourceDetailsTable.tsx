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
import { ComplianceItem } from 'Generated/schema';
import { Table, TableProps } from 'pouncejs';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';
import { generateEnumerationColumn } from 'Helpers/utils';

interface ResourcesDetailsTableProps {
  items?: ComplianceItem[];
  columns: TableProps<ComplianceItem>['columns'];
  enumerationStartIndex: number;
}

const ResourcesDetailsTable: React.FC<ResourcesDetailsTableProps> = ({
  enumerationStartIndex,
  items,
  columns,
}) => {
  const { history } = useRouter();

  // prepend an extra enumeration column
  const enumeratedColumns = [generateEnumerationColumn(enumerationStartIndex), ...columns];

  return (
    <Table<ComplianceItem>
      columns={enumeratedColumns}
      getItemKey={complianceItem => complianceItem.policyId}
      items={items}
      onSelect={complianceItem =>
        history.push(urls.compliance.policies.details(complianceItem.policyId))
      }
    />
  );
};

export default React.memo(ResourcesDetailsTable);
