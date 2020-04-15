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
import { ComplianceItem, ComplianceIntegration } from 'Generated/schema';
import { Table, TableProps } from 'pouncejs';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';
import { generateEnumerationColumn } from 'Helpers/utils';

type EnhancedComplianceItem = ComplianceItem & Pick<ComplianceIntegration, 'integrationLabel'>;

interface PolicyDetailsTableProps {
  items?: EnhancedComplianceItem[];
  columns: TableProps<EnhancedComplianceItem>['columns'];
  enumerationStartIndex: number;
}

const PolicyDetailsTable: React.FC<PolicyDetailsTableProps> = ({
  items,
  columns,
  enumerationStartIndex,
}) => {
  const { history } = useRouter();

  // prepend an extra enumeration column
  const enumeratedColumns = [generateEnumerationColumn(enumerationStartIndex), ...columns];

  return (
    <Table<EnhancedComplianceItem>
      columns={enumeratedColumns}
      getItemKey={complianceItem => complianceItem.resourceId}
      items={items}
      onSelect={complianceItem =>
        history.push(urls.compliance.resources.details(complianceItem.resourceId))
      }
    />
  );
};

export default React.memo(PolicyDetailsTable);
