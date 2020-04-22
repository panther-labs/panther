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
import { AlertSummary } from 'Generated/schema';
import { generateEnumerationColumn } from 'Helpers/utils';
import { Table } from 'pouncejs';
import columns from 'Pages/ListAlerts/columns';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';

interface ListAlertsTableProps {
  items?: AlertSummary[];
  enumerationStartIndex?: number;
}

const ListAlertsTable: React.FC<ListAlertsTableProps> = ({ items }) => {
  const { history } = useRouter();

  const enumeratedColumns = [generateEnumerationColumn(0), ...columns];
  return (
    <Table<AlertSummary>
      columns={enumeratedColumns}
      getItemKey={alert => alert.alertId}
      items={items}
      onSelect={alert => history.push(urls.logAnalysis.alerts.details(alert.alertId))}
    />
  );
};

export default React.memo(ListAlertsTable);
