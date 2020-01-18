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
import { Alert, Table, TableProps } from 'pouncejs';
import { Integration } from 'Generated/schema';
import TablePlaceholder from 'Components/table-placeholder';
import { extractErrorMessage } from 'Helpers/utils';
import { QueryResult } from '@apollo/client';

interface BaseSourceTableProps {
  query: QueryResult<{ integrations: Integration[] }, {}>;
  columns: TableProps<Integration>['columns'];
}

const BaseSourceTable: React.FC<BaseSourceTableProps> = ({ query, columns }) => {
  const { loading, error, data } = query;

  if (loading && !data) {
    return <TablePlaceholder />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your sources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Table<Integration>
      items={data.integrations}
      getItemKey={item => item.integrationId}
      columns={columns}
    />
  );
};

export default BaseSourceTable;
