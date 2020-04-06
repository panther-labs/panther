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

/* eslint-disable react/display-name */

import React from 'react';
import { Badge, Box, TableProps, Text, Icon } from 'pouncejs';
import { RuleSummary } from 'Generated/schema';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { formatDatetime } from 'Helpers/utils';
import ListRulesTableRowOptions from './ListRulesTableRowOptions';

// The columns that the associated table will show
const columns = [
  // Prefer to show the name. If it doesn't exist, fallback to the `id`
  {
    key: 'id',
    sortable: true,
    header: 'Rule',
    flex: '0 0 400px',
    renderCell: item => <Text size="medium">{item.displayName || item.id}</Text>,
  },

  // A log type might not be be specified, meaning that it applies to "All". Else render
  // one row for each log type
  {
    key: 'logTypes',
    sortable: true,
    header: 'Log Type',
    flex: '1 0 200px',
    renderCell: ({ logTypes, id }) =>
      logTypes.length ? (
        <div>
          {logTypes.map(logType => (
            <Text size="medium" wordBreak="break-word" key={id} mb={1}>
              {logType}
            </Text>
          ))}
        </div>
      ) : (
        <Text size="medium">All logs</Text>
      ),
  },

  // Render badges to showcase severity
  {
    key: 'enabled',
    sortable: true,
    flex: '0 0 105px',
    header: 'Enabled',
    renderCell: ({ enabled }) => {
      return enabled ? (
        <Icon type="check" color="green300" size="small" />
      ) : (
        <Icon type="close" color="red300" size="small" />
      );
    },
  },

  // Render badges to showcase severity
  {
    key: 'severity',
    sortable: true,
    flex: '0 0 110px',
    header: 'Severity',
    renderCell: item => <Badge color={SEVERITY_COLOR_MAP[item.severity]}>{item.severity}</Badge>,
  },

  // Date needs to be formatted properly
  {
    key: 'lastModified',
    sortable: true,
    header: 'Last Modified',
    flex: '0 0 200px',
    renderCell: ({ lastModified }) => <Text size="medium">{formatDatetime(lastModified)}</Text>,
  },
  {
    key: 'options',
    flex: '0 1 auto',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <ListRulesTableRowOptions rule={item} />,
  },
] as TableProps<RuleSummary>['columns'];

export default columns;
