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

/* eslint-disable react/display-name */

import React from 'react';
import { Badge, TableProps, Text } from 'pouncejs';
import { AlertSummary } from 'Generated/schema';
import { formatDatetime, shortenId } from 'Helpers/utils';
import { SEVERITY_COLOR_MAP } from 'Source/constants';

// The columns that the associated table will show
const columns = [
  {
    key: 'title',
    sortable: true,
    header: 'Title',
    flex: '1 0 200px',
  },
  // Date needs to be formatted properly
  {
    key: 'createdAt',
    sortable: true,
    header: 'Created At',
    flex: '0 0 200px',
    renderCell: ({ creationTime }) => <Text size="medium">{formatDatetime(creationTime)}</Text>,
  },

  // Render badges to showcase severity
  {
    key: 'severity',
    sortable: true,
    flex: '0 0 150px',
    header: 'Severity',
    renderCell: ({ severity }) => {
      if (!severity) {
        return (
          <Text size="medium" pl={4}>
            N/A
          </Text>
        );
      }
      return <Badge color={SEVERITY_COLOR_MAP[severity]}>{severity}</Badge>;
    },
  },

  {
    key: 'alertId',
    sortable: true,
    header: 'Alert ID',
    flex: '0 0 200px',
    renderCell: ({ alertId }) => <Text size="medium">{shortenId(alertId)}</Text>,
  },

  {
    key: 'eventsMatched',
    sortable: true,
    header: 'Events Count',
    flex: '1 0 50px',
  },

  // Date needs to be formatted properly
  {
    key: 'lastModified',
    sortable: true,
    header: 'Last Matched At',
    flex: '0 0 200px',
    renderCell: ({ updateTime }) => <Text size="medium">{formatDatetime(updateTime)}</Text>,
  },
] as TableProps<AlertSummary>['columns'];

export default columns;
