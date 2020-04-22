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
import { Text, TableProps } from 'pouncejs';
import { AlertSummary } from 'Generated/schema';
import { formatDatetime, shortenId } from 'Helpers/utils';

// The columns that the associated table will show
const columns = [
  // The name is the `id` of the alert
  {
    key: 'title',
    sortable: true,
    header: 'Title',
    flex: '1 0 200px',
  },
  {
    key: 'creationTime',
    header: 'Created At',
    flex: '1 0 200px',
    renderCell: ({ creationTime }) => <Text size="medium">{formatDatetime(creationTime)}</Text>,
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
