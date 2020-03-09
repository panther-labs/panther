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
import { Text, TableProps } from 'pouncejs';
import { AlertSummary } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';

// The columns that the associated table will show
const columns = [
  // The name is the `id` of the alert
  {
    key: 'alertId',
    header: 'Alert',
    flex: '2 0 450px',
  },

  {
    key: 'creationTime',
    header: 'Created At',
    flex: '1 0 250px',
    renderCell: ({ creationTime }) => <Text size="medium">{formatDatetime(creationTime)}</Text>,
  },
] as TableProps<AlertSummary>['columns'];

export default columns;
