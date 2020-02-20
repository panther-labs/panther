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
import { Text, TableProps, Box } from 'pouncejs';
import { User } from 'Generated/schema';
import ListUsersTableRowOptions from 'Pages/users/subcomponents/list-users-table-row-options';
import dayjs from 'dayjs';
import { generateEnumerationColumn } from 'Helpers/utils';

// The columns that the associated table will show
const columns = [
  generateEnumerationColumn(0),
  // Show given name and family name in two separate column
  {
    key: 'givenName',
    header: 'Name',
    flex: '1 0 150px',
    renderCell: ({ givenName, familyName }) => (
      <Text size="medium">
        {givenName} {familyName}
      </Text>
    ),
  },
  {
    key: 'email',
    header: 'Email',
    flex: '1 0 200px',
  },
  // Display hardcoded Admin role
  {
    key: 'role',
    header: 'Role',
    flex: '0 0 100px',
    renderCell: <Text size="medium">Admin</Text>,
  },
  // Display when user is invited
  {
    key: 'createdAt',
    header: 'Invited at',
    flex: '0 0 250px',
    renderCell: item => (
      <Text size="medium">{dayjs(item.createdAt * 1000).format('MM/DD/YYYY, HH:mm G[M]TZZ')}</Text>
    ),
  },
  // Display if user is confirmed or not
  {
    key: 'status',
    header: 'Status',
    flex: '1 0 150px',
  },
  {
    key: 'options',
    flex: '0 1 100px',
    renderColumnHeader: () => <Box mx={5} />,
    renderCell: item => <ListUsersTableRowOptions user={item} />,
  },
] as TableProps<User>['columns'];

export default columns;
