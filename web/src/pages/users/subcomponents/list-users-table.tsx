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
import { useQuery, gql } from '@apollo/client';
import { ListUsersResponse, User } from 'Generated/schema';
import { Alert, Card, Table } from 'pouncejs';
import columns from 'Pages/users/columns';

import TablePlaceholder from 'Components/table-placeholder';
import { extractErrorMessage } from 'Helpers/utils';

// This is done so we can benefit from React.memo
const getUserItemKey = (item: User) => item.id;

export const LIST_USERS = gql`
  query ListUsers($limit: Int, $paginationToken: String) {
    users(limit: $limit, paginationToken: $paginationToken) {
      users {
        id
        email
        givenName
        familyName
        createdAt
        status
      }
      paginationToken
    }
  }
`;

const ListUsersTable = () => {
  const { loading, error, data } = useQuery<{ users: ListUsersResponse }>(LIST_USERS, {
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
    return (
      <Card p={9}>
        <TablePlaceholder />
      </Card>
    );
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load users"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Card>
      <Table<User> columns={columns} getItemKey={getUserItemKey} items={data.users.users} />
    </Card>
  );
};

export default React.memo(ListUsersTable);
