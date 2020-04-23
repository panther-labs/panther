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
import { Alert, Card, Label, Table } from 'pouncejs';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import dayjs from 'dayjs';
import ListUsersTableRowOptions from '../ListUsersTableRowOptions';
import { useListUsers } from './graphql/listUsers.generated';

const ListUsersTable = () => {
  const { loading, error, data } = useListUsers({
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
      <Table>
        <Table.Head>
          <Table.Row>
            <Table.HeaderCell />
            <Table.HeaderCell>Name</Table.HeaderCell>
            <Table.HeaderCell>Email</Table.HeaderCell>
            <Table.HeaderCell>Role</Table.HeaderCell>
            <Table.HeaderCell>Invited At</Table.HeaderCell>
            <Table.HeaderCell>Status</Table.HeaderCell>
            <Table.HeaderCell />
          </Table.Row>
        </Table.Head>
        <Table.Body>
          {data.users.map((user, index) => (
            <Table.Row key={user.id}>
              <Table.Cell>
                <Label size="medium">{index + 1}</Label>
              </Table.Cell>
              <Table.Cell>
                {user.givenName} {user.familyName}
              </Table.Cell>
              <Table.Cell>{user.email}</Table.Cell>
              <Table.Cell>Admin</Table.Cell>
              <Table.Cell>
                {dayjs(user.createdAt * 1000).format('MM/DD/YYYY, HH:mm G[M]TZZ')}
              </Table.Cell>
              <Table.Cell>{user.status}</Table.Cell>
              <Table.Cell>
                <ListUsersTableRowOptions user={user} />
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </Card>
  );
};

export default React.memo(ListUsersTable);
