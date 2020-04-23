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
import { Alert, Card } from 'pouncejs';
import TablePlaceholder from 'Components/TablePlaceholder';
import { extractErrorMessage } from 'Helpers/utils';
import { useListUsers } from './graphql/listUsers.generated';
import ListUsersTable from '../ListUsersTable';

const ListUsers = () => {
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
      <ListUsersTable users={data.users} />
    </Card>
  );
};

export default ListUsers;
