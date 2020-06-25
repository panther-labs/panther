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
import { Alert, Button } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import Panel from 'Components/Panel';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';
import { useListUsers } from './graphql/listUsers.generated';
import ListUsersTable from './ListUsersTable';
import Skeleton from './Skeleton';

const ListUsersPage = () => {
  const { showSidesheet } = useSidesheet();
  const { loading, error, data } = useListUsers();

  if (loading && !data) {
    return <Skeleton />;
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
    <Panel
      title="Users"
      actions={
        <Button
          icon="add-user"
          onClick={() => showSidesheet({ sidesheet: SIDESHEETS.USER_INVITATION })}
        >
          Invite User
        </Button>
      }
    >
      <ListUsersTable users={data.users} />
    </Panel>
  );
};

export default ListUsersPage;
