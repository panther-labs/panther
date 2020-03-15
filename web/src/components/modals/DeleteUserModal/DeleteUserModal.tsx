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
import { User } from 'Generated/schema';
import { ListUsersDocument } from 'Pages/Users';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import useAuth from 'Hooks/useAuth';
import BaseConfirmModal from 'Components/modals/BaseConfirmModal';
import { useDeleteUser } from './graphql/deleteUser.generated';

export interface DeleteUserModalProps {
  user: User;
}

const DeleteUserModal: React.FC<DeleteUserModalProps> = ({ user }) => {
  const { signOut, userInfo } = useAuth();
  // Checking if user deleted is the same as the user signed in
  const onSuccess = () => userInfo.sub === user.id && signOut();

  const userDisplayName = `${user.givenName} ${user.familyName}` || user.id;
  const mutation = useDeleteUser({
    variables: {
      id: user.id,
    },
    awaitRefetchQueries: true,
    refetchQueries: [getOperationName(ListUsersDocument)],
  });

  return (
    <BaseConfirmModal
      mutation={mutation}
      title={`Delete ${userDisplayName}`}
      subtitle={`Are you sure you want to delete ${userDisplayName}?`}
      onSuccessMsg={`Successfully deleted ${userDisplayName}`}
      onErrorMsg={`Failed to delete ${userDisplayName}`}
      onSuccess={onSuccess}
    />
  );
};

export default DeleteUserModal;
